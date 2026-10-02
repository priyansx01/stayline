//! Thin safe wrappers over the IP Helper calls stayline needs (IPv4 only).
//!
//! The `windows` crate maps the `BOOLEAN` fields of these rows to Rust
//! `bool`, but Windows may store values other than 0 and 1 in them, which is
//! undefined behaviour for `bool`. Rows that Windows writes are therefore
//! only ever held as `MaybeUninit` and touched field by field through raw
//! pointers, never moved or copied as values.

use std::mem::MaybeUninit;
use std::net::Ipv4Addr;
use std::ptr::addr_of_mut;

use windows::Win32::Foundation::{ERROR_NOT_FOUND, ERROR_OBJECT_ALREADY_EXISTS, WIN32_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceLuidToGuid, CreateIpForwardEntry2, CreateUnicastIpAddressEntry,
    DNS_INTERFACE_SETTINGS, DNS_INTERFACE_SETTINGS_VERSION1, DNS_SETTING_NAMESERVER,
    DNS_SETTING_SEARCHLIST, DeleteIpForwardEntry2, DeleteUnicastIpAddressEntry, GetBestRoute2,
    GetIpInterfaceEntry, InitializeIpForwardEntry, InitializeIpInterfaceEntry,
    InitializeUnicastIpAddressEntry, MIB_IPFORWARD_ROW2, MIB_IPINTERFACE_ROW,
    MIB_UNICASTIPADDRESS_ROW, SetInterfaceDnsSettings, SetIpInterfaceEntry,
};
use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows::Win32::Networking::WinSock::{
    AF_INET, IN_ADDR, IN_ADDR_0, IpDadStatePreferred, SOCKADDR_IN, SOCKADDR_INET,
};
use windows::core::{GUID, PWSTR};

use crate::error::{NetError, Result, check};

fn luid(value: u64) -> NET_LUID_LH {
    NET_LUID_LH { Value: value }
}

fn sockaddr(ip: Ipv4Addr) -> SOCKADDR_INET {
    // Start from zero so the unused IPv6 part of the union is initialised.
    let mut addr = SOCKADDR_INET::default();
    addr.Ipv4 = SOCKADDR_IN {
        sin_family: AF_INET,
        sin_port: 0,
        sin_addr: IN_ADDR {
            S_un: IN_ADDR_0 {
                S_addr: u32::from_ne_bytes(ip.octets()),
            },
        },
        sin_zero: [0; 8],
    };
    addr
}

/// # Safety
/// `addr` must point to an initialised AF_INET `SOCKADDR_INET`.
unsafe fn ipv4_at(addr: *const SOCKADDR_INET) -> Ipv4Addr {
    // SAFETY: guaranteed by the caller.
    Ipv4Addr::from(unsafe { (*addr).Ipv4.sin_addr.S_un.S_addr }.to_ne_bytes())
}

/// A route we created, kept so it can be deleted again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteRow {
    pub if_luid: u64,
    pub network: Ipv4Addr,
    pub prefix_len: u8,
    pub next_hop: Ipv4Addr,
}

impl RouteRow {
    /// Runs `f` on a Windows route row describing this route.
    fn with_row<T>(&self, metric: u32, f: impl FnOnce(*const MIB_IPFORWARD_ROW2) -> T) -> T {
        let mut row = MaybeUninit::<MIB_IPFORWARD_ROW2>::zeroed();
        let p = row.as_mut_ptr();
        // SAFETY: p points to writable memory the size of the row; fields are
        // written through the pointer without reading the row as a value.
        unsafe {
            InitializeIpForwardEntry(p);
            addr_of_mut!((*p).InterfaceLuid).write(luid(self.if_luid));
            addr_of_mut!((*p).DestinationPrefix.Prefix).write(sockaddr(self.network));
            addr_of_mut!((*p).DestinationPrefix.PrefixLength).write(self.prefix_len);
            addr_of_mut!((*p).NextHop).write(sockaddr(self.next_hop));
            addr_of_mut!((*p).Metric).write(metric);
        }
        f(p)
    }
}

/// The route Windows would use right now to reach `dest`: interface LUID
/// and next hop.
pub fn best_route(dest: Ipv4Addr) -> Result<(u64, Ipv4Addr)> {
    let mut row = MaybeUninit::<MIB_IPFORWARD_ROW2>::zeroed();
    let mut source = SOCKADDR_INET::default();
    let dest = sockaddr(dest);
    let p = row.as_mut_ptr();
    // SAFETY: all pointers refer to live, properly sized locals.
    let err = unsafe { GetBestRoute2(None, 0, None, &dest, 0, p, &mut source) };
    check("GetBestRoute2", err)?;
    // SAFETY: GetBestRoute2 filled the row; only plain fields are read.
    unsafe { Ok(((*p).InterfaceLuid.Value, ipv4_at(&raw const (*p).NextHop))) }
}

/// Adds `network/prefix_len` on interface `if_luid` via `next_hop`
/// (`0.0.0.0` for on-link). An identical existing route counts as success
/// and is not returned for later deletion.
pub fn add_route(
    if_luid: u64,
    network: Ipv4Addr,
    prefix_len: u8,
    next_hop: Ipv4Addr,
    metric: u32,
) -> Result<Option<RouteRow>> {
    let route = RouteRow {
        if_luid,
        network,
        prefix_len,
        next_hop,
    };
    // SAFETY: the row pointer is valid for the duration of the call.
    let err = route.with_row(metric, |row| unsafe { CreateIpForwardEntry2(row) });
    if err == ERROR_OBJECT_ALREADY_EXISTS {
        return Ok(None);
    }
    check("CreateIpForwardEntry2", err)?;
    Ok(Some(route))
}

pub fn delete_route(route: &RouteRow) {
    // SAFETY: the row pointer is valid for the duration of the call.
    let err = route.with_row(0, |row| unsafe { DeleteIpForwardEntry2(row) });
    warn_unless_ok_or_missing(err, || format!("could not delete route {route:?}"));
}

/// Assigns `ip/32` to the interface. Already present counts as success.
pub fn add_address(if_luid: u64, ip: Ipv4Addr) -> Result<()> {
    let err = with_address_row(if_luid, ip, |p| {
        // SAFETY: p comes from with_address_row and is valid here.
        unsafe {
            addr_of_mut!((*p).OnLinkPrefixLength).write(32);
            addr_of_mut!((*p).DadState).write(IpDadStatePreferred);
            CreateUnicastIpAddressEntry(p)
        }
    });
    if err == ERROR_OBJECT_ALREADY_EXISTS {
        return Ok(());
    }
    check("CreateUnicastIpAddressEntry", err)
}

pub fn delete_address(if_luid: u64, ip: Ipv4Addr) {
    // SAFETY: p comes from with_address_row and is valid here.
    let err = with_address_row(if_luid, ip, |p| unsafe { DeleteUnicastIpAddressEntry(p) });
    warn_unless_ok_or_missing(err, || format!("could not remove tunnel address {ip}"));
}

fn with_address_row<T>(
    if_luid: u64,
    ip: Ipv4Addr,
    f: impl FnOnce(*mut MIB_UNICASTIPADDRESS_ROW) -> T,
) -> T {
    let mut row = MaybeUninit::<MIB_UNICASTIPADDRESS_ROW>::zeroed();
    let p = row.as_mut_ptr();
    // SAFETY: p points to writable memory the size of the row.
    unsafe {
        InitializeUnicastIpAddressEntry(p);
        addr_of_mut!((*p).InterfaceLuid).write(luid(if_luid));
        addr_of_mut!((*p).Address).write(sockaddr(ip));
    }
    f(p)
}

/// Sets the IPv4 MTU and a fixed interface metric (lower wins, also for
/// which interface's DNS servers Windows asks first).
pub fn set_mtu_and_metric(if_luid: u64, mtu: u32, metric: u32) -> Result<()> {
    let mut row = MaybeUninit::<MIB_IPINTERFACE_ROW>::zeroed();
    let p = row.as_mut_ptr();
    // SAFETY: p points to writable memory the size of the row; fields are
    // accessed through the pointer only.
    unsafe {
        InitializeIpInterfaceEntry(p);
        addr_of_mut!((*p).Family).write(AF_INET);
        addr_of_mut!((*p).InterfaceLuid).write(luid(if_luid));
        check("GetIpInterfaceEntry", GetIpInterfaceEntry(p))?;
        addr_of_mut!((*p).NlMtu).write(mtu);
        addr_of_mut!((*p).UseAutomaticMetric).cast::<u8>().write(0);
        addr_of_mut!((*p).Metric).write(metric);
        // Must be zero for IPv4 or SetIpInterfaceEntry fails.
        addr_of_mut!((*p).SitePrefixLength).write(0);
        check("SetIpInterfaceEntry", SetIpInterfaceEntry(p))
    }
}

/// Sets the interface's DNS servers and search suffixes (Windows 10 2004+).
pub fn set_dns(if_luid: u64, servers: &[Ipv4Addr], search: &[String]) -> Result<()> {
    let mut guid = GUID::zeroed();
    // SAFETY: both pointers refer to live locals.
    check("ConvertInterfaceLuidToGuid", unsafe {
        ConvertInterfaceLuidToGuid(&luid(if_luid), &mut guid)
    })?;

    let mut name_servers = wide(
        &servers
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(","),
    );
    let mut search_list = wide(&search.join(","));
    let settings = DNS_INTERFACE_SETTINGS {
        Version: DNS_INTERFACE_SETTINGS_VERSION1,
        Flags: u64::from(DNS_SETTING_NAMESERVER | DNS_SETTING_SEARCHLIST),
        NameServer: PWSTR(name_servers.as_mut_ptr()),
        SearchList: PWSTR(search_list.as_mut_ptr()),
        ..Default::default()
    };
    // SAFETY: the strings outlive the call.
    let err = unsafe { SetInterfaceDnsSettings(guid, &settings) };
    check("SetInterfaceDnsSettings", err).map_err(|e| match e {
        NetError::Win32 { code, .. } => NetError::Win32 {
            call: "SetInterfaceDnsSettings (needs Windows 10 2004 or later)",
            code,
        },
        other => other,
    })
}

fn warn_unless_ok_or_missing(err: WIN32_ERROR, what: impl FnOnce() -> String) {
    if err.is_err() && err != ERROR_NOT_FOUND {
        tracing::warn!(code = err.0, "{}", what());
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn best_route_to_public_address_has_an_interface() {
        // Read-only; works without administrator rights.
        if let Ok((luid, _)) = best_route(Ipv4Addr::new(1, 1, 1, 1)) {
            assert_ne!(luid, 0);
        }
    }

    #[test]
    fn sockaddr_round_trips() {
        let ip = Ipv4Addr::new(10, 212, 134, 200);
        let addr = sockaddr(ip);
        // SAFETY: built as AF_INET just above.
        assert_eq!(unsafe { ipv4_at(&addr) }, ip);
    }
}
