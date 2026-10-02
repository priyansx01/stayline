//! Thin safe wrappers over the IP Helper calls stayline needs (IPv4 only).

use std::net::Ipv4Addr;

use windows::Win32::Foundation::{ERROR_NOT_FOUND, ERROR_OBJECT_ALREADY_EXISTS};
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
    SOCKADDR_INET {
        Ipv4: SOCKADDR_IN {
            sin_family: AF_INET,
            sin_port: 0,
            sin_addr: IN_ADDR {
                S_un: IN_ADDR_0 {
                    S_addr: u32::from_ne_bytes(ip.octets()),
                },
            },
            sin_zero: [0; 8],
        },
    }
}

fn ipv4_of(addr: &SOCKADDR_INET) -> Ipv4Addr {
    // SAFETY: only called on addresses we know are AF_INET.
    Ipv4Addr::from(unsafe { addr.Ipv4.sin_addr.S_un.S_addr }.to_ne_bytes())
}

/// A route row we created, kept so it can be deleted again.
#[derive(Clone, Copy)]
pub struct RouteRow(MIB_IPFORWARD_ROW2);

impl std::fmt::Debug for RouteRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}/{} via {} (luid {:#x})",
            ipv4_of(&self.0.DestinationPrefix.Prefix),
            self.0.DestinationPrefix.PrefixLength,
            ipv4_of(&self.0.NextHop),
            // SAFETY: Value covers the whole union.
            unsafe { self.0.InterfaceLuid.Value }
        )
    }
}

/// The route Windows would use right now to reach `dest`: interface LUID
/// and next hop.
pub fn best_route(dest: Ipv4Addr) -> Result<(u64, Ipv4Addr)> {
    let mut row = MIB_IPFORWARD_ROW2::default();
    let mut source = SOCKADDR_INET::default();
    let dest = sockaddr(dest);
    // SAFETY: all pointers refer to live, properly sized locals.
    let err = unsafe { GetBestRoute2(None, 0, None, &dest, 0, &mut row, &mut source) };
    check("GetBestRoute2", err)?;
    // SAFETY: Value covers the whole union.
    Ok((unsafe { row.InterfaceLuid.Value }, ipv4_of(&row.NextHop)))
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
    let mut row = MIB_IPFORWARD_ROW2::default();
    // SAFETY: row is a valid, writable MIB_IPFORWARD_ROW2.
    unsafe { InitializeIpForwardEntry(&mut row) };
    row.InterfaceLuid = luid(if_luid);
    row.DestinationPrefix.Prefix = sockaddr(network);
    row.DestinationPrefix.PrefixLength = prefix_len;
    row.NextHop = sockaddr(next_hop);
    row.Metric = metric;
    // SAFETY: row was initialised above.
    let err = unsafe { CreateIpForwardEntry2(&row) };
    if err == ERROR_OBJECT_ALREADY_EXISTS {
        return Ok(None);
    }
    check("CreateIpForwardEntry2", err)?;
    Ok(Some(RouteRow(row)))
}

pub fn delete_route(route: &RouteRow) {
    // SAFETY: the row came from a successful CreateIpForwardEntry2.
    let err = unsafe { DeleteIpForwardEntry2(&route.0) };
    if err.is_err() && err != ERROR_NOT_FOUND {
        tracing::warn!(?route, code = err.0, "could not delete route");
    }
}

/// Assigns `ip/32` to the interface. Already present counts as success.
pub fn add_address(if_luid: u64, ip: Ipv4Addr) -> Result<()> {
    let mut row = address_row(if_luid, ip);
    row.OnLinkPrefixLength = 32;
    row.DadState = IpDadStatePreferred;
    // SAFETY: row was initialised by address_row.
    let err = unsafe { CreateUnicastIpAddressEntry(&row) };
    if err == ERROR_OBJECT_ALREADY_EXISTS {
        return Ok(());
    }
    check("CreateUnicastIpAddressEntry", err)
}

pub fn delete_address(if_luid: u64, ip: Ipv4Addr) {
    let row = address_row(if_luid, ip);
    // SAFETY: row was initialised by address_row.
    let err = unsafe { DeleteUnicastIpAddressEntry(&row) };
    if err.is_err() && err != ERROR_NOT_FOUND {
        tracing::warn!(%ip, code = err.0, "could not remove tunnel address");
    }
}

fn address_row(if_luid: u64, ip: Ipv4Addr) -> MIB_UNICASTIPADDRESS_ROW {
    let mut row = MIB_UNICASTIPADDRESS_ROW::default();
    // SAFETY: row is a valid, writable MIB_UNICASTIPADDRESS_ROW.
    unsafe { InitializeUnicastIpAddressEntry(&mut row) };
    row.InterfaceLuid = luid(if_luid);
    row.Address = sockaddr(ip);
    row
}

/// Sets the IPv4 MTU and a fixed interface metric (lower wins, also for
/// which interface's DNS servers Windows asks first).
pub fn set_mtu_and_metric(if_luid: u64, mtu: u32, metric: u32) -> Result<()> {
    let mut row = MIB_IPINTERFACE_ROW::default();
    // SAFETY: row is a valid, writable MIB_IPINTERFACE_ROW.
    unsafe { InitializeIpInterfaceEntry(&mut row) };
    row.Family = AF_INET;
    row.InterfaceLuid = luid(if_luid);
    // SAFETY: row identifies the interface by family and LUID.
    check("GetIpInterfaceEntry", unsafe {
        GetIpInterfaceEntry(&mut row)
    })?;
    row.NlMtu = mtu;
    row.UseAutomaticMetric = false;
    row.Metric = metric;
    // Must be zero for IPv4 or SetIpInterfaceEntry fails.
    row.SitePrefixLength = 0;
    // SAFETY: row was filled by GetIpInterfaceEntry.
    check("SetIpInterfaceEntry", unsafe {
        SetIpInterfaceEntry(&mut row)
    })
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

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}
