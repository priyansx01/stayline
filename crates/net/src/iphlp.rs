//! Thin safe wrappers over the IP Helper calls stayline needs (IPv4 only).
//!
//! The `windows` crate maps the `BOOLEAN` fields of these rows to Rust
//! `bool`, but Windows may store values other than 0 and 1 in them, which is
//! undefined behaviour for `bool`. Rows that Windows writes are therefore
//! only ever held as `MaybeUninit` and touched field by field through raw
//! pointers, never moved or copied as values.

use std::ffi::c_void;
use std::mem::MaybeUninit;
use std::net::Ipv4Addr;
use std::ptr::addr_of_mut;

use windows::Win32::Foundation::{
    ERROR_NOT_FOUND, ERROR_OBJECT_ALREADY_EXISTS, HANDLE, WIN32_ERROR,
};
use windows::Win32::NetworkManagement::IpHelper::{
    CancelMibChangeNotify2, ConvertInterfaceLuidToGuid, CreateIpForwardEntry2,
    CreateUnicastIpAddressEntry, DNS_INTERFACE_SETTINGS, DNS_INTERFACE_SETTINGS_VERSION1,
    DNS_SETTING_NAMESERVER, DNS_SETTING_SEARCHLIST, DeleteIpForwardEntry2,
    DeleteUnicastIpAddressEntry, FreeMibTable, GetBestRoute2, GetIpForwardTable2,
    GetIpInterfaceEntry, InitializeIpForwardEntry, InitializeIpInterfaceEntry,
    InitializeUnicastIpAddressEntry, MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2, MIB_IPINTERFACE_ROW,
    MIB_NOTIFICATION_TYPE, MIB_UNICASTIPADDRESS_ROW, NotifyIpInterfaceChange, NotifyRouteChange2,
    NotifyUnicastIpAddressChange, SetInterfaceDnsSettings, SetIpInterfaceEntry,
};
use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows::Win32::Networking::WinSock::{
    AF_INET, IN_ADDR, IN_ADDR_0, IpDadStatePreferred, SOCKADDR_IN, SOCKADDR_INET,
};
use windows::core::{GUID, PWSTR};

use stayline_core::supervisor::NetEvent;

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

/// The default route (`0.0.0.0/0`) Windows prefers, ignoring interface
/// `exclude_luid` (the tunnel): interface LUID and next hop. `None` when
/// the machine has no other network.
pub fn default_route(exclude_luid: u64) -> Option<(u64, Ipv4Addr)> {
    let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    // SAFETY: Windows allocates the table; it is freed below.
    let err = unsafe { GetIpForwardTable2(AF_INET, &mut table) };
    if check("GetIpForwardTable2", err).is_err() || table.is_null() {
        return None;
    }

    let mut best: Option<(u32, u64, Ipv4Addr)> = None;
    // SAFETY: the table holds NumEntries rows; only plain fields are read
    // through pointers, never whole rows.
    unsafe {
        let count = (*table).NumEntries as usize;
        let rows = (&raw const (*table).Table).cast::<MIB_IPFORWARD_ROW2>();
        for i in 0..count {
            let row = rows.add(i);
            if (*row).DestinationPrefix.PrefixLength != 0 {
                continue;
            }
            let luid = (*row).InterfaceLuid.Value;
            if luid == exclude_luid {
                continue;
            }
            let Some(if_metric) = interface_metric(luid) else {
                continue;
            };
            let metric = (*row).Metric.saturating_add(if_metric);
            if best.is_none_or(|(m, _, _)| metric < m) {
                best = Some((metric, luid, ipv4_at(&raw const (*row).NextHop)));
            }
        }
        FreeMibTable(table.cast());
    }
    best.map(|(_, luid, hop)| (luid, hop))
}

/// Whether the interface exists, has IPv4 and is connected.
pub fn interface_connected(if_luid: u64) -> bool {
    interface_metric(if_luid).is_some()
}

/// Interface metric, or `None` if the interface has no IPv4, is not
/// connected or is gone.
fn interface_metric(if_luid: u64) -> Option<u32> {
    let mut row = MaybeUninit::<MIB_IPINTERFACE_ROW>::zeroed();
    let p = row.as_mut_ptr();
    // SAFETY: p points to writable memory the size of the row.
    unsafe {
        InitializeIpInterfaceEntry(p);
        addr_of_mut!((*p).Family).write(AF_INET);
        addr_of_mut!((*p).InterfaceLuid).write(luid(if_luid));
        if GetIpInterfaceEntry(p).is_err() || (&raw const (*p).Connected).cast::<u8>().read() == 0 {
            return None;
        }
        Some((*p).Metric)
    }
}

/// Signals network changes outside one interface (the tunnel): default
/// routes, interface connect/disconnect, and address changes.
///
/// Turning Wi-Fi off and on does not touch the default route, which Windows
/// keeps in its table; only interface and address notifications show it.
pub struct NetworkWatcher {
    handles: Vec<HANDLE>,
    context: *mut WatchContext,
}

// SAFETY: the notification handles and context may be used from any
// thread; the context is only freed after every notification is cancelled.
unsafe impl Send for NetworkWatcher {}
unsafe impl Sync for NetworkWatcher {}

struct WatchContext {
    tx: tokio::sync::mpsc::UnboundedSender<NetEvent>,
    exclude_luid: u64,
}

impl WatchContext {
    /// # Safety
    /// `context` must be null or the pointer registered by `NetworkWatcher`.
    unsafe fn signal(context: *const c_void, luid: u64) {
        if context.is_null() {
            return;
        }
        // SAFETY: the context outlives the registrations (see Drop).
        let ctx = unsafe { &*context.cast::<WatchContext>() };
        if luid != ctx.exclude_luid {
            let _ = ctx.tx.send(NetEvent::Changed);
        }
    }
}

unsafe extern "system" fn on_route_change(
    context: *const c_void,
    row: *const MIB_IPFORWARD_ROW2,
    _kind: MIB_NOTIFICATION_TYPE,
) {
    // SAFETY: row is valid for the duration of the callback.
    unsafe {
        // Only default routes matter; host routes change on every attempt.
        if !row.is_null() && (*row).DestinationPrefix.PrefixLength == 0 {
            WatchContext::signal(context, (*row).InterfaceLuid.Value);
        }
    }
}

// Interface notifications only fill in Family, InterfaceLuid and
// InterfaceIndex, so nothing else is read here.
unsafe extern "system" fn on_interface_change(
    context: *const c_void,
    row: *const MIB_IPINTERFACE_ROW,
    _kind: MIB_NOTIFICATION_TYPE,
) {
    // SAFETY: row is valid for the duration of the callback.
    unsafe {
        if !row.is_null() {
            WatchContext::signal(context, (*row).InterfaceLuid.Value);
        }
    }
}

unsafe extern "system" fn on_address_change(
    context: *const c_void,
    row: *const MIB_UNICASTIPADDRESS_ROW,
    _kind: MIB_NOTIFICATION_TYPE,
) {
    // SAFETY: row is valid for the duration of the callback.
    unsafe {
        if !row.is_null() {
            WatchContext::signal(context, (*row).InterfaceLuid.Value);
        }
    }
}

impl NetworkWatcher {
    /// Sends [`NetEvent::Changed`] on `tx` for every relevant change.
    pub fn start(
        exclude_luid: u64,
        tx: tokio::sync::mpsc::UnboundedSender<NetEvent>,
    ) -> Result<Self> {
        let context = Box::into_raw(Box::new(WatchContext { tx, exclude_luid }));
        // From here on Drop cancels what was registered and frees the context.
        let mut watcher = Self {
            handles: Vec::with_capacity(3),
            context,
        };
        let ctx: *const c_void = context.cast_const().cast();

        let mut handle = HANDLE::default();
        // SAFETY: ctx outlives the registration (freed in Drop).
        let err =
            unsafe { NotifyRouteChange2(AF_INET, Some(on_route_change), ctx, false, &mut handle) };
        check("NotifyRouteChange2", err)?;
        watcher.handles.push(handle);

        let mut handle = HANDLE::default();
        // SAFETY: as above.
        let err = unsafe {
            NotifyIpInterfaceChange(
                AF_INET,
                Some(on_interface_change),
                Some(ctx),
                false,
                &mut handle,
            )
        };
        check("NotifyIpInterfaceChange", err)?;
        watcher.handles.push(handle);

        let mut handle = HANDLE::default();
        // SAFETY: as above.
        let err = unsafe {
            NotifyUnicastIpAddressChange(
                AF_INET,
                Some(on_address_change),
                Some(ctx),
                false,
                &mut handle,
            )
        };
        check("NotifyUnicastIpAddressChange", err)?;
        watcher.handles.push(handle);

        Ok(watcher)
    }
}

impl Drop for NetworkWatcher {
    fn drop(&mut self) {
        // SAFETY: CancelMibChangeNotify2 waits for running callbacks, after
        // which the context is no longer used.
        unsafe {
            for handle in &self.handles {
                let _ = CancelMibChangeNotify2(*handle);
            }
            drop(Box::from_raw(self.context));
        }
    }
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
            // With no tunnel up, the preferred default route is the same path.
            let (uplink, _) = default_route(0).expect("a default route exists");
            assert_eq!(uplink, luid);
        }
    }

    #[test]
    fn network_watcher_starts_and_stops() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let _guard = rt.enter();
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let watcher = NetworkWatcher::start(0, tx).unwrap();
        drop(watcher);
    }

    #[test]
    fn sockaddr_round_trips() {
        let ip = Ipv4Addr::new(10, 212, 134, 200);
        let addr = sockaddr(ip);
        // SAFETY: built as AF_INET just above.
        assert_eq!(unsafe { ipv4_at(&addr) }, ip);
    }
}
