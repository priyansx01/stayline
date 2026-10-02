use std::net::Ipv4Addr;
use std::sync::Mutex;

use stayline_core::TunnelConfig;
use stayline_core::supervisor::TunnelHooks;

use crate::TUNNEL_MTU;
use crate::error::{NetError, Result};
use crate::iphlp::{self, RouteRow};

/// Interface metric for the tunnel: low, so its routes and DNS win.
const TUNNEL_METRIC: u32 = 1;

/// Address, routes and DNS of the tunnel adapter for one tunnel
/// configuration. Dropping it removes the routes and address again.
#[derive(Debug)]
pub struct TunnelNetwork {
    tun_luid: u64,
    local_ip: Ipv4Addr,
    routes: Vec<RouteRow>,
}

impl TunnelNetwork {
    pub fn apply(tun_luid: u64, local_ip: Ipv4Addr, cfg: &TunnelConfig) -> Result<Self> {
        // Partially applied state is cleaned up by Drop if a step fails.
        let mut net = Self {
            tun_luid,
            local_ip,
            routes: Vec::new(),
        };
        iphlp::add_address(tun_luid, local_ip)?;
        iphlp::set_mtu_and_metric(tun_luid, TUNNEL_MTU, TUNNEL_METRIC)?;

        if cfg.is_full_tunnel() {
            // Two /1 routes beat the existing default route without replacing it.
            net.add(Ipv4Addr::new(0, 0, 0, 0), 1)?;
            net.add(Ipv4Addr::new(128, 0, 0, 0), 1)?;
        } else {
            for route in &cfg.routes {
                let network = Ipv4Addr::from(u32::from(route.network) & u32::from(route.mask));
                net.add(network, route.prefix_len() as u8)?;
            }
            // Make sure the tunnel DNS servers are reachable through the tunnel.
            for dns in &cfg.dns {
                net.add(*dns, 32)?;
            }
        }

        if !cfg.dns.is_empty() {
            iphlp::set_dns(tun_luid, &cfg.dns, &search_domains(cfg))?;
        }

        tracing::info!(%local_ip, routes = net.routes.len(), full_tunnel = cfg.is_full_tunnel(), "tunnel network configured");
        Ok(net)
    }

    fn add(&mut self, network: Ipv4Addr, prefix_len: u8) -> Result<()> {
        if let Some(row) =
            iphlp::add_route(self.tun_luid, network, prefix_len, Ipv4Addr::UNSPECIFIED, 0)?
        {
            tracing::debug!(?row, "route added");
            self.routes.push(row);
        }
        Ok(())
    }
}

impl Drop for TunnelNetwork {
    fn drop(&mut self) {
        for row in self.routes.iter().rev() {
            iphlp::delete_route(row);
        }
        iphlp::delete_address(self.tun_luid, self.local_ip);
    }
}

/// Host route that keeps traffic to the gateway on the physical network,
/// so the tunnel does not try to carry itself. Removed on drop.
#[derive(Debug)]
pub struct GatewayRoute {
    route: Option<RouteRow>,
    /// Default route at the time the route was pinned.
    uplink: Option<(u64, Ipv4Addr)>,
}

impl GatewayRoute {
    pub fn pin(tun_luid: u64, gateway_ip: Ipv4Addr) -> Result<Self> {
        let uplink = iphlp::default_route(tun_luid);
        let (luid, next_hop) = match iphlp::best_route(gateway_ip) {
            Ok((luid, hop)) if luid != tun_luid => (luid, hop),
            // The best route goes into the tunnel (full tunnel): use the uplink.
            _ => uplink.ok_or(NetError::Offline)?,
        };
        let route = iphlp::add_route(luid, gateway_ip, 32, next_hop, 0)?;
        tracing::debug!(%gateway_ip, %next_hop, "gateway route pinned");
        Ok(Self { route, uplink })
    }

    /// Whether the machine's uplink is different from when this was pinned.
    pub fn uplink_changed(&self, tun_luid: u64) -> bool {
        iphlp::default_route(tun_luid) != self.uplink
    }
}

impl Drop for GatewayRoute {
    fn drop(&mut self) {
        if let Some(route) = &self.route {
            iphlp::delete_route(route);
        }
    }
}

/// [`TunnelHooks`] for the Windows tunnel adapter.
///
/// The adapter's address and routes stay in place while the tunnel is down,
/// so applications see a pause rather than a vanished network.
pub struct WindowsHooks {
    tun_luid: u64,
    gateway: Mutex<Option<GatewayRoute>>,
    network: Mutex<Option<(Ipv4Addr, TunnelConfig, TunnelNetwork)>>,
}

impl WindowsHooks {
    pub fn new(tun_luid: u64) -> Self {
        Self {
            tun_luid,
            gateway: Mutex::new(None),
            network: Mutex::new(None),
        }
    }
}

impl TunnelHooks for WindowsHooks {
    fn route_to_gateway(&self, gateway_ip: Ipv4Addr) -> Result<(), String> {
        let mut gateway = self.gateway.lock().expect("gateway route lock");
        // Remove the old route first: it may point at a network we left.
        *gateway = None;
        *gateway = Some(GatewayRoute::pin(self.tun_luid, gateway_ip).map_err(|e| e.to_string())?);
        Ok(())
    }

    fn link_up(&self, local_ip: Ipv4Addr, cfg: &TunnelConfig) -> Result<(), String> {
        let mut network = self.network.lock().expect("tunnel network lock");
        if let Some((ip, old_cfg, _)) = network.as_ref()
            && *ip == local_ip
            && old_cfg == cfg
        {
            return Ok(());
        }
        *network = None;
        let applied =
            TunnelNetwork::apply(self.tun_luid, local_ip, cfg).map_err(|e| e.to_string())?;
        *network = Some((local_ip, cfg.clone(), applied));
        Ok(())
    }

    fn network_available(&self) -> bool {
        iphlp::default_route(self.tun_luid).is_some()
    }

    fn gateway_path_changed(&self) -> bool {
        self.gateway
            .lock()
            .expect("gateway route lock")
            .as_ref()
            .is_some_and(|g| g.uplink_changed(self.tun_luid))
    }
}

/// DNS suffix plus split-DNS domains, without duplicates.
fn search_domains(cfg: &TunnelConfig) -> Vec<String> {
    let mut domains: Vec<String> = Vec::new();
    let suffixes = cfg.dns_suffix.iter().flat_map(|s| s.split([';', ',', ' ']));
    let split = cfg
        .split_dns
        .iter()
        .flat_map(|s| s.domains.iter().map(String::as_str));
    for d in suffixes.chain(split) {
        let d = d.trim().trim_start_matches('.');
        if !d.is_empty() && !domains.iter().any(|x| x.eq_ignore_ascii_case(d)) {
            domains.push(d.to_owned());
        }
    }
    domains
}

#[cfg(test)]
mod tests {
    use super::*;
    use stayline_core::SplitDns;

    #[test]
    fn search_domains_merges_suffix_and_split_dns() {
        let cfg = TunnelConfig {
            dns_suffix: Some("corp.example.com;.lab.example.com".into()),
            split_dns: vec![SplitDns {
                domains: vec!["Corp.Example.com".into(), "intra.example.net".into()],
                servers: vec![],
            }],
            ..Default::default()
        };
        assert_eq!(
            search_domains(&cfg),
            vec!["corp.example.com", "lab.example.com", "intra.example.net"]
        );
    }
}
