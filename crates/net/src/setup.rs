use std::net::Ipv4Addr;

use stayline_core::TunnelConfig;

use crate::TUNNEL_MTU;
use crate::error::Result;
use crate::iphlp::{self, RouteRow};

/// Interface metric for the tunnel: low, so its routes and DNS win.
const TUNNEL_METRIC: u32 = 1;

/// Address, routes and DNS applied for one tunnel session. Dropping it
/// removes the routes and address again.
#[derive(Debug)]
pub struct TunnelNetwork {
    tun_luid: u64,
    local_ip: Ipv4Addr,
    routes: Vec<RouteRow>,
}

impl TunnelNetwork {
    /// Configures the tunnel adapter for `cfg`.
    ///
    /// `gateway_ip` is the address the tunnel's TLS connection uses; a host
    /// route keeps it on the current physical path so the tunnel does not
    /// try to route itself.
    pub fn apply(
        tun_luid: u64,
        local_ip: Ipv4Addr,
        gateway_ip: Ipv4Addr,
        cfg: &TunnelConfig,
    ) -> Result<Self> {
        // Look this up before any tunnel routes exist.
        let (phys_luid, phys_next_hop) = iphlp::best_route(gateway_ip)?;

        // Partially applied state is cleaned up by Drop if a step fails.
        let mut net = Self {
            tun_luid,
            local_ip,
            routes: Vec::new(),
        };
        iphlp::add_address(tun_luid, local_ip)?;
        iphlp::set_mtu_and_metric(tun_luid, TUNNEL_MTU, TUNNEL_METRIC)?;

        if phys_luid != tun_luid {
            net.add(phys_luid, gateway_ip, 32, phys_next_hop)?;
        }

        if cfg.is_full_tunnel() {
            // Two /1 routes beat the existing default route without replacing it.
            net.add(
                tun_luid,
                Ipv4Addr::new(0, 0, 0, 0),
                1,
                Ipv4Addr::UNSPECIFIED,
            )?;
            net.add(
                tun_luid,
                Ipv4Addr::new(128, 0, 0, 0),
                1,
                Ipv4Addr::UNSPECIFIED,
            )?;
        } else {
            for route in &cfg.routes {
                let network = Ipv4Addr::from(u32::from(route.network) & u32::from(route.mask));
                net.add(
                    tun_luid,
                    network,
                    route.prefix_len() as u8,
                    Ipv4Addr::UNSPECIFIED,
                )?;
            }
            // Make sure the tunnel DNS servers are reachable through the tunnel.
            for dns in &cfg.dns {
                net.add(tun_luid, *dns, 32, Ipv4Addr::UNSPECIFIED)?;
            }
        }

        if !cfg.dns.is_empty() {
            iphlp::set_dns(tun_luid, &cfg.dns, &search_domains(cfg))?;
        }

        tracing::info!(%local_ip, routes = net.routes.len(), full_tunnel = cfg.is_full_tunnel(), "tunnel network configured");
        Ok(net)
    }

    fn add(
        &mut self,
        luid: u64,
        network: Ipv4Addr,
        prefix_len: u8,
        next_hop: Ipv4Addr,
    ) -> Result<()> {
        if let Some(row) = iphlp::add_route(luid, network, prefix_len, next_hop, 0)? {
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
