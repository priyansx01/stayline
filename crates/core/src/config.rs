use std::net::Ipv4Addr;

use quick_xml::events::{BytesStart, Event};
use quick_xml::{Reader, XmlVersion};

use crate::error::{Error, Result};

/// A route the gateway wants sent through the tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Route {
    pub network: Ipv4Addr,
    pub mask: Ipv4Addr,
}

impl Route {
    pub fn prefix_len(&self) -> u32 {
        u32::from(self.mask).count_ones()
    }
}

/// DNS servers to use for specific domains only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitDns {
    pub domains: Vec<String>,
    pub servers: Vec<Ipv4Addr>,
}

/// Parsed `/remote/fortisslvpn_xml`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TunnelConfig {
    pub assigned_ip: Option<Ipv4Addr>,
    pub dns: Vec<Ipv4Addr>,
    pub dns_suffix: Option<String>,
    pub split_dns: Vec<SplitDns>,
    /// Split-tunnel routes. Empty means all traffic goes through the tunnel.
    pub routes: Vec<Route>,
    /// Tunnel modes the gateway offers, e.g. `ppp`, `tun`.
    pub tunnel_methods: Vec<String>,
    pub fortios_version: Option<String>,
    pub idle_timeout_secs: Option<u32>,
    pub auth_timeout_secs: Option<u32>,
    pub tunnel_connect_without_reauth: Option<bool>,
    pub tunnel_user_session_timeout_secs: Option<u32>,
}

impl TunnelConfig {
    pub fn is_full_tunnel(&self) -> bool {
        self.routes.is_empty()
    }

    pub fn parse(xml: &str) -> Result<Self> {
        let mut reader = Reader::from_str(xml);
        reader.config_mut().trim_text(true);

        let mut cfg = TunnelConfig::default();
        let mut seen_root = false;
        let mut in_ipv6 = 0usize;
        let mut text_target: Option<&'static str> = None;

        loop {
            let event = reader
                .read_event()
                .map_err(|e| Error::ConfigParse(e.to_string()))?;
            match event {
                Event::Start(e) => {
                    seen_root |= e.local_name().as_ref() == "sslvpn-tunnel";
                    if e.local_name().as_ref() == "ipv6" {
                        in_ipv6 += 1;
                    } else if in_ipv6 == 0 {
                        text_target = cfg.apply_element(&e)?;
                    }
                }
                Event::Empty(e) => {
                    seen_root |= e.local_name().as_ref() == "sslvpn-tunnel";
                    if in_ipv6 == 0 && e.local_name().as_ref() != "ipv6" {
                        cfg.apply_element(&e)?;
                    }
                }
                Event::Text(t) => {
                    if let Some("dns-suffix") = text_target {
                        let text = t.xml10_content();
                        let text = text.trim();
                        if !text.is_empty() {
                            cfg.dns_suffix = Some(text.to_owned());
                        }
                    }
                }
                Event::End(e) => {
                    if e.local_name().as_ref() == "ipv6" {
                        in_ipv6 = in_ipv6.saturating_sub(1);
                    }
                    text_target = None;
                }
                Event::Eof => break,
                _ => {}
            }
        }

        if !seen_root {
            return Err(Error::ConfigParse("missing <sslvpn-tunnel> element".into()));
        }
        Ok(cfg)
    }

    /// Applies one element's attributes. Returns the element name if its
    /// text content is also wanted.
    fn apply_element(&mut self, e: &BytesStart<'_>) -> Result<Option<&'static str>> {
        let attr = |name: &str| attribute(e, name);
        match e.local_name().as_ref() {
            "assigned-addr" => {
                if let Some(ip) = attr("ipv4")?.and_then(|v| v.parse().ok()) {
                    self.assigned_ip = Some(ip);
                }
            }
            "dns" => {
                if let Some(ip) = attr("ip")?.and_then(|v| v.parse().ok()) {
                    self.dns.push(ip);
                }
            }
            "dns-suffix" => {
                if let Some(v) = attr("val")?.filter(|v| !v.is_empty()) {
                    self.dns_suffix = Some(v);
                }
                return Ok(Some("dns-suffix"));
            }
            "split-dns" => {
                let domains: Vec<String> = attr("domains")?
                    .unwrap_or_default()
                    .split([',', ';', ' '])
                    .filter(|d| !d.is_empty())
                    .map(str::to_owned)
                    .collect();
                let servers = [attr("dnsserver1")?, attr("dnsserver2")?]
                    .into_iter()
                    .flatten()
                    .filter_map(|s| s.parse().ok())
                    .collect();
                if !domains.is_empty() {
                    self.split_dns.push(SplitDns { domains, servers });
                }
            }
            "addr" => {
                let network = attr("ip")?.and_then(|v| v.parse().ok());
                let mask = attr("mask")?.and_then(|v| v.parse().ok());
                if let (Some(network), Some(mask)) = (network, mask) {
                    self.routes.push(Route { network, mask });
                }
            }
            "tunnel-method" => {
                if let Some(v) = attr("value")? {
                    self.tunnel_methods.push(v);
                }
            }
            "fos" => {
                if let (Some(major), Some(minor)) = (attr("major")?, attr("minor")?) {
                    let patch = attr("patch")?.unwrap_or_else(|| "0".into());
                    self.fortios_version = Some(format!("{major}.{minor}.{patch}"));
                }
            }
            "auth-ses" => {
                self.tunnel_connect_without_reauth =
                    attr("tun-connect-without-reauth")?.map(|v| v == "1");
                self.tunnel_user_session_timeout_secs =
                    attr("tun-user-ses-timeout")?.and_then(|v| v.parse().ok());
            }
            "idle-timeout" => self.idle_timeout_secs = attr("val")?.and_then(|v| v.parse().ok()),
            "auth-timeout" => self.auth_timeout_secs = attr("val")?.and_then(|v| v.parse().ok()),
            _ => {}
        }
        Ok(None)
    }
}

fn attribute(e: &BytesStart<'_>, name: &str) -> Result<Option<String>> {
    match e.try_get_attribute(name) {
        Ok(Some(a)) => a
            .normalized_value(XmlVersion::Implicit1_0)
            .map(|v| Some(v.trim().to_owned()))
            .map_err(|err| Error::ConfigParse(err.to_string())),
        Ok(None) => Ok(None),
        Err(err) => Err(Error::ConfigParse(err.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPLIT: &str = r#"<?xml version='1.0' encoding='utf-8'?>
<sslvpn-tunnel ver='2' dtls='1' patch='1'>
  <dtls-config heartbeat-interval='10' heartbeat-fail-count='10' heartbeat-idle-timeout='10' client-hello-timeout='10'/>
  <tunnel-method value='ppp'/>
  <tunnel-method value='tun'/>
  <fos platform='FG100F' major='7' minor='2' patch='8' build='1639' branch='1639'/>
  <auth-ses check-src-ip='1' tun-connect-without-reauth='1' tun-user-ses-timeout='30'/>
  <client-config save-password='off' keep-alive='off' auto-connect='off'/>
  <ipv4>
    <dns ip='10.10.0.53'/>
    <dns ip='10.10.0.54'/>
    <dns-suffix>corp.example.com</dns-suffix>
    <split-dns domains='corp.example.com,lab.example.com' dnsserver1='10.10.0.53' dnsserver2=''/>
    <assigned-addr ipv4='10.212.134.200'/>
    <split-tunnel-info>
      <addr ip='10.10.0.0' mask='255.255.0.0'/>
      <addr ip='192.168.50.0' mask='255.255.255.0'/>
    </split-tunnel-info>
  </ipv4>
  <ipv6>
    <dns ip='fd00::53'/>
    <assigned-addr ipv6='fd00::200' prefix-len='128'/>
  </ipv6>
  <idle-timeout val='3600'/>
  <auth-timeout val='28800'/>
</sslvpn-tunnel>"#;

    #[test]
    fn parses_split_tunnel_config() {
        let cfg = TunnelConfig::parse(SPLIT).unwrap();
        assert_eq!(cfg.assigned_ip, Some(Ipv4Addr::new(10, 212, 134, 200)));
        assert_eq!(
            cfg.dns,
            vec![Ipv4Addr::new(10, 10, 0, 53), Ipv4Addr::new(10, 10, 0, 54)]
        );
        assert_eq!(cfg.dns_suffix.as_deref(), Some("corp.example.com"));
        assert_eq!(cfg.split_dns.len(), 1);
        assert_eq!(
            cfg.split_dns[0].domains,
            vec!["corp.example.com", "lab.example.com"]
        );
        assert_eq!(cfg.split_dns[0].servers, vec![Ipv4Addr::new(10, 10, 0, 53)]);
        assert_eq!(cfg.routes.len(), 2);
        assert_eq!(cfg.routes[0].prefix_len(), 16);
        assert_eq!(cfg.routes[1].network, Ipv4Addr::new(192, 168, 50, 0));
        assert!(!cfg.is_full_tunnel());
        assert_eq!(cfg.tunnel_methods, vec!["ppp", "tun"]);
        assert_eq!(cfg.fortios_version.as_deref(), Some("7.2.8"));
        assert_eq!(cfg.tunnel_connect_without_reauth, Some(true));
        assert_eq!(cfg.tunnel_user_session_timeout_secs, Some(30));
        assert_eq!(cfg.idle_timeout_secs, Some(3600));
        assert_eq!(cfg.auth_timeout_secs, Some(28800));
    }

    #[test]
    fn parses_legacy_flat_config_as_full_tunnel() {
        let xml = "<?xml version='1.0'?><sslvpn-tunnel ver='1'>\
            <assigned-addr ipv4='172.16.1.9'/><dns ip='172.16.0.1'/><dns-suffix val='example.org'/>\
            </sslvpn-tunnel>";
        let cfg = TunnelConfig::parse(xml).unwrap();
        assert_eq!(cfg.assigned_ip, Some(Ipv4Addr::new(172, 16, 1, 9)));
        assert_eq!(cfg.dns_suffix.as_deref(), Some("example.org"));
        assert!(cfg.is_full_tunnel());
    }

    #[test]
    fn rejects_html_login_page() {
        let html = "<html><body><form action='/remote/logincheck'></form></body></html>";
        assert!(matches!(
            TunnelConfig::parse(html),
            Err(Error::ConfigParse(_))
        ));
    }
}
