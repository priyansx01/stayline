use std::fmt;

use url::Url;

use crate::error::{Error, Result};

const DEFAULT_PORT: u16 = 443;

/// Address of a FortiGate SSL-VPN gateway.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gateway {
    host: String,
    port: u16,
    base: Url,
}

impl Gateway {
    /// Accepts `host`, `host:port` or `https://host[:port][/]`.
    pub fn parse(input: &str) -> Result<Self> {
        let input = input.trim();
        let with_scheme = if input.contains("://") {
            input.to_owned()
        } else {
            format!("https://{input}")
        };
        let url = Url::parse(&with_scheme).map_err(|e| Error::InvalidGateway(e.to_string()))?;
        if url.scheme() != "https" {
            return Err(Error::InvalidGateway("only https:// is supported".into()));
        }
        let host = url
            .host_str()
            .filter(|h| !h.is_empty())
            .ok_or_else(|| Error::InvalidGateway("missing host".into()))?
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_owned();
        let port = url.port().unwrap_or(DEFAULT_PORT);

        let mut base = url.clone();
        base.set_path("/");
        base.set_query(None);
        base.set_fragment(None);

        Ok(Self { host, port, base })
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// Full URL for a path on the gateway, e.g. `/remote/logincheck`.
    pub fn url(&self, path: &str) -> Url {
        self.base.join(path).expect("gateway paths are valid")
    }
}

impl fmt::Display for Gateway {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.port == DEFAULT_PORT {
            write!(f, "{}", self.host)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_host_only() {
        let g = Gateway::parse("vpn.example.com").unwrap();
        assert_eq!(g.host(), "vpn.example.com");
        assert_eq!(g.port(), 443);
        assert_eq!(
            g.url("/remote/logincheck").as_str(),
            "https://vpn.example.com/remote/logincheck"
        );
    }

    #[test]
    fn parses_host_and_port() {
        let g = Gateway::parse("vpn.example.com:10443").unwrap();
        assert_eq!(g.port(), 10443);
        assert_eq!(g.to_string(), "vpn.example.com:10443");
    }

    #[test]
    fn parses_full_url_and_drops_path() {
        let g = Gateway::parse("https://10.0.0.1:8443/remote/login?lang=en").unwrap();
        assert_eq!(g.host(), "10.0.0.1");
        assert_eq!(
            g.url("/remote/fortisslvpn_xml").as_str(),
            "https://10.0.0.1:8443/remote/fortisslvpn_xml"
        );
    }

    #[test]
    fn rejects_http() {
        assert!(Gateway::parse("http://vpn.example.com").is_err());
    }
}
