//! `%ProgramData%\stayline\connections.toml`: connections set up by the
//! organisation (written by an administrator or the installer).
//!
//! ```toml
//! allow_user_connections = true
//! allow_trust_on_first_use = true
//!
//! [[connection]]
//! name = "Company VPN"
//! gateway = "vpn.example.com:10443"
//! pin = "<sha-256 of the gateway certificate>"
//! ```

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::{ConfigError, write_atomically};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ManagedConfig {
    /// Users may add their own connections next to the company ones.
    pub allow_user_connections: bool,
    /// Users may pin an untrusted certificate on first connect when a
    /// company connection has no pin.
    pub allow_trust_on_first_use: bool,
    #[serde(rename = "connection", skip_serializing_if = "Vec::is_empty")]
    pub connections: Vec<ManagedConnection>,
}

impl Default for ManagedConfig {
    fn default() -> Self {
        Self {
            allow_user_connections: true,
            allow_trust_on_first_use: true,
            connections: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedConnection {
    pub name: String,
    pub gateway: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pin: Option<String>,
}

impl ManagedConfig {
    pub fn load() -> Result<Self, ConfigError> {
        match std::fs::read_to_string(path()?) {
            Ok(text) => Ok(toml::from_str(&text)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e.into()),
        }
    }

    /// Adds or replaces the connection with the same name.
    pub fn upsert(&mut self, connection: ManagedConnection) {
        match self
            .connections
            .iter_mut()
            .find(|c| c.name == connection.name)
        {
            Some(existing) => *existing = connection,
            None => self.connections.push(connection),
        }
    }

    /// Writes the file so that only SYSTEM and administrators can change
    /// it and everyone else can read it. Needs administrator rights.
    #[cfg(windows)]
    pub fn save_protected(&self) -> Result<(), ConfigError> {
        let path = path()?;
        write_atomically(&path, toml::to_string_pretty(self)?.as_bytes())?;
        protect(&path)
    }
}

pub fn path() -> Result<PathBuf, ConfigError> {
    let base = std::env::var_os("ProgramData").ok_or(ConfigError::NoProgramData)?;
    Ok(PathBuf::from(base)
        .join("stayline")
        .join("connections.toml"))
}

#[cfg(windows)]
fn protect(path: &std::path::Path) -> Result<(), ConfigError> {
    use windows::Win32::Foundation::{HLOCAL, LocalFree};
    use windows::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows::Win32::Security::{
        DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
        SetFileSecurityW,
    };
    use windows::core::{HSTRING, w};

    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // Protected DACL: SYSTEM and Administrators full control, Users read.
    // SAFETY: the SDDL string is a valid literal; the descriptor is freed below.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            w!("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)"),
            SDDL_REVISION_1,
            &mut descriptor,
            None,
        )
        .map_err(|e| ConfigError::Protect(e.to_string()))?;
        let result = SetFileSecurityW(
            &HSTRING::from(path.as_os_str()),
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            descriptor,
        );
        let _ = LocalFree(Some(HLOCAL(descriptor.0)));
        result.ok().map_err(|e| ConfigError::Protect(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_documented_format_and_defaults() {
        let text = r#"
            allow_user_connections = false

            [[connection]]
            name = "Company VPN"
            gateway = "vpn.example.com:10443"
            pin = "abcd"
        "#;
        let config: ManagedConfig = toml::from_str(text).unwrap();
        assert!(!config.allow_user_connections);
        assert!(config.allow_trust_on_first_use);
        assert_eq!(config.connections.len(), 1);
        assert_eq!(config.connections[0].realm, None);
    }

    #[test]
    fn upsert_replaces_by_name() {
        let mut config = ManagedConfig::default();
        let conn = |gw: &str| ManagedConnection {
            name: "Company VPN".into(),
            gateway: gw.into(),
            realm: None,
            pin: None,
        };
        config.upsert(conn("a.example.com"));
        config.upsert(conn("b.example.com"));
        assert_eq!(config.connections.len(), 1);
        assert_eq!(config.connections[0].gateway, "b.example.com");
    }
}
