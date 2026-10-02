//! `%APPDATA%\stayline\config\settings.toml`: the user's own settings.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::{ConfigError, project_dirs, write_atomically};

/// Name given to the connection converted from single-connection settings.
pub const LEGACY_NAME: &str = "VPN";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct UserSettings {
    /// Connect when the app starts (at sign-in), if a password is saved.
    pub auto_connect: bool,
    /// Name of the connection Connect uses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active: Option<String>,
    /// The user's own connections, and their username (plus a pin they
    /// accepted) for company connections of the same name.
    #[serde(rename = "connection", skip_serializing_if = "Vec::is_empty")]
    pub connections: Vec<UserConnection>,

    // Single-connection settings from before multiple connections; read
    // once and converted by `migrate_legacy`.
    #[serde(skip_serializing)]
    gateway: String,
    #[serde(skip_serializing)]
    username: String,
    #[serde(skip_serializing)]
    realm: Option<String>,
    #[serde(skip_serializing)]
    pin: Option<String>,
}

impl Default for UserSettings {
    fn default() -> Self {
        Self {
            auto_connect: true,
            active: None,
            connections: Vec::new(),
            gateway: String::new(),
            username: String::new(),
            realm: None,
            pin: None,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct UserConnection {
    pub name: String,
    /// Empty for the user's part of a company connection.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub gateway: String,
    pub username: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pin: Option<String>,
}

impl UserSettings {
    pub fn load() -> Result<Self, ConfigError> {
        match std::fs::read_to_string(path()?) {
            Ok(text) => Ok(toml::from_str(&text)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e.into()),
        }
    }

    pub fn save(&self) -> Result<(), ConfigError> {
        write_atomically(&path()?, toml::to_string_pretty(self)?.as_bytes())?;
        Ok(())
    }

    /// Converts single-connection settings into a connection. Returns its
    /// name if anything was converted.
    pub fn migrate_legacy(&mut self) -> Option<String> {
        if !self.connections.is_empty() || self.gateway.trim().is_empty() {
            return None;
        }
        self.connections.push(UserConnection {
            name: LEGACY_NAME.into(),
            gateway: std::mem::take(&mut self.gateway),
            username: std::mem::take(&mut self.username),
            realm: self.realm.take(),
            pin: self.pin.take(),
        });
        self.active = Some(LEGACY_NAME.into());
        Some(LEGACY_NAME.into())
    }

    /// The user's entry for a company connection, created if missing.
    pub(crate) fn overlay_mut(&mut self, name: &str) -> &mut UserConnection {
        if let Some(i) = self.connections.iter().position(|u| u.name == name) {
            return &mut self.connections[i];
        }
        self.connections.push(UserConnection {
            name: name.to_owned(),
            ..Default::default()
        });
        self.connections.last_mut().expect("just pushed")
    }
}

pub fn path() -> Result<PathBuf, ConfigError> {
    Ok(project_dirs()?.config_dir().join("settings.toml"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_connection_settings_are_migrated() {
        let old = "gateway = \"vpn.example.com:10443\"\nusername = \"alice\"\npin = \"ab\"\nauto_connect = false\n";
        let mut settings: UserSettings = toml::from_str(old).unwrap();
        assert_eq!(settings.migrate_legacy().as_deref(), Some(LEGACY_NAME));
        assert!(!settings.auto_connect);
        assert_eq!(settings.active.as_deref(), Some(LEGACY_NAME));
        assert_eq!(settings.connections[0].gateway, "vpn.example.com:10443");
        assert_eq!(settings.connections[0].username, "alice");

        let text = toml::to_string_pretty(&settings).unwrap();
        assert!(
            !text.starts_with("gateway"),
            "legacy keys must not be written back:\n{text}"
        );
        let reread: UserSettings = toml::from_str(&text).unwrap();
        assert_eq!(reread, settings);
        assert!(settings.migrate_legacy().is_none());
    }

    #[test]
    fn empty_file_gives_defaults() {
        let s: UserSettings = toml::from_str("").unwrap();
        assert!(s.auto_connect);
        assert!(s.connections.is_empty());
    }
}
