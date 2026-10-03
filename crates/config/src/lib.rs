//! Connection settings.
//!
//! Two sources are merged into the list of [`Connection`]s the app shows:
//!
//! - **Company connections** in `%ProgramData%\stayline\connections.toml`,
//!   written by an administrator or the installer ([`managed`]). Users
//!   cannot change their gateway or certificate pin.
//! - **User settings** in `%APPDATA%\stayline\config\settings.toml`
//!   ([`user`]): the active connection, the user's name for each company
//!   connection, and connections the user added (if allowed).
//!
//! Passwords are stored per connection, encrypted for the Windows user
//! ([`secret`]).

pub mod managed;
pub mod user;

#[cfg(windows)]
pub mod secret;

use std::path::Path;

use stayline_ipc::Profile;

use managed::ManagedConfig;
pub use user::{ThemePreference, UserConnection, UserSettings};

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("no user profile directory")]
    NoHome,
    #[error("the ProgramData folder is not set")]
    NoProgramData,
    #[error("could not read or write settings: {0}")]
    Io(#[from] std::io::Error),
    #[error("settings file is invalid: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("could not encode settings: {0}")]
    Encode(#[from] toml::ser::Error),
    #[error("could not protect the company settings file: {0}")]
    Protect(String),
}

/// A connection as the app uses it: company settings merged with the user's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Connection {
    pub name: String,
    pub gateway: String,
    pub username: String,
    pub realm: Option<String>,
    pub pin: Option<String>,
    /// Set up by the organisation; gateway and pin cannot be edited.
    pub managed: bool,
    /// The user may pin the certificate themselves on first connect.
    pub may_trust_on_first_use: bool,
}

impl Connection {
    pub fn is_complete(&self) -> bool {
        !self.gateway.trim().is_empty() && !self.username.trim().is_empty()
    }

    pub fn profile(&self) -> Profile {
        Profile {
            gateway: self.gateway.trim().to_owned(),
            username: self.username.trim().to_owned(),
            realm: self.realm.clone().filter(|r| !r.trim().is_empty()),
            pin: self.pin.clone().filter(|p| !p.trim().is_empty()),
        }
    }
}

/// What the connection form submits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionEdit {
    pub name: String,
    pub gateway: String,
    pub username: String,
    pub realm: Option<String>,
    pub pin: Option<String>,
}

/// Company and user settings together.
#[derive(Debug, Clone, Default)]
pub struct Config {
    pub user: UserSettings,
    pub managed: ManagedConfig,
}

impl Config {
    /// Loads both files. Settings from before multiple connections are
    /// converted (and saved) on the way.
    pub fn load() -> Result<Self, ConfigError> {
        let managed = ManagedConfig::load().unwrap_or_else(|e| {
            tracing::warn!(error = %e, "ignoring unreadable company settings");
            ManagedConfig::default()
        });
        let mut user = UserSettings::load()?;
        if let Some(name) = user.migrate_legacy() {
            #[cfg(windows)]
            secret::adopt_legacy(&name);
            let _ = name;
            user.save()?;
        }
        Ok(Self { user, managed })
    }

    pub fn allow_user_connections(&self) -> bool {
        self.managed.allow_user_connections || self.managed.connections.is_empty()
    }

    /// Company connections first, then the user's own.
    pub fn connections(&self) -> Vec<Connection> {
        let mut out = Vec::new();
        for m in &self.managed.connections {
            let overlay = self.user.connections.iter().find(|u| u.name == m.name);
            let may_trust = m.pin.is_none() && self.managed.allow_trust_on_first_use;
            out.push(Connection {
                name: m.name.clone(),
                gateway: m.gateway.clone(),
                username: overlay.map(|u| u.username.clone()).unwrap_or_default(),
                realm: m
                    .realm
                    .clone()
                    .or_else(|| overlay.and_then(|u| u.realm.clone())),
                pin: m
                    .pin
                    .clone()
                    .or_else(|| overlay.and_then(|u| u.pin.clone()).filter(|_| may_trust)),
                managed: true,
                may_trust_on_first_use: may_trust,
            });
        }
        if self.allow_user_connections() {
            for u in &self.user.connections {
                if self.is_managed(&u.name) || u.gateway.trim().is_empty() {
                    continue;
                }
                out.push(Connection {
                    name: u.name.clone(),
                    gateway: u.gateway.clone(),
                    username: u.username.clone(),
                    realm: u.realm.clone(),
                    pin: u.pin.clone(),
                    managed: false,
                    may_trust_on_first_use: true,
                });
            }
        }
        out
    }

    pub fn connection(&self, name: &str) -> Option<Connection> {
        self.connections().into_iter().find(|c| c.name == name)
    }

    /// The connection Connect uses: the chosen one, else the first.
    pub fn active(&self) -> Option<Connection> {
        let all = self.connections();
        self.user
            .active
            .as_ref()
            .and_then(|name| all.iter().find(|c| &c.name == name).cloned())
            .or_else(|| all.into_iter().next())
    }

    pub fn set_active(&mut self, name: &str) {
        self.user.active = Some(name.to_owned());
    }

    pub fn is_managed(&self, name: &str) -> bool {
        self.managed.connections.iter().any(|m| m.name == name)
    }

    /// Adds or updates a connection. `original` is the name it had before
    /// (`None` for a new one). For a company connection only the username
    /// (and a realm the company did not set) are taken from `edit`.
    pub fn save_connection(
        &mut self,
        original: Option<&str>,
        edit: ConnectionEdit,
    ) -> Result<(), String> {
        if let Some(name) = original.filter(|n| self.is_managed(n)) {
            let realm_locked = self
                .managed
                .connections
                .iter()
                .any(|m| m.name == name && m.realm.is_some());
            let overlay = self.user.overlay_mut(name);
            overlay.username = edit.username.trim().to_owned();
            if !realm_locked {
                overlay.realm = edit.realm;
            }
            return Ok(());
        }

        let name = edit.name.trim().to_owned();
        if name.is_empty() {
            return Err("Give the connection a name.".into());
        }
        if original.is_none() && !self.allow_user_connections() {
            return Err("Your organisation does not allow adding connections.".into());
        }
        let taken = self
            .connections()
            .iter()
            .any(|c| c.name == name && Some(c.name.as_str()) != original)
            || self.is_managed(&name);
        if taken {
            return Err(format!("There is already a connection called \"{name}\"."));
        }

        let updated = UserConnection {
            name: name.clone(),
            gateway: edit.gateway.trim().to_owned(),
            username: edit.username.trim().to_owned(),
            realm: edit.realm,
            pin: edit.pin,
        };
        match original.and_then(|o| self.user.connections.iter_mut().find(|u| u.name == o)) {
            Some(existing) => *existing = updated,
            None => self.user.connections.push(updated),
        }
        if let Some(old) = original
            && old != name
            && self.user.active.as_deref() == Some(old)
        {
            self.user.active = Some(name);
        }
        Ok(())
    }

    pub fn remove_connection(&mut self, name: &str) -> Result<(), String> {
        if self.is_managed(name) {
            return Err("This connection is managed by your organisation.".into());
        }
        self.user.connections.retain(|u| u.name != name);
        if self.user.active.as_deref() == Some(name) {
            self.user.active = None;
        }
        Ok(())
    }

    /// Pins a certificate the user accepted on first connect.
    pub fn trust(&mut self, name: &str, fingerprint: &str) -> Result<(), String> {
        let connection = self.connection(name).ok_or("Unknown connection.")?;
        if !connection.may_trust_on_first_use {
            return Err("Your organisation manages this connection's certificate.".into());
        }
        if connection.managed {
            self.user.overlay_mut(name).pin = Some(fingerprint.to_owned());
        } else if let Some(own) = self.user.connections.iter_mut().find(|u| u.name == name) {
            own.pin = Some(fingerprint.to_owned());
        }
        Ok(())
    }
}

/// Checks what the user typed in the connection form. Returns the cleaned
/// gateway and pin, or a message to show next to the form.
pub fn validate(
    gateway: &str,
    username: &str,
    pin: &str,
) -> Result<(String, Option<String>), String> {
    let gateway = gateway.trim();
    if gateway.is_empty() {
        return Err("Enter the gateway address.".into());
    }
    if gateway.chars().any(char::is_whitespace) {
        return Err("The gateway address cannot contain spaces.".into());
    }
    if gateway.contains("://") && !gateway.to_ascii_lowercase().starts_with("https://") {
        return Err("The gateway address must use https://.".into());
    }
    if username.trim().is_empty() {
        return Err("Enter your username.".into());
    }
    Ok((gateway.to_owned(), normalize_pin(pin)?))
}

/// Port FortiGate SSL-VPN uses unless configured otherwise.
pub const DEFAULT_PORT: u16 = 443;

/// Splits a stored gateway (`host`, `host:port`, `https://host:port/...`,
/// `[v6]:port`) into the address and port shown in separate fields.
pub fn split_gateway(gateway: &str) -> (String, String) {
    let rest = gateway.trim();
    let rest = rest
        .strip_prefix("https://")
        .or_else(|| rest.strip_prefix("HTTPS://"))
        .unwrap_or(rest);
    let rest = rest.split('/').next().unwrap_or("");
    if let Some((host, after)) = rest.strip_prefix('[').and_then(|v6| v6.split_once(']')) {
        let port = after.strip_prefix(':').unwrap_or("");
        return (host.to_owned(), port.to_owned());
    }
    match rest.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => (host.to_owned(), port.to_owned()),
        _ => (rest.to_owned(), String::new()),
    }
}

/// Joins the address and port fields into the stored `host:port` form.
/// An empty port means [`DEFAULT_PORT`].
pub fn join_gateway(host: &str, port: &str) -> Result<String, String> {
    let host = host
        .trim()
        .trim_start_matches("https://")
        .trim_end_matches('/');
    if host.is_empty() {
        return Err("Enter the gateway address.".into());
    }
    if host.contains("://") || host.contains('/') || host.chars().any(char::is_whitespace) {
        return Err(
            "Enter only the gateway's name or IP address, without https:// or a path.".into(),
        );
    }
    let port = port.trim();
    let port: u16 = if port.is_empty() {
        DEFAULT_PORT
    } else {
        port.parse()
            .ok()
            .filter(|p| *p > 0)
            .ok_or("The port must be a number from 1 to 65535.")?
    };
    let host = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    Ok(format!("{host}:{port}"))
}

/// Lower-case hex without separators, or `None` if empty.
pub fn normalize_pin(pin: &str) -> Result<Option<String>, String> {
    let pin: String = pin
        .chars()
        .filter(|c| *c != ':' && !c.is_whitespace())
        .collect::<String>()
        .to_ascii_lowercase();
    if pin.is_empty() {
        return Ok(None);
    }
    if pin.len() != 64 || !pin.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(
            "The certificate fingerprint must be 64 hexadecimal characters (SHA-256).".into(),
        );
    }
    Ok(Some(pin))
}

/// Writes via a temporary file and rename, so a crash never leaves a
/// half-written file behind.
pub(crate) fn write_atomically(path: &Path, data: &[u8]) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, data)?;
    std::fs::rename(&tmp, path)
}

pub(crate) fn project_dirs() -> Result<directories::ProjectDirs, ConfigError> {
    directories::ProjectDirs::from("", "", "stayline").ok_or(ConfigError::NoHome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use managed::ManagedConnection;

    const PIN_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const PIN_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn company() -> ManagedConfig {
        ManagedConfig {
            allow_user_connections: true,
            allow_trust_on_first_use: true,
            connections: vec![ManagedConnection {
                name: "Company VPN".into(),
                gateway: "vpn.example.com:10443".into(),
                realm: None,
                pin: Some(PIN_A.into()),
            }],
        }
    }

    fn edit(name: &str, gateway: &str) -> ConnectionEdit {
        ConnectionEdit {
            name: name.into(),
            gateway: gateway.into(),
            username: "alice".into(),
            realm: None,
            pin: None,
        }
    }

    #[test]
    fn company_connection_takes_username_from_user_settings() {
        let mut config = Config {
            managed: company(),
            ..Default::default()
        };
        let c = &config.connections()[0];
        assert!(c.managed);
        assert_eq!(c.username, "");
        assert!(!c.is_complete());

        let mut e = edit("ignored", "evil.example.net");
        e.pin = Some(PIN_B.into());
        config.save_connection(Some("Company VPN"), e).unwrap();
        let c = &config.connections()[0];
        assert_eq!(c.username, "alice");
        // Gateway and pin stay as the company set them.
        assert_eq!(c.gateway, "vpn.example.com:10443");
        assert_eq!(c.pin.as_deref(), Some(PIN_A));
        assert_eq!(config.active().unwrap().name, "Company VPN");
    }

    #[test]
    fn company_pin_cannot_be_replaced_by_trust() {
        let mut config = Config {
            managed: company(),
            ..Default::default()
        };
        assert!(config.trust("Company VPN", PIN_B).is_err());
    }

    #[test]
    fn unpinned_company_connection_allows_first_use_trust() {
        let mut managed = company();
        managed.connections[0].pin = None;
        let mut config = Config {
            managed,
            ..Default::default()
        };
        assert!(config.connections()[0].may_trust_on_first_use);
        config.trust("Company VPN", PIN_B).unwrap();
        assert_eq!(config.connections()[0].pin.as_deref(), Some(PIN_B));

        config.managed.allow_trust_on_first_use = false;
        assert_eq!(config.connections()[0].pin, None);
        assert!(config.trust("Company VPN", PIN_B).is_err());
    }

    #[test]
    fn user_connections_can_be_added_renamed_and_removed() {
        let mut config = Config {
            managed: company(),
            ..Default::default()
        };
        config
            .save_connection(None, edit("Lab", "lab.example.com"))
            .unwrap();
        config.set_active("Lab");
        config
            .save_connection(Some("Lab"), edit("Test lab", "lab.example.com"))
            .unwrap();
        assert_eq!(config.user.active.as_deref(), Some("Test lab"));
        let names: Vec<_> = config.connections().into_iter().map(|c| c.name).collect();
        assert_eq!(names, vec!["Company VPN", "Test lab"]);

        assert!(
            config
                .save_connection(None, edit("Company VPN", "x.example.com"))
                .is_err()
        );
        assert!(
            config
                .save_connection(None, edit("Test lab", "x.example.com"))
                .is_err()
        );
        assert!(config.remove_connection("Company VPN").is_err());
        config.remove_connection("Test lab").unwrap();
        assert_eq!(config.user.active, None);
    }

    #[test]
    fn organisation_can_forbid_own_connections() {
        let mut managed = company();
        managed.allow_user_connections = false;
        let mut config = Config {
            managed,
            ..Default::default()
        };
        config.user.connections.push(UserConnection {
            name: "Home".into(),
            gateway: "home.example.org".into(),
            ..Default::default()
        });
        assert_eq!(config.connections().len(), 1);
        assert!(
            config
                .save_connection(None, edit("New", "new.example.org"))
                .is_err()
        );
    }

    #[test]
    fn validate_accepts_good_input_and_normalises_pin() {
        let pin = "AB:".repeat(31) + "AB";
        let (gw, p) = validate(" 203.0.113.10:10443 ", "alice", &pin).unwrap();
        assert_eq!(gw, "203.0.113.10:10443");
        assert_eq!(p, Some("ab".repeat(32)));
        assert_eq!(validate("vpn.example.com", "a", "").unwrap().1, None);
    }

    #[test]
    fn gateway_splits_into_address_and_port() {
        assert_eq!(
            split_gateway("vpn.example.com:10443"),
            ("vpn.example.com".into(), "10443".into())
        );
        assert_eq!(
            split_gateway("203.0.113.10"),
            ("203.0.113.10".into(), String::new())
        );
        assert_eq!(
            split_gateway("https://vpn.example.com:8443/remote/login"),
            ("vpn.example.com".into(), "8443".into())
        );
        assert_eq!(
            split_gateway("[2001:db8::1]:443"),
            ("2001:db8::1".into(), "443".into())
        );
        assert_eq!(split_gateway(""), (String::new(), String::new()));
    }

    #[test]
    fn gateway_joins_with_default_port_and_checks_input() {
        assert_eq!(
            join_gateway(" vpn.example.com ", "10443").unwrap(),
            "vpn.example.com:10443"
        );
        assert_eq!(
            join_gateway("203.0.113.10", "").unwrap(),
            "203.0.113.10:443"
        );
        assert_eq!(
            join_gateway("2001:db8::1", "443").unwrap(),
            "[2001:db8::1]:443"
        );
        assert!(join_gateway("", "443").is_err());
        assert!(join_gateway("vpn.example.com", "70000").is_err());
        assert!(join_gateway("vpn.example.com", "abc").is_err());
        assert!(join_gateway("vpn.example.com", "0").is_err());
        assert!(join_gateway("http://vpn.example.com", "").is_err());
        for stored in [
            "vpn.example.com:10443",
            "203.0.113.10:443",
            "[2001:db8::1]:443",
        ] {
            let (host, port) = split_gateway(stored);
            assert_eq!(join_gateway(&host, &port).unwrap(), stored);
        }
    }

    #[test]
    fn validate_rejects_bad_input() {
        assert!(validate("", "alice", "").is_err());
        assert!(validate("vpn example.com", "alice", "").is_err());
        assert!(validate("http://vpn.example.com", "alice", "").is_err());
        assert!(validate("vpn.example.com", " ", "").is_err());
        assert!(validate("vpn.example.com", "alice", "abcd").is_err());
        assert!(validate("vpn.example.com", "alice", &"zz".repeat(32)).is_err());
    }
}
