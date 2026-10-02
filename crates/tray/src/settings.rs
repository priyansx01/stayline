//! `settings.toml` in the user's config directory.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use stayline_ipc::Profile;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub gateway: String,
    pub username: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
    /// SHA-256 of a self-signed gateway certificate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pin: Option<String>,
    /// Connect when the tray app starts (at login), if a password is saved.
    pub auto_connect: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            gateway: String::new(),
            username: String::new(),
            realm: None,
            pin: None,
            auto_connect: true,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SettingsError {
    #[error("no user profile directory")]
    NoHome,
    #[error("could not read or write settings: {0}")]
    Io(#[from] std::io::Error),
    #[error("settings file is invalid: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("could not encode settings: {0}")]
    Encode(#[from] toml::ser::Error),
}

impl Settings {
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

    /// Loads the settings; missing file means defaults.
    pub fn load() -> Result<Self, SettingsError> {
        match std::fs::read_to_string(path()?) {
            Ok(text) => Ok(toml::from_str(&text)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e.into()),
        }
    }

    pub fn save(&self) -> Result<(), SettingsError> {
        let path = path()?;
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        write_atomically(&path, toml::to_string_pretty(self)?.as_bytes())?;
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
    let pin: String = pin
        .chars()
        .filter(|c| *c != ':' && !c.is_whitespace())
        .collect::<String>()
        .to_ascii_lowercase();
    if pin.is_empty() {
        return Ok((gateway.to_owned(), None));
    }
    if pin.len() != 64 || !pin.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(
            "The certificate fingerprint must be 64 hexadecimal characters (SHA-256).".into(),
        );
    }
    Ok((gateway.to_owned(), Some(pin)))
}

pub fn path() -> Result<PathBuf, SettingsError> {
    let dirs = directories::ProjectDirs::from("", "", "stayline").ok_or(SettingsError::NoHome)?;
    Ok(dirs.config_dir().join("settings.toml"))
}

/// Writes via a temporary file and rename, so a crash never leaves a
/// half-written file behind.
pub(crate) fn write_atomically(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, data)?;
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_toml() {
        let s = Settings {
            gateway: "203.0.113.10:10443".into(),
            username: "alice".into(),
            realm: None,
            pin: Some("ab".repeat(32)),
            auto_connect: false,
        };
        let text = toml::to_string_pretty(&s).unwrap();
        assert!(!text.contains("realm"));
        assert_eq!(toml::from_str::<Settings>(&text).unwrap(), s);
    }

    #[test]
    fn missing_fields_take_defaults() {
        let s: Settings = toml::from_str("gateway = \"vpn.example.com\"").unwrap();
        assert_eq!(s.gateway, "vpn.example.com");
        assert!(s.auto_connect);
        assert!(!s.is_complete());
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
    fn validate_rejects_bad_input() {
        assert!(validate("", "alice", "").is_err());
        assert!(validate("vpn example.com", "alice", "").is_err());
        assert!(validate("http://vpn.example.com", "alice", "").is_err());
        assert!(validate("vpn.example.com", " ", "").is_err());
        assert!(validate("vpn.example.com", "alice", "abcd").is_err());
        assert!(validate("vpn.example.com", "alice", &"zz".repeat(32)).is_err());
    }

    #[test]
    fn profile_drops_blank_optionals() {
        let s = Settings {
            gateway: " vpn.example.com ".into(),
            username: "bob".into(),
            realm: Some(" ".into()),
            pin: Some(String::new()),
            auto_connect: true,
        };
        let p = s.profile();
        assert_eq!(p.gateway, "vpn.example.com");
        assert_eq!(p.realm, None);
        assert_eq!(p.pin, None);
    }
}
