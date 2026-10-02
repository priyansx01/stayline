//! `stayline-svc provision`: sets up company connections for every user of
//! this machine. Used by the installer and by IT (needs administrator).
//!
//! ```text
//! stayline-svc provision --name <name> --gateway <host[:port]> [--pin <sha256>] [--realm <realm>]
//!                        [--user-connections yes|no] [--trust-prompt yes|no]
//! stayline-svc unprovision --name <name>
//! stayline-svc unprovision --all
//! ```
//!
//! Empty values (as an installer passes for properties nobody set) count
//! as not given.

use anyhow::{Context, Result, bail};
use stayline_config::managed::{ManagedConfig, ManagedConnection};

const USAGE: &str = "usage: stayline-svc provision --name <name> --gateway <host[:port]> [--pin <sha256>] \
                     [--realm <realm>] [--user-connections yes|no] [--trust-prompt yes|no]";

pub fn provision(mut args: impl Iterator<Item = String>) -> Result<()> {
    let (mut name, mut gateway, mut pin, mut realm) = (None, None, None, None);
    let (mut user_connections, mut trust_prompt) = (None, None);
    while let Some(flag) = args.next() {
        let mut value = || {
            args.next()
                .with_context(|| format!("{flag} needs a value\n{USAGE}"))
        };
        match flag.as_str() {
            "--name" => name = Some(value()?),
            "--gateway" => gateway = Some(value()?),
            "--pin" => pin = Some(value()?),
            "--realm" => realm = Some(value()?),
            "--user-connections" => user_connections = yes_no(&value()?)?,
            "--trust-prompt" => trust_prompt = yes_no(&value()?)?,
            // Older spellings.
            "--no-user-connections" => user_connections = Some(false),
            "--no-trust-prompt" => trust_prompt = Some(false),
            other => bail!("unknown option {other}\n{USAGE}"),
        }
    }
    let name = name
        .filter(|n| !n.trim().is_empty())
        .context(USAGE)?
        .trim()
        .to_owned();
    let (gateway, pin) =
        stayline_config::validate(&gateway.context(USAGE)?, "-", pin.as_deref().unwrap_or(""))
            .map_err(anyhow::Error::msg)?;

    let mut config = ManagedConfig::load()?;
    config.upsert(ManagedConnection {
        name: name.clone(),
        gateway,
        realm: realm.filter(|r| !r.trim().is_empty()),
        pin,
    });
    if let Some(allow) = user_connections {
        config.allow_user_connections = allow;
    }
    if let Some(allow) = trust_prompt {
        config.allow_trust_on_first_use = allow;
    }
    config
        .save_protected()
        .context("could not write the company settings (run as administrator)")?;
    println!(
        "connection '{name}' set up in {}",
        stayline_config::managed::path()?.display()
    );
    Ok(())
}

/// `yes`/`no` (also `1`/`0`, `true`/`false`); empty means not given.
fn yes_no(value: &str) -> Result<Option<bool>> {
    match value.trim().to_ascii_lowercase().as_str() {
        "" => Ok(None),
        "yes" | "1" | "true" => Ok(Some(true)),
        "no" | "0" | "false" => Ok(Some(false)),
        other => bail!("expected yes or no, got '{other}'"),
    }
}

pub fn unprovision(mut args: impl Iterator<Item = String>) -> Result<()> {
    let path = stayline_config::managed::path()?;
    match (args.next().as_deref(), args.next()) {
        (Some("--all"), None) => {
            match std::fs::remove_file(&path) {
                Ok(()) => println!("company settings removed"),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    println!("no company settings")
                }
                Err(e) => return Err(e).context("could not remove the company settings"),
            }
            Ok(())
        }
        (Some("--name"), Some(name)) => {
            let mut config = ManagedConfig::load()?;
            let before = config.connections.len();
            config.connections.retain(|c| c.name != name);
            if config.connections.len() == before {
                bail!("no company connection called '{name}'");
            }
            config
                .save_protected()
                .context("could not write the company settings (run as administrator)")?;
            println!("connection '{name}' removed");
            Ok(())
        }
        _ => bail!("usage: stayline-svc unprovision --name <name> | --all"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yes_no_values() {
        assert_eq!(yes_no("yes").unwrap(), Some(true));
        assert_eq!(yes_no(" NO ").unwrap(), Some(false));
        assert_eq!(yes_no("1").unwrap(), Some(true));
        assert_eq!(yes_no("").unwrap(), None);
        assert!(yes_no("maybe").is_err());
    }
}
