//! `stayline-svc provision`: sets up company connections for every user of
//! this machine. Used by the installer and by IT (needs administrator).
//!
//! ```text
//! stayline-svc provision --name <name> --gateway <host[:port]> [--pin <sha256>] [--realm <realm>]
//!                        [--no-user-connections] [--no-trust-prompt]
//! stayline-svc unprovision --name <name>
//! ```

use anyhow::{Context, Result, bail};
use stayline_config::managed::{ManagedConfig, ManagedConnection};

const USAGE: &str = "usage: stayline-svc provision --name <name> --gateway <host[:port]> [--pin <sha256>] \
                     [--realm <realm>] [--no-user-connections] [--no-trust-prompt]";

pub fn provision(mut args: impl Iterator<Item = String>) -> Result<()> {
    let (mut name, mut gateway, mut pin, mut realm) = (None, None, None, None);
    let (mut no_user_connections, mut no_trust_prompt) = (false, false);
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
            "--no-user-connections" => no_user_connections = true,
            "--no-trust-prompt" => no_trust_prompt = true,
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
    if no_user_connections {
        config.allow_user_connections = false;
    }
    if no_trust_prompt {
        config.allow_trust_on_first_use = false;
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

pub fn unprovision(mut args: impl Iterator<Item = String>) -> Result<()> {
    let name = match (args.next().as_deref(), args.next()) {
        (Some("--name"), Some(name)) => name,
        _ => bail!("usage: stayline-svc unprovision --name <name>"),
    };
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
