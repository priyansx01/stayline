//! Developer CLI for checking a FortiGate gateway before the service exists.
//!
//! ```text
//! stayline-probe cert   <gateway>
//! stayline-probe login  <gateway> --user <name> [--realm <realm>] [--pin <sha256>] [--keep-session]
//! stayline-probe tunnel <gateway> --user <name> [--realm <realm>] [--pin <sha256>]
//! ```
//!
//! The password is read from `STAYLINE_PASSWORD` or prompted for without echo.

use std::io::{self, BufRead, Write};
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use stayline_core::{
    Credentials, Error, Fingerprint, Gateway, GatewayClient, LoginOutcome, SessionCookie,
    TunnelConfig,
};
use zeroize::Zeroizing;

#[cfg(windows)]
mod tunnel;

const USAGE: &str = "\
usage:
  stayline-probe cert   <gateway>
  stayline-probe login  <gateway> --user <name> [--realm <realm>] [--pin <sha256>] [--keep-session]
  stayline-probe tunnel <gateway> --user <name> [--realm <realm>] [--pin <sha256>]

<gateway> is host, host:port or https://host:port.
The password is read from STAYLINE_PASSWORD, or prompted for.
`tunnel` needs an elevated prompt and wintun.dll next to the executable.
Set RUST_LOG=debug for request logs.";

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(io::stderr)
        .init();

    match run(std::env::args().skip(1).collect()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run(args: Vec<String>) -> Result<()> {
    let mut args = args.into_iter();
    match args.next().as_deref() {
        Some("cert") => {
            let gateway = Gateway::parse(&args.next().context(USAGE)?)?;
            cert(&gateway).await
        }
        Some("login") => login(LoginArgs::parse(args)?).await,
        #[cfg(windows)]
        Some("tunnel") => {
            let args = LoginArgs::parse(args)?;
            let creds = read_credentials(args.user, args.realm)?;
            tunnel::run(&args.gateway, args.pin, &creds).await
        }
        #[cfg(windows)]
        Some("net-selftest") => tunnel::net_selftest(args).await,
        Some("-h" | "--help" | "help") => {
            println!("{USAGE}");
            Ok(())
        }
        _ => bail!("{USAGE}"),
    }
}

async fn cert(gateway: &Gateway) -> Result<()> {
    let info = stayline_core::tls::inspect_certificate(gateway)
        .await
        .with_context(|| format!("TLS handshake with {gateway} failed"))?;
    println!("gateway      {gateway}");
    println!("sha256       {}", info.fingerprint);
    match info.public_ca_error {
        None => println!("public CA    trusted (no pin needed)"),
        Some(why) => {
            println!("public CA    not trusted: {why}");
            println!(
                "\nCheck this fingerprint with IT, then pass it as --pin {}",
                info.fingerprint
            );
        }
    }
    Ok(())
}

struct LoginArgs {
    gateway: Gateway,
    user: String,
    realm: Option<String>,
    pin: Option<Fingerprint>,
    keep_session: bool,
}

impl LoginArgs {
    fn parse(mut args: impl Iterator<Item = String>) -> Result<Self> {
        let gateway = Gateway::parse(&args.next().context(USAGE)?)?;
        let (mut user, mut realm, mut pin, mut keep_session) = (None, None, None, false);
        while let Some(flag) = args.next() {
            let mut value = || args.next().with_context(|| format!("{flag} needs a value"));
            match flag.as_str() {
                "--user" | "-u" => user = Some(value()?),
                "--realm" => realm = Some(value()?),
                "--pin" => pin = Some(value()?.parse()?),
                "--keep-session" => keep_session = true,
                other => bail!("unknown option {other}\n\n{USAGE}"),
            }
        }
        Ok(Self {
            gateway,
            user: user.context("--user is required")?,
            realm,
            pin,
            keep_session,
        })
    }
}

async fn login(args: LoginArgs) -> Result<()> {
    let keep_session = args.keep_session;
    let (client, cookie) = authenticate(args).await?;

    let result = client.tunnel_config(&cookie).await;
    if keep_session {
        println!("session      kept open on the gateway");
    } else {
        client.logout(&cookie).await;
    }
    print_config(&result?);
    Ok(())
}

/// Prompts for the password (and token code if asked) and logs in.
/// Reads the password from `STAYLINE_PASSWORD` or prompts for it.
fn read_credentials(user: String, realm: Option<String>) -> Result<Credentials> {
    let password = match std::env::var("STAYLINE_PASSWORD") {
        Ok(p) => Zeroizing::new(p),
        Err(_) => Zeroizing::new(rpassword::prompt_password(format!(
            "password for {user}: "
        ))?),
    };
    Ok(Credentials {
        username: user,
        password,
        realm,
    })
}

async fn authenticate(args: LoginArgs) -> Result<(GatewayClient, SessionCookie)> {
    let creds = read_credentials(args.user, args.realm)?;
    let client = GatewayClient::new(args.gateway, args.pin)?;

    let cookie = match client.login(&creds).await {
        Ok(LoginOutcome::LoggedIn(cookie)) => {
            println!("login        ok (password only, no MFA)");
            cookie
        }
        Ok(LoginOutcome::TokenRequired(challenge)) => {
            println!("login        password ok, token code required (MFA)");
            let prompt = challenge.message.as_deref().unwrap_or("token code");
            let code = read_line(&format!("{prompt}: "))?;
            let cookie = client.submit_token(&creds, &challenge, code.trim()).await?;
            println!("token        ok");
            cookie
        }
        Err(e @ Error::Tls(_)) | Err(e @ Error::Http(_)) => {
            return Err(e).context("could not reach the gateway; if its certificate is self-signed run `stayline-probe cert` and pass --pin");
        }
        Err(e) => return Err(e.into()),
    };
    Ok((client, cookie))
}

fn print_config(cfg: &TunnelConfig) {
    let or_unknown = |v: Option<String>| v.unwrap_or_else(|| "unknown".into());

    println!("fortios      {}", or_unknown(cfg.fortios_version.clone()));
    println!(
        "tunnel modes {}",
        if cfg.tunnel_methods.is_empty() {
            "not listed".into()
        } else {
            cfg.tunnel_methods.join(", ")
        }
    );
    println!(
        "assigned ip  {}",
        or_unknown(cfg.assigned_ip.map(|ip| ip.to_string()))
    );
    let dns: Vec<_> = cfg.dns.iter().map(ToString::to_string).collect();
    println!(
        "dns          {}",
        if dns.is_empty() {
            "none".into()
        } else {
            dns.join(", ")
        }
    );
    println!(
        "dns suffix   {}",
        cfg.dns_suffix.as_deref().unwrap_or("none")
    );
    for s in &cfg.split_dns {
        let servers: Vec<_> = s.servers.iter().map(ToString::to_string).collect();
        println!(
            "split dns    {} -> {}",
            s.domains.join(", "),
            servers.join(", ")
        );
    }
    if cfg.is_full_tunnel() {
        println!("routes       all traffic (full tunnel)");
    } else {
        for r in &cfg.routes {
            println!("route        {}/{}", r.network, r.prefix_len());
        }
    }
    let secs = |v: Option<u32>| {
        v.map(|s| format!("{s} s"))
            .unwrap_or_else(|| "unknown".into())
    };
    println!("idle timeout {}", secs(cfg.idle_timeout_secs));
    println!("auth timeout {}", secs(cfg.auth_timeout_secs));
    println!(
        "reconnect without reauth {}",
        match cfg.tunnel_connect_without_reauth {
            Some(true) => "allowed",
            Some(false) => "not allowed",
            None => "unknown",
        }
    );
    println!(
        "tunnel session timeout   {}",
        secs(cfg.tunnel_user_session_timeout_secs)
    );

    if !cfg.tunnel_methods.is_empty() && !cfg.tunnel_methods.iter().any(|m| m == "ppp") {
        println!("\nwarning: the gateway does not offer PPP tunnel mode, which stayline uses");
    }
}

fn read_line(prompt: &str) -> Result<String> {
    print!("{prompt}");
    io::stdout().flush()?;
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line)?;
    Ok(line)
}
