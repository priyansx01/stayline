//! `stayline-probe tunnel`: keep the tunnel up in the foreground, reconnecting
//! after drops, until Ctrl+C.

use std::net::Ipv4Addr;
use std::time::Duration;

use anyhow::{Context, Result};
use stayline_core::supervisor::{
    self, Status, SupervisorConfig, SupervisorEnd, SupervisorIo, TunnelHooks,
};
use stayline_core::{Credentials, Fingerprint, Gateway, Route, TunnelConfig};
use stayline_net::{DeviceChannels, NetworkWatcher, TunDevice, WindowsHooks};
use tokio::sync::watch;

pub async fn run(gateway: &Gateway, pin: Option<Fingerprint>, creds: &Credentials) -> Result<()> {
    let (device, channels) =
        TunDevice::create("stayline").context("could not create the stayline network adapter")?;
    let DeviceChannels {
        mut from_device,
        to_device,
    } = channels;
    let (watcher, mut network_changed) =
        NetworkWatcher::start(device.luid()).context("could not watch for network changes")?;
    let hooks = WindowsHooks::new(device.luid());

    let (status_tx, mut status_rx) = watch::channel(Status::Disconnected);
    let printer = tokio::spawn(async move {
        while status_rx.changed().await.is_ok() {
            let status = status_rx.borrow_and_update().clone();
            print_status(&status);
        }
    });

    let (stop_tx, stop_rx) = watch::channel(false);
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        println!("disconnecting ...");
        let _ = stop_tx.send(true);
    });

    let end = supervisor::supervise(
        SupervisorConfig {
            gateway,
            pin,
            credentials: creds,
        },
        &hooks,
        SupervisorIo {
            from_device: &mut from_device,
            to_device: &to_device,
            network_changed: &mut network_changed,
            status: &status_tx,
            shutdown: stop_rx,
        },
    )
    .await;

    drop(hooks);
    drop(watcher);
    drop(device);
    printer.abort();

    match end {
        SupervisorEnd::Stopped => {
            println!("disconnected");
            Ok(())
        }
        SupervisorEnd::NeedsUser(e) => Err(e).context("stopped retrying"),
    }
}

fn print_status(status: &Status) {
    let now = time_of_day();
    match status {
        Status::Connecting { attempt } if *attempt <= 1 => println!("{now} connecting"),
        Status::Connecting { attempt } => println!("{now} connecting (attempt {attempt})"),
        Status::Connected { local_ip } => {
            println!("{now} CONNECTED as {local_ip}  (Ctrl+C to disconnect)")
        }
        Status::Reconnecting {
            retry_in,
            last_error,
            ..
        } => println!(
            "{now} down: {last_error}; retrying in {} s (or as soon as the network changes)",
            retry_in.as_secs()
        ),
        Status::WaitingForNetwork => {
            println!("{now} down: no network; reconnecting as soon as it is back")
        }
        Status::NeedsUser { reason } => println!("{now} NEEDS YOU: {reason}"),
        Status::Disconnected => {}
    }
}

/// UTC wall-clock time as HH:MM:SS, so reconnect timings can be read off.
fn time_of_day() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    format!(
        "{:02}:{:02}:{:02}Z",
        secs / 3600 % 24,
        secs / 60 % 60,
        secs % 60
    )
}

/// `stayline-probe net-selftest <gateway-ip> <local-ip> [<network/prefix>...]`:
/// creates the adapter, pins the gateway route and applies the given address
/// and routes without connecting, then removes everything again.
pub async fn net_selftest(mut args: impl Iterator<Item = String>) -> Result<()> {
    let usage = "usage: stayline-probe net-selftest <gateway-ip> <local-ip> [<network/prefix>...]";
    let gateway_ip: Ipv4Addr = args.next().context(usage)?.parse()?;
    let local_ip: Ipv4Addr = args.next().context(usage)?.parse()?;
    let mut cfg = TunnelConfig::default();
    for cidr in args {
        let (net, len) = cidr
            .split_once('/')
            .context("routes look like 10.0.0.0/24")?;
        let len: u32 = len.parse()?;
        let mask = Ipv4Addr::from(u32::MAX.checked_shl(32 - len).unwrap_or(0));
        cfg.routes.push(Route {
            network: net.parse()?,
            mask,
        });
    }

    println!("creating adapter ...");
    let (device, _channels) =
        TunDevice::create("stayline").context("could not create the stayline network adapter")?;
    println!("adapter ok, luid {:#x}", device.luid());

    let hooks = WindowsHooks::new(device.luid());
    hooks
        .route_to_gateway(gateway_ip)
        .map_err(anyhow::Error::msg)
        .context("could not pin the gateway route")?;
    println!("gateway route pinned");
    hooks
        .link_up(local_ip, &cfg)
        .map_err(anyhow::Error::msg)
        .context("could not configure the adapter")?;
    println!("address and {} routes applied", cfg.routes.len());
    println!("path changed? {}", hooks.gateway_path_changed());

    tokio::time::sleep(Duration::from_secs(3)).await;
    drop(hooks);
    drop(device);
    println!("removed again");
    Ok(())
}
