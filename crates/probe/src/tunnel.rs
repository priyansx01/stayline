//! `stayline-probe tunnel`: bring the tunnel up in the foreground until Ctrl+C.

use std::net::IpAddr;

use anyhow::{Context, Result, bail};
use stayline_core::ppp::PppConfig;
use stayline_core::tunnel::{self, TunnelEnd};
use stayline_core::{Fingerprint, Gateway, GatewayClient, SessionCookie};
use stayline_net::{DeviceChannels, TunDevice, TunnelNetwork};

pub async fn run(
    client: &GatewayClient,
    gateway: &Gateway,
    pin: Option<Fingerprint>,
    cookie: &SessionCookie,
) -> Result<()> {
    let result = run_inner(client, gateway, pin, cookie).await;
    client.logout(cookie).await;
    result
}

async fn run_inner(
    client: &GatewayClient,
    gateway: &Gateway,
    pin: Option<Fingerprint>,
    cookie: &SessionCookie,
) -> Result<()> {
    let cfg = client.tunnel_config(cookie).await?;
    super::print_config(&cfg);

    let (device, channels) =
        TunDevice::create("stayline").context("could not create the stayline network adapter")?;
    let DeviceChannels {
        mut from_device,
        to_device,
    } = channels;

    let stream = tunnel::connect(gateway, pin, cookie).await?;
    let gateway_ip = match stream.get_ref().0.peer_addr()?.ip() {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(_) => bail!("gateways reached over IPv6 are not supported yet"),
    };
    println!("\nconnecting tunnel to {gateway_ip} ...");

    let mut network: Option<TunnelNetwork> = None;
    let ppp = PppConfig::new(tunnel::random_magic(), cfg.assigned_ip);
    let end = tunnel::run(
        stream,
        ppp,
        &mut from_device,
        &to_device,
        |local_ip, peer_ip| {
            network = None;
            match TunnelNetwork::apply(device.luid(), local_ip, gateway_ip, &cfg) {
                Ok(net) => {
                    network = Some(net);
                    let peer = peer_ip.map_or_else(|| "unknown".into(), |ip| ip.to_string());
                    println!("tunnel up    local {local_ip}, gateway side {peer}");
                    println!("press Ctrl+C to disconnect");
                }
                Err(e) => eprintln!("error: could not configure the adapter: {e}"),
            }
        },
        async {
            let _ = tokio::signal::ctrl_c().await;
        },
    )
    .await;

    drop(network);
    drop(device);
    match end {
        TunnelEnd::Ppp(reason) => println!("tunnel down  {reason:?}"),
        TunnelEnd::Eof => println!("tunnel down  gateway closed the connection"),
        TunnelEnd::Error(e) => return Err(e).context("tunnel failed"),
    }
    Ok(())
}
