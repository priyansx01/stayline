//! Keeps the tunnel up: connects, notices drops and reconnects with
//! backoff, logging in again with the saved credentials each time.

use std::cell::Cell;
use std::net::Ipv4Addr;
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::{mpsc, watch};

use crate::auth::{Credentials, LoginOutcome};
use crate::client::GatewayClient;
use crate::config::TunnelConfig;
use crate::error::{Error, Result};
use crate::gateway::Gateway;
use crate::ppp::{DownReason, PppConfig};
use crate::tls::Fingerprint;
use crate::tunnel::{self, TunnelEnd};

/// Pause after a network change before retrying, so DHCP and routes settle.
const NETWORK_SETTLE: Duration = Duration::from_secs(1);
const LOGOUT_TIMEOUT: Duration = Duration::from_secs(3);
/// While offline, check again this often even without a change event.
const OFFLINE_RECHECK: Duration = Duration::from_secs(60);

/// Platform side of keeping a tunnel up (adapter, routes).
pub trait TunnelHooks {
    /// Makes traffic to the gateway bypass the tunnel. Called before every
    /// connection attempt, since the right path depends on the current network.
    fn route_to_gateway(&self, gateway_ip: Ipv4Addr) -> Result<(), String>;

    /// Configures the adapter once PPP is up. An error closes the tunnel.
    fn link_up(&self, local_ip: Ipv4Addr, cfg: &TunnelConfig) -> Result<(), String>;

    /// Called on network-change events while connected. `true` means the
    /// path to the gateway changed and the tunnel must be rebuilt.
    fn gateway_path_changed(&self) -> bool;

    /// Whether the machine has a usable network at all. While it has not,
    /// the supervisor waits for a network change instead of retrying.
    fn network_available(&self) -> bool;
}

/// What the supervisor is doing, for display.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    Connecting {
        attempt: u32,
    },
    Connected {
        local_ip: Ipv4Addr,
    },
    Reconnecting {
        attempt: u32,
        retry_in: Duration,
        last_error: String,
    },
    /// No network; reconnects as soon as Windows reports one.
    WaitingForNetwork,
    NeedsUser {
        reason: String,
    },
    Disconnected,
}

#[derive(Debug)]
pub enum SupervisorEnd {
    /// Shutdown was requested.
    Stopped,
    /// Retrying cannot help; the user has to act (e.g. new password).
    NeedsUser(Error),
}

/// Exponential backoff: 1 s, 2 s, 4 s, ... capped at 60 s.
#[derive(Debug, Clone)]
pub struct Backoff {
    next: Duration,
    min: Duration,
    max: Duration,
}

impl Default for Backoff {
    fn default() -> Self {
        Self::new(Duration::from_secs(1), Duration::from_secs(60))
    }
}

impl Backoff {
    pub fn new(min: Duration, max: Duration) -> Self {
        Self {
            next: min,
            min,
            max,
        }
    }

    pub fn next_delay(&mut self) -> Duration {
        let delay = self.next;
        self.next = (self.next * 2).min(self.max);
        delay
    }

    pub fn reset(&mut self) {
        self.next = self.min;
    }
}

/// Everything the supervisor needs besides the hooks.
pub struct SupervisorConfig<'a> {
    pub gateway: &'a Gateway,
    pub pin: Option<Fingerprint>,
    pub credentials: &'a Credentials,
}

/// Packet channels and event sources shared across reconnects.
pub struct SupervisorIo<'a> {
    pub from_device: &'a mut mpsc::Receiver<Bytes>,
    pub to_device: &'a mpsc::Sender<Bytes>,
    /// Fires when the machine's network changes (route changes, resume).
    pub network_changed: &'a mut mpsc::UnboundedReceiver<()>,
    pub status: &'a watch::Sender<Status>,
    /// Becomes `true` to stop. Dropping the sender also stops.
    pub shutdown: watch::Receiver<bool>,
}

/// Runs until shutdown or until the user has to step in.
pub async fn supervise(
    cfg: SupervisorConfig<'_>,
    hooks: &impl TunnelHooks,
    mut io: SupervisorIo<'_>,
) -> SupervisorEnd {
    let client = match GatewayClient::new(cfg.gateway.clone(), cfg.pin) {
        Ok(client) => client,
        Err(e) => return needs_user(io.status, e),
    };
    let mut backoff = Backoff::default();
    let mut attempt = 0;

    loop {
        attempt += 1;
        io.status.send_replace(Status::Connecting { attempt });

        let last_error = match connect_once(&client, &cfg, hooks, &mut io).await {
            Ok(Ended::Stopped) => {
                io.status.send_replace(Status::Disconnected);
                return SupervisorEnd::Stopped;
            }
            Ok(Ended::Dropped { was_up, reason }) => {
                if was_up {
                    backoff.reset();
                    attempt = 0;
                }
                reason
            }
            Err(e) if e.needs_user() => return needs_user(io.status, e),
            Err(e) => e.to_string(),
        };

        let retry_in = if hooks.network_available() {
            let retry_in = backoff.next_delay();
            tracing::warn!(error = %last_error, ?retry_in, "tunnel down, will reconnect");
            io.status.send_replace(Status::Reconnecting {
                attempt,
                retry_in,
                last_error,
            });
            retry_in
        } else {
            // Retrying without a network only grows the backoff; wait for one.
            tracing::warn!(error = %last_error, "tunnel down and no network, waiting");
            io.status.send_replace(Status::WaitingForNetwork);
            backoff.reset();
            attempt = 0;
            OFFLINE_RECHECK
        };

        tokio::select! {
            () = tokio::time::sleep(retry_in) => {}
            _ = io.shutdown.wait_for(|stop| *stop) => {
                io.status.send_replace(Status::Disconnected);
                return SupervisorEnd::Stopped;
            }
            Some(()) = io.network_changed.recv() => {
                while io.network_changed.try_recv().is_ok() {}
                tracing::info!("network changed, retrying now");
                tokio::time::sleep(NETWORK_SETTLE).await;
                backoff.reset();
            }
        }
    }
}

fn needs_user(status: &watch::Sender<Status>, error: Error) -> SupervisorEnd {
    tracing::error!(%error, "giving up until the user acts");
    status.send_replace(Status::NeedsUser {
        reason: error.to_string(),
    });
    SupervisorEnd::NeedsUser(error)
}

enum Ended {
    Stopped,
    Dropped { was_up: bool, reason: String },
}

async fn connect_once(
    client: &GatewayClient,
    cfg: &SupervisorConfig<'_>,
    hooks: &impl TunnelHooks,
    io: &mut SupervisorIo<'_>,
) -> Result<Ended> {
    let mut shutdown = io.shutdown.clone();

    let setup = async {
        let gateway_ip = tunnel::resolve(cfg.gateway).await?;
        hooks
            .route_to_gateway(gateway_ip)
            .map_err(Error::Platform)?;
        let cookie = match client.login(cfg.credentials).await? {
            LoginOutcome::LoggedIn(cookie) => cookie,
            LoginOutcome::TokenRequired(_) => return Err(Error::TokenRequired),
        };
        let tunnel_cfg = client.tunnel_config(&cookie).await?;
        let stream = tunnel::connect(gateway_ip, cfg.gateway, cfg.pin, &cookie).await?;
        Ok((cookie, tunnel_cfg, stream))
    };
    let (cookie, tunnel_cfg, stream) = tokio::select! {
        setup = setup => setup?,
        _ = shutdown.wait_for(|stop| *stop) => return Ok(Ended::Stopped),
    };

    let was_up = Cell::new(false);
    let user_stop = Cell::new(false);
    let path_changed = Cell::new(false);
    let network_changed = &mut *io.network_changed;

    let stop = async {
        let mut events_open = true;
        loop {
            tokio::select! {
                _ = shutdown.wait_for(|stop| *stop) => {
                    user_stop.set(true);
                    return;
                }
                event = network_changed.recv(), if events_open => match event {
                    None => events_open = false,
                    Some(()) => {
                        while network_changed.try_recv().is_ok() {}
                        if hooks.gateway_path_changed() {
                            tracing::info!("path to the gateway changed, rebuilding tunnel");
                            path_changed.set(true);
                            return;
                        }
                    }
                },
            }
        }
    };

    let ppp = PppConfig::new(tunnel::random_magic(), tunnel_cfg.assigned_ip);
    let end = tunnel::run(
        stream,
        ppp,
        io.from_device,
        io.to_device,
        |local_ip, _peer| match hooks.link_up(local_ip, &tunnel_cfg) {
            Ok(()) => {
                tracing::info!(%local_ip, "tunnel up");
                was_up.set(true);
                io.status.send_replace(Status::Connected { local_ip });
                true
            }
            Err(e) => {
                tracing::error!(error = %e, "could not configure the adapter");
                false
            }
        },
        stop,
    )
    .await;

    if user_stop.get() {
        let _ = tokio::time::timeout(LOGOUT_TIMEOUT, client.logout(&cookie)).await;
        return Ok(Ended::Stopped);
    }

    let reason = if path_changed.get() {
        "network changed".to_owned()
    } else {
        match end {
            TunnelEnd::Ppp(DownReason::EchoTimeout) => "gateway stopped answering".to_owned(),
            TunnelEnd::Ppp(DownReason::PeerTerminated) => "gateway ended the session".to_owned(),
            TunnelEnd::Ppp(DownReason::NegotiationFailed) => "PPP negotiation failed".to_owned(),
            TunnelEnd::Ppp(DownReason::LocalClose) => "adapter setup failed".to_owned(),
            TunnelEnd::Eof => "gateway closed the connection".to_owned(),
            TunnelEnd::Error(e) => e.to_string(),
        }
    };
    Ok(Ended::Dropped {
        was_up: was_up.get(),
        reason,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_up_to_a_minute_and_resets() {
        let mut b = Backoff::default();
        let delays: Vec<u64> = (0..9).map(|_| b.next_delay().as_secs()).collect();
        assert_eq!(delays, vec![1, 2, 4, 8, 16, 32, 60, 60, 60]);
        b.reset();
        assert_eq!(b.next_delay(), Duration::from_secs(1));
    }

    #[test]
    fn credential_problems_need_the_user() {
        assert!(Error::BadCredentials.needs_user());
        assert!(Error::TokenRequired.needs_user());
        assert!(Error::PasswordChangeRequired.needs_user());
        assert!(!Error::SessionExpired.needs_user());
        assert!(!Error::Io(std::io::ErrorKind::TimedOut.into()).needs_user());
        assert!(!Error::ConfigUnavailable { status: 503 }.needs_user());
    }
}
