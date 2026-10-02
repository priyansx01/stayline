//! Named-pipe server for tray clients.

use std::sync::Arc;

use stayline_ipc::security::PipeSecurity;
use stayline_ipc::{Event, PIPE_NAME, Request, TunnelState, read_message, write_message};
use tokio::io::BufReader;
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use tokio::sync::{mpsc, watch};

use crate::controller::{Controller, inspect_certificate};

/// How often connected clients get traffic counters.
const STATS_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);

/// Accepts clients until `shutdown` becomes `true`.
pub async fn serve(
    controller: Arc<Controller>,
    mut shutdown: watch::Receiver<bool>,
) -> std::io::Result<()> {
    let security = PipeSecurity::new()?;
    // first_pipe_instance makes this fail if another process already owns
    // the name, so nobody can squat it to collect passwords.
    let mut server = create(&security, true)?;
    tracing::info!(pipe = PIPE_NAME, "listening");

    loop {
        tokio::select! {
            connected = server.connect() => connected?,
            _ = shutdown.wait_for(|stop| *stop) => return Ok(()),
        }
        let client = std::mem::replace(&mut server, create(&security, false)?);
        tokio::spawn(handle_client(client, controller.clone()));
    }
}

fn create(security: &PipeSecurity, first: bool) -> std::io::Result<NamedPipeServer> {
    let mut options = ServerOptions::new();
    options
        .first_pipe_instance(first)
        .reject_remote_clients(true);
    // SAFETY: the security attributes outlive the call.
    unsafe { options.create_with_security_attributes_raw(PIPE_NAME, security.as_ptr()) }
}

async fn handle_client(pipe: NamedPipeServer, controller: Arc<Controller>) {
    tracing::debug!("client connected");
    let (reader, mut writer) = tokio::io::split(pipe);
    let mut state = controller.subscribe();
    let (reply_tx, mut replies) = mpsc::unbounded_channel::<Event>();

    // Requests are read in their own task: a read cancelled half-way
    // through a line by a status update would lose the request.
    let requests = tokio::spawn({
        let controller = controller.clone();
        async move {
            let mut reader = BufReader::new(reader);
            loop {
                // Commands run in their own task so a client that goes away
                // cannot cancel one half-way through.
                let command = match read_message::<_, Request>(&mut reader).await {
                    Ok(Some(Request::Connect { profile, password })) => {
                        let controller = controller.clone();
                        tokio::spawn(async move {
                            let result = controller.connect(profile, password).await;
                            result.err().map(|reason| Event::Rejected { reason })
                        })
                    }
                    Ok(Some(Request::Disconnect)) => {
                        let controller = controller.clone();
                        tokio::spawn(async move {
                            controller.disconnect().await;
                            None
                        })
                    }
                    Ok(Some(Request::InspectCertificate { gateway })) => tokio::spawn(async move {
                        Some(Event::Certificate(inspect_certificate(gateway).await))
                    }),
                    Ok(None) => break,
                    Err(e) => {
                        tracing::debug!(error = %e, "bad message from client");
                        break;
                    }
                };
                if let Ok(Some(reply)) = command.await {
                    let _ = reply_tx.send(reply);
                }
            }
        }
    });

    let initial = state.borrow_and_update().clone();
    if write_message(&mut writer, &Event::Status(initial))
        .await
        .is_ok()
    {
        let mut stats_tick = tokio::time::interval(STATS_INTERVAL);
        loop {
            let event = tokio::select! {
                changed = state.changed() => match changed {
                    Ok(()) => Event::Status(state.borrow_and_update().clone()),
                    Err(_) => break,
                },
                _ = stats_tick.tick() => {
                    if !matches!(*state.borrow(), TunnelState::Connected { .. }) {
                        continue;
                    }
                    let (sent, received) = controller.stats();
                    Event::Stats { sent, received }
                }
                reply = replies.recv() => match reply {
                    Some(reply) => reply,
                    // The reader finished: the client went away.
                    None => break,
                },
            };
            if write_message(&mut writer, &event).await.is_err() {
                break;
            }
        }
    }
    requests.abort();
    tracing::debug!("client disconnected");
}
