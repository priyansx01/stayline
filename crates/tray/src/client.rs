//! Background thread that stays connected to the service's pipe.

use std::sync::Arc;
use std::time::Duration;

use stayline_ipc::{Event, PIPE_NAME, Request, read_message, write_message};
use tokio::io::BufReader;
use tokio::net::windows::named_pipe::ClientOptions;
use tokio::sync::mpsc;

/// What the client thread reports to the UI.
#[derive(Debug)]
pub enum FromService {
    /// Connected to the service pipe.
    Available,
    /// The service is not running (or not installed).
    Unavailable,
    Event(Event),
}

const ERROR_PIPE_BUSY: i32 = 231;
const RETRY: Duration = Duration::from_secs(2);

/// Starts the client thread. `notify` is called for every message (it must
/// wake the UI thread); requests sent on the returned channel are delivered
/// once the service is reachable.
pub fn start(
    notify: impl Fn(FromService) + Send + Sync + 'static,
) -> mpsc::UnboundedSender<Request> {
    let (tx, rx) = mpsc::unbounded_channel();
    let notify: Notify = Arc::new(notify);
    std::thread::Builder::new()
        .name("service-client".into())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tokio runtime");
            rt.block_on(run(notify, rx));
        })
        .expect("spawn service client thread");
    tx
}

type Notify = Arc<dyn Fn(FromService) + Send + Sync>;

async fn run(notify: Notify, mut requests: mpsc::UnboundedReceiver<Request>) {
    let mut reported_unavailable = false;
    loop {
        let pipe = match ClientOptions::new().open(PIPE_NAME) {
            Ok(pipe) => pipe,
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) => {
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
            Err(e) => {
                if !reported_unavailable {
                    tracing::info!(error = %e, "service not reachable");
                    notify(FromService::Unavailable);
                    reported_unavailable = true;
                }
                tokio::time::sleep(RETRY).await;
                continue;
            }
        };
        tracing::info!("connected to service");
        notify(FromService::Available);

        let (reader, mut writer) = tokio::io::split(pipe);
        // Reading in its own task: a read cancelled by select! half-way
        // through a line would lose the event.
        let mut events = tokio::spawn({
            let notify = notify.clone();
            async move {
                let mut reader = BufReader::new(reader);
                loop {
                    match read_message::<_, Event>(&mut reader).await {
                        Ok(Some(event)) => notify(FromService::Event(event)),
                        // A message this version does not understand (e.g.
                        // from a newer service): skip it, keep the link.
                        Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
                            tracing::warn!(error = %e, "ignoring unreadable message from service");
                        }
                        Ok(None) | Err(_) => break,
                    }
                }
            }
        });
        loop {
            tokio::select! {
                _ = &mut events => break,
                request = requests.recv() => match request {
                    Some(request) => {
                        if let Err(e) = write_message(&mut writer, &request).await {
                            tracing::warn!(error = %e, "could not send request");
                            break;
                        }
                    }
                    None => return,
                },
            }
        }
        events.abort();
        tracing::info!("lost connection to service");
        notify(FromService::Unavailable);
        reported_unavailable = true;
        tokio::time::sleep(RETRY).await;
    }
}
