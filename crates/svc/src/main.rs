//! stayline Windows service.
//!
//! ```text
//! stayline-svc            run as a service (started by Windows)
//! stayline-svc run        run in the console for debugging (Ctrl+C stops)
//! stayline-svc install    register and start the service (administrator)
//! stayline-svc uninstall  stop and remove the service (administrator)
//! stayline-svc provision --name <n> --gateway <g> [--pin <sha256>] ...
//!                         set up a company connection (administrator)
//! ```

#[cfg(windows)]
mod controller;
#[cfg(windows)]
mod pipe;
#[cfg(windows)]
mod provision;
#[cfg(windows)]
mod service;

#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    match std::env::args().nth(1).as_deref() {
        None => {
            let _log = init_file_logging();
            service::dispatch()
        }
        Some("run") => {
            init_console_logging();
            let controller = controller::Controller::new();
            let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
            std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                rt.block_on(async {
                    let _ = tokio::signal::ctrl_c().await;
                });
                let _ = stop_tx.send(true);
            });
            run(controller, stop_rx)
        }
        Some("install") => service::install(),
        Some("uninstall") => service::uninstall(),
        Some("provision") => provision::provision(std::env::args().skip(2)),
        Some("unprovision") => provision::unprovision(std::env::args().skip(2)),
        Some(other) => anyhow::bail!(
            "unknown command '{other}'; use run, install, uninstall, provision or unprovision"
        ),
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("stayline-svc only runs on Windows");
}

/// Serves tray clients until `stop` becomes `true`, then disconnects.
#[cfg(windows)]
fn run(
    controller: std::sync::Arc<controller::Controller>,
    stop: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
    // One thread is plenty and keeps memory use low.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        let served = pipe::serve(controller.clone(), stop).await;
        controller.disconnect().await;
        served
    })?;
    Ok(())
}

#[cfg(windows)]
fn init_console_logging() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,stayline_core=debug".into()),
        )
        .init();
}

/// Daily log files in `%ProgramData%\stayline\logs`, kept for a week.
#[cfg(windows)]
fn init_file_logging() -> Option<tracing_appender::non_blocking::WorkerGuard> {
    let base = std::env::var_os("ProgramData")?;
    let dir = std::path::Path::new(&base).join("stayline").join("logs");
    let appender = tracing_appender::rolling::Builder::new()
        .rotation(tracing_appender::rolling::Rotation::DAILY)
        .filename_prefix("stayline-svc")
        .filename_suffix("log")
        .max_log_files(7)
        .build(dir)
        .ok()?;
    let (writer, guard) = tracing_appender::non_blocking(appender);
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_ansi(false)
        .with_writer(writer)
        .init();
    Some(guard)
}
