//! Named-pipe protocol between `stayline-tray` and `stayline-svc`.

/// Name of the pipe the service listens on.
pub const PIPE_NAME: &str = r"\\.\pipe\stayline";
