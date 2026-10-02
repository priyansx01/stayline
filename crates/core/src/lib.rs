//! FortiGate SSL-VPN client core.
//!
//! Login, tunnel configuration, PPP framing and the reconnect state machine.
//! Contains no Windows-specific code so it can be tested on any platform.

pub mod auth;
pub mod client;
pub mod config;
pub mod error;
pub mod gateway;
pub mod tls;

pub use auth::{Credentials, LoginOutcome, SessionCookie, TokenChallenge};
pub use client::GatewayClient;
pub use config::{Route, SplitDns, TunnelConfig};
pub use error::{Error, Result};
pub use gateway::Gateway;
pub use tls::{CertificateInfo, Fingerprint};
