//! Windows networking for stayline: the Wintun adapter, its address, routes
//! and DNS. Everything here needs administrator rights.

#[cfg(windows)]
mod device;
#[cfg(windows)]
mod error;
#[cfg(windows)]
mod iphlp;
#[cfg(windows)]
mod setup;

#[cfg(windows)]
pub use device::{DeviceChannels, TunDevice};
#[cfg(windows)]
pub use error::{NetError, Result};
#[cfg(windows)]
pub use iphlp::NetworkWatcher;
#[cfg(windows)]
pub use setup::{GatewayRoute, TunnelNetwork, WindowsHooks};

/// MTU of the tunnel adapter; matches the PPP MRU we negotiate.
pub const TUNNEL_MTU: u32 = stayline_core::ppp::DEFAULT_MRU as u32;
