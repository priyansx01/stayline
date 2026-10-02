use std::sync::Arc;
use std::thread::JoinHandle;

use bytes::Bytes;
use tokio::sync::mpsc;

use crate::error::{NetError, Result};

/// Fixed adapter GUID so Windows keeps one network profile for stayline
/// instead of creating "Network 2", "Network 3", ... on every connect.
const ADAPTER_GUID: u128 = 0x5f3c_8a1e_2b7d_4c90_9e61_7a4d_3b28_c1f6;
/// Wintun ring size. Larger rings only help at multi-gigabit rates.
const RING_CAPACITY: u32 = 0x20_0000;
const QUEUE_LEN: usize = 1024;

/// Packet channels of a [`TunDevice`].
pub struct DeviceChannels {
    /// IPv4 packets written by Windows into the adapter.
    pub from_device: mpsc::Receiver<Bytes>,
    /// Packets to hand to Windows as if they arrived on the adapter.
    pub to_device: mpsc::Sender<Bytes>,
}

/// The Wintun adapter and its packet session.
pub struct TunDevice {
    adapter: Arc<wintun::Adapter>,
    session: Arc<wintun::Session>,
    reader: Option<JoinHandle<()>>,
    writer: tokio::task::JoinHandle<()>,
}

impl TunDevice {
    /// Creates the adapter. `wintun.dll` must sit next to the executable.
    /// Must be called inside a Tokio runtime.
    pub fn create(name: &str) -> Result<(Self, DeviceChannels)> {
        let dll = std::env::current_exe()?
            .parent()
            .map(|dir| dir.join("wintun.dll"))
            .ok_or_else(|| NetError::Wintun("cannot locate executable directory".into()))?;
        // SAFETY: wintun.dll is the official signed driver library; loading it
        // from our own directory avoids picking up a planted copy elsewhere.
        let wintun =
            unsafe { wintun::load_from_path(&dll) }.map_err(|e| NetError::WintunMissing {
                path: dll.display().to_string(),
                reason: e.to_string(),
            })?;

        let adapter = wintun::Adapter::create(&wintun, name, "stayline", Some(ADAPTER_GUID))
            .map_err(|e| NetError::Wintun(e.to_string()))?;
        let session = Arc::new(
            adapter
                .start_session(RING_CAPACITY)
                .map_err(|e| NetError::Wintun(e.to_string()))?,
        );

        let (in_tx, from_device) = mpsc::channel(QUEUE_LEN);
        let reader_session = session.clone();
        let reader = std::thread::Builder::new()
            .name("wintun-rx".into())
            .spawn(move || {
                while let Ok(packet) = reader_session.receive_blocking() {
                    let bytes = packet.bytes();
                    // Only IPv4 goes through the tunnel; IPv6 is not negotiated.
                    if bytes.first().is_some_and(|b| b >> 4 == 4)
                        && in_tx.try_send(Bytes::copy_from_slice(bytes)).is_err()
                    {
                        tracing::trace!("tunnel queue full, dropping packet");
                    }
                }
            })?;

        let (to_device, mut out_rx) = mpsc::channel::<Bytes>(QUEUE_LEN);
        let writer_session = session.clone();
        let writer = tokio::spawn(async move {
            while let Some(packet) = out_rx.recv().await {
                let Ok(len) = u16::try_from(packet.len()) else {
                    continue;
                };
                match writer_session.allocate_send_packet(len) {
                    Ok(mut out) => {
                        out.bytes_mut().copy_from_slice(&packet);
                        writer_session.send_packet(out);
                    }
                    Err(e) => tracing::trace!(error = %e, "adapter ring full, dropping packet"),
                }
            }
        });

        let device = Self {
            adapter,
            session,
            reader: Some(reader),
            writer,
        };
        Ok((
            device,
            DeviceChannels {
                from_device,
                to_device,
            },
        ))
    }

    /// Interface LUID, used by the IP Helper calls.
    pub fn luid(&self) -> u64 {
        // SAFETY: NET_LUID_LH is a union whose `Value` covers all of it.
        unsafe { self.adapter.get_luid().Value }
    }
}

impl Drop for TunDevice {
    fn drop(&mut self) {
        self.writer.abort();
        if let Err(e) = self.session.shutdown() {
            tracing::warn!(error = %e, "could not stop Wintun session");
        }
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}
