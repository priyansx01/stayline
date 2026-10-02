//! The SSL-VPN data channel: a TLS stream carrying framed PPP.

use std::future::Future;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use zeroize::Zeroizing;

use crate::auth::SessionCookie;
use crate::error::{Error, Result};
use crate::gateway::Gateway;
use crate::ppp::{DownReason, PppConfig, PppEvent, PppSession, frame};
use crate::tls::{self, Fingerprint};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
/// Packets taken from the adapter per loop turn, so reads are not starved.
const DEVICE_BATCH: usize = 64;

pub type TunnelStream = TlsStream<TcpStream>;

/// Opens the tunnel connection: TLS to the gateway, then
/// `GET /remote/sslvpn-tunnel`. The stream carries PPP from here on.
pub async fn connect(
    gateway: &Gateway,
    pin: Option<Fingerprint>,
    cookie: &SessionCookie,
) -> Result<TunnelStream> {
    let open = async {
        let tcp = TcpStream::connect((gateway.host(), gateway.port())).await?;
        tcp.set_nodelay(true)?;
        let connector = TlsConnector::from(tls::client_config(pin)?);
        let mut stream = connector.connect(tls::server_name(gateway)?, tcp).await?;

        let request = Zeroizing::new(format!(
            "GET /remote/sslvpn-tunnel HTTP/1.1\r\nHost: sslvpn\r\nCookie: {}\r\n\r\n",
            cookie.header_value().as_str()
        ));
        stream.write_all(request.as_bytes()).await?;
        stream.flush().await?;
        Ok(stream)
    };
    tokio::time::timeout(CONNECT_TIMEOUT, open)
        .await
        .map_err(|_| Error::Io(std::io::ErrorKind::TimedOut.into()))?
}

/// Random LCP magic number.
pub fn random_magic() -> u32 {
    let mut buf = [0u8; 4];
    rustls::crypto::ring::default_provider()
        .secure_random
        .fill(&mut buf)
        .expect("system RNG available");
    u32::from_ne_bytes(buf).max(1)
}

/// Why [`run`] returned.
#[derive(Debug)]
pub enum TunnelEnd {
    /// PPP ended: closed by us, terminated by the gateway, or echoes lost.
    Ppp(DownReason),
    /// The gateway closed the connection.
    Eof,
    Error(Error),
}

/// Runs PPP over `stream` until the link ends or `shutdown` completes.
///
/// IPv4 packets from `from_device` go to the gateway once the link is up;
/// packets from the gateway go to `to_device` (dropped if it is full).
/// `on_up` is called each time IPCP completes with our and the gateway's
/// tunnel addresses; returning `false` closes the tunnel. The channels are
/// borrowed so they survive reconnects.
pub async fn run<S, F>(
    stream: S,
    ppp: PppConfig,
    from_device: &mut mpsc::Receiver<Bytes>,
    to_device: &mpsc::Sender<Bytes>,
    mut on_up: impl FnMut(Ipv4Addr, Option<Ipv4Addr>) -> bool,
    shutdown: F,
) -> TunnelEnd
where
    S: AsyncRead + AsyncWrite,
    F: Future<Output = ()>,
{
    let (mut rd, mut wr) = tokio::io::split(stream);
    let mut session = PppSession::new(ppp, Instant::now());
    let mut rbuf = BytesMut::with_capacity(64 * 1024);
    let mut wbuf = BytesMut::with_capacity(64 * 1024);
    let mut shutting_down = false;
    tokio::pin!(shutdown);

    loop {
        while let Some((protocol, data)) = session.poll_transmit() {
            frame::encode(protocol, &data, &mut wbuf);
        }
        if !wbuf.is_empty() {
            if let Err(e) = async {
                wr.write_all(&wbuf).await?;
                wr.flush().await
            }
            .await
            {
                return TunnelEnd::Error(e.into());
            }
            wbuf.clear();
        }

        while let Some(event) = session.poll_event() {
            match event {
                PppEvent::Up { local_ip, peer_ip } => {
                    if !on_up(local_ip, peer_ip) {
                        session.close(Instant::now());
                    }
                }
                PppEvent::Ip(packet) => {
                    if to_device.try_send(packet).is_err() {
                        tracing::trace!("adapter queue full, dropping packet");
                    }
                }
                PppEvent::Down(reason) => return TunnelEnd::Ppp(reason),
            }
        }

        let deadline = session.next_deadline();
        let timer = async {
            match deadline {
                Some(at) => tokio::time::sleep_until(at.into()).await,
                None => std::future::pending().await,
            }
        };

        tokio::select! {
            read = rd.read_buf(&mut rbuf) => match read {
                Ok(0) => return TunnelEnd::Eof,
                Ok(_) => loop {
                    match frame::decode(&mut rbuf) {
                        Ok(Some(f)) => session.handle(f.protocol, f.payload, Instant::now()),
                        Ok(None) => break,
                        // The gateway answers a stale cookie with an HTTP error page.
                        Err(_) if rbuf.starts_with(b"HTTP/") => return TunnelEnd::Error(Error::SessionExpired),
                        Err(e) => return TunnelEnd::Error(e),
                    }
                },
                Err(e) => return TunnelEnd::Error(e.into()),
            },
            packet = from_device.recv(), if session.is_up() => match packet {
                Some(packet) => {
                    session.send_ip(packet);
                    for _ in 1..DEVICE_BATCH {
                        match from_device.try_recv() {
                            Ok(packet) => { session.send_ip(packet); }
                            Err(_) => break,
                        }
                    }
                }
                None => session.close(Instant::now()),
            },
            () = timer => session.tick(Instant::now()),
            () = &mut shutdown, if !shutting_down => {
                shutting_down = true;
                session.close(Instant::now());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ppp::packet::{self, ConfigOption, ControlPacket};
    use crate::ppp::{PROTO_IPCP, PROTO_IPV4, PROTO_LCP};
    use tokio::io::DuplexStream;

    const OFFERED: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 5);
    const GATEWAY: Ipv4Addr = Ipv4Addr::new(169, 254, 2, 1);

    async fn send(io: &mut DuplexStream, protocol: u16, data: &[u8]) {
        let mut buf = BytesMut::new();
        frame::encode(protocol, data, &mut buf);
        io.write_all(&buf).await.unwrap();
    }

    fn conf_req(id: u8, opts: &[ConfigOption]) -> Bytes {
        ControlPacket::new(packet::CONFIGURE_REQUEST, id, packet::encode_options(opts)).encode()
    }

    /// A tiny FortiGate stand-in: acks LCP, NAKs an unspecified IPCP
    /// address with OFFERED, echoes IPv4 packets back and acks terminate.
    async fn fake_gateway(mut io: DuplexStream) {
        send(
            &mut io,
            PROTO_LCP,
            &conf_req(1, &[ConfigOption::new(5, vec![9, 9, 9, 9])]),
        )
        .await;
        let mut buf = BytesMut::new();
        let mut ipcp_started = false;
        loop {
            if io.read_buf(&mut buf).await.unwrap_or(0) == 0 {
                return;
            }
            while let Some(f) = frame::decode(&mut buf).unwrap() {
                if f.protocol == PROTO_IPV4 {
                    send(&mut io, PROTO_IPV4, &f.payload).await;
                    continue;
                }
                let pkt = ControlPacket::parse(&f.payload).unwrap();
                match (f.protocol, pkt.code) {
                    (PROTO_LCP, packet::CONFIGURE_REQUEST) => {
                        let ack = ControlPacket::new(packet::CONFIGURE_ACK, pkt.id, pkt.data);
                        send(&mut io, PROTO_LCP, &ack.encode()).await;
                    }
                    (PROTO_LCP, packet::TERMINATE_REQUEST) => {
                        let ack = ControlPacket::new(packet::TERMINATE_ACK, pkt.id, Bytes::new());
                        send(&mut io, PROTO_LCP, &ack.encode()).await;
                        return;
                    }
                    (PROTO_IPCP, packet::CONFIGURE_REQUEST) => {
                        if !ipcp_started {
                            ipcp_started = true;
                            let opt = ConfigOption::new(3, GATEWAY.octets().to_vec());
                            send(&mut io, PROTO_IPCP, &conf_req(2, &[opt])).await;
                        }
                        let opts = packet::parse_options(&pkt.data).unwrap();
                        let reply = if opts[0].data[..] == [0, 0, 0, 0] {
                            let offer = ConfigOption::new(3, OFFERED.octets().to_vec());
                            ControlPacket::new(
                                packet::CONFIGURE_NAK,
                                pkt.id,
                                packet::encode_options(&[offer]),
                            )
                        } else {
                            ControlPacket::new(packet::CONFIGURE_ACK, pkt.id, pkt.data)
                        };
                        send(&mut io, PROTO_IPCP, &reply.encode()).await;
                    }
                    _ => {}
                }
            }
        }
    }

    #[tokio::test]
    async fn negotiates_forwards_packets_and_closes() {
        let (client, server) = tokio::io::duplex(64 * 1024);
        tokio::spawn(fake_gateway(server));

        let (dev_tx, mut from_device) = mpsc::channel(16);
        let (to_device, mut dev_rx) = mpsc::channel(16);
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let (up_tx, mut up_rx) = mpsc::unbounded_channel();

        let tunnel = tokio::spawn(async move {
            run(
                client,
                PppConfig::new(0xabcd, None),
                &mut from_device,
                &to_device,
                move |local, peer| up_tx.send((local, peer)).is_ok(),
                async {
                    stop_rx.await.ok();
                },
            )
            .await
        });

        assert_eq!(up_rx.recv().await, Some((OFFERED, Some(GATEWAY))));

        let ping = Bytes::from_static(&[0x45, 0, 0, 20, 1, 2, 3, 4]);
        dev_tx.send(ping.clone()).await.unwrap();
        assert_eq!(dev_rx.recv().await, Some(ping));

        stop_tx.send(()).unwrap();
        let end = tunnel.await.unwrap();
        assert!(
            matches!(end, TunnelEnd::Ppp(DownReason::LocalClose)),
            "{end:?}"
        );
    }

    #[tokio::test]
    async fn http_error_means_session_expired() {
        let (client, mut server) = tokio::io::duplex(4096);
        server
            .write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n")
            .await
            .unwrap();
        let (_dev_tx, mut from_device) = mpsc::channel(1);
        let (to_device, _dev_rx) = mpsc::channel(1);
        let end = run(
            client,
            PppConfig::new(1, None),
            &mut from_device,
            &to_device,
            |_, _| true,
            std::future::pending(),
        )
        .await;
        assert!(
            matches!(end, TunnelEnd::Error(Error::SessionExpired)),
            "{end:?}"
        );
    }
}
