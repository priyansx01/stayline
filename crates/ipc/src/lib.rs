//! Named-pipe protocol between `stayline-tray` and `stayline-svc`.
//!
//! Each message is one line of JSON. The tray sends [`Request`]s; the
//! service sends the current [`TunnelState`] when a client connects and
//! again whenever it changes.

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

#[cfg(windows)]
pub mod security;

/// Name of the pipe the service listens on.
pub const PIPE_NAME: &str = r"\\.\pipe\stayline";

/// Longest accepted message, to bound memory use per client.
pub const MAX_MESSAGE: usize = 64 * 1024;

/// Which gateway to use and as whom.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    /// `host`, `host:port` or `https://host:port`.
    pub gateway: String,
    pub username: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
    /// SHA-256 of the gateway certificate, for self-signed gateways.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pin: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Request {
    /// Connect (or reconnect with new settings) and keep the tunnel up.
    Connect {
        profile: Profile,
        password: Zeroizing<String>,
    },
    Disconnect,
    /// Fetch the gateway's certificate so the user can decide to pin it.
    InspectCertificate {
        gateway: String,
    },
}

impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Request::Connect { profile, .. } => f
                .debug_struct("Connect")
                .field("profile", profile)
                .field("password", &"<redacted>")
                .finish(),
            Request::Disconnect => f.write_str("Disconnect"),
            Request::InspectCertificate { gateway } => f
                .debug_struct("InspectCertificate")
                .field("gateway", gateway)
                .finish(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum TunnelState {
    Disconnected,
    Connecting {
        attempt: u32,
    },
    Connected {
        local_ip: String,
        /// When the tunnel came up, in seconds since the Unix epoch.
        #[serde(default)]
        since_unix: u64,
    },
    Reconnecting {
        attempt: u32,
        retry_in_secs: u64,
        last_error: String,
    },
    WaitingForNetwork,
    /// Retrying cannot help, e.g. the password was rejected.
    NeedsUser {
        reason: String,
        #[serde(default)]
        attention: Attention,
    },
}

/// What the user has to deal with when the tunnel needs them.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Attention {
    #[default]
    Other,
    /// Username or password rejected.
    Credentials,
    /// The certificate is not publicly trusted and no pin is set; the
    /// user may decide to trust it.
    CertificateUntrusted { fingerprint: Option<String> },
    /// The certificate differs from the pinned one: possibly intercepted.
    CertificateChanged { expected: String, actual: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    Status(TunnelState),
    /// A request could not be carried out.
    Rejected {
        reason: String,
    },
    /// Bytes carried by the tunnel; sent every few seconds while connected.
    Stats {
        sent: u64,
        received: u64,
    },
    /// Answer to [`Request::InspectCertificate`].
    Certificate(CertificateReport),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateReport {
    pub gateway: String,
    /// SHA-256 fingerprint, if the gateway could be reached.
    pub fingerprint: Option<String>,
    /// Whether the certificate chains to a public CA and matches the host.
    pub publicly_trusted: bool,
    /// Why it is not publicly trusted, or why it could not be fetched.
    pub problem: Option<String>,
}

/// Writes one message as a line of JSON.
pub async fn write_message<W, T>(writer: &mut W, message: &T) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let mut line = Zeroizing::new(serde_json::to_vec(message)?);
    line.push(b'\n');
    writer.write_all(&line).await?;
    writer.flush().await
}

/// Reads one message. `Ok(None)` means the other side closed the pipe.
pub async fn read_message<R, T>(reader: &mut R) -> std::io::Result<Option<T>>
where
    R: AsyncBufRead + Unpin,
    T: DeserializeOwned,
{
    let mut line = Zeroizing::new(Vec::new());
    let mut limited = reader.take(MAX_MESSAGE as u64 + 1);
    let n = limited.read_until(b'\n', &mut line).await?;
    if n == 0 {
        return Ok(None);
    }
    if line.last() != Some(&b'\n') {
        let reason = if n > MAX_MESSAGE {
            "message too long"
        } else {
            "truncated message"
        };
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, reason));
    }
    serde_json::from_slice(&line)
        .map(Some)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::BufReader;

    fn profile() -> Profile {
        Profile {
            gateway: "vpn.example.com:10443".into(),
            username: "alice".into(),
            realm: None,
            pin: Some("ab".repeat(32)),
        }
    }

    #[tokio::test]
    async fn messages_round_trip_over_a_stream() {
        let (client, server) = tokio::io::duplex(4096);
        let (_, mut client_w) = tokio::io::split(client);
        let (server_r, _) = tokio::io::split(server);
        let mut server_r = BufReader::new(server_r);

        let req = Request::Connect {
            profile: profile(),
            password: Zeroizing::new("s3cret".into()),
        };
        write_message(&mut client_w, &req).await.unwrap();
        write_message(&mut client_w, &Request::Disconnect)
            .await
            .unwrap();
        drop(client_w);

        match read_message::<_, Request>(&mut server_r).await.unwrap() {
            Some(Request::Connect {
                profile: p,
                password,
            }) => {
                assert_eq!(p, profile());
                assert_eq!(password.as_str(), "s3cret");
            }
            other => panic!("unexpected {other:?}"),
        }
        assert!(matches!(
            read_message::<_, Request>(&mut server_r).await.unwrap(),
            Some(Request::Disconnect)
        ));
        assert!(
            read_message::<_, Request>(&mut server_r)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn wire_format_is_tagged_json() {
        let json = serde_json::to_string(&Event::Status(TunnelState::Connected {
            local_ip: "10.0.0.5".into(),
            since_unix: 1_790_000_000,
        }))
        .unwrap();
        assert_eq!(
            json,
            r#"{"type":"status","state":"connected","local_ip":"10.0.0.5","since_unix":1790000000}"#
        );
    }

    #[test]
    fn needs_user_carries_attention_and_tolerates_older_services() {
        let state = TunnelState::NeedsUser {
            reason: "x".into(),
            attention: Attention::CertificateUntrusted {
                fingerprint: Some("ab".into()),
            },
        };
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(
            json,
            r#"{"state":"needs_user","reason":"x","attention":{"kind":"certificate_untrusted","fingerprint":"ab"}}"#
        );
        let old: TunnelState =
            serde_json::from_str(r#"{"state":"needs_user","reason":"x"}"#).unwrap();
        assert_eq!(
            old,
            TunnelState::NeedsUser {
                reason: "x".into(),
                attention: Attention::Other
            }
        );
    }

    #[test]
    fn password_is_not_in_debug_output() {
        let req = Request::Connect {
            profile: profile(),
            password: Zeroizing::new("s3cret".into()),
        };
        assert!(!format!("{req:?}").contains("s3cret"));
    }

    #[tokio::test]
    async fn oversized_messages_are_rejected() {
        let big = vec![b'x'; MAX_MESSAGE + 10];
        let mut reader = BufReader::new(&big[..]);
        assert!(read_message::<_, Request>(&mut reader).await.is_err());
    }
}
