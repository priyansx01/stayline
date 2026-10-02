use std::fmt;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, OtherError, RootCertStore,
    SignatureScheme,
};
use sha2::{Digest, Sha256};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::error::{Error, Result};
use crate::gateway::Gateway;

/// SHA-256 fingerprint of a certificate's DER encoding.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Fingerprint([u8; 32]);

impl Fingerprint {
    pub fn of(cert_der: &[u8]) -> Self {
        Self(Sha256::digest(cert_der).into())
    }
}

impl FromStr for Fingerprint {
    type Err = Error;

    /// Accepts plain hex or colon-separated hex, any case.
    fn from_str(s: &str) -> Result<Self> {
        let cleaned: String = s
            .chars()
            .filter(|c| *c != ':' && !c.is_whitespace())
            .collect();
        let mut out = [0u8; 32];
        hex::decode_to_slice(&cleaned, &mut out).map_err(|_| Error::InvalidFingerprint)?;
        Ok(Self(out))
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fingerprint({self})")
    }
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn webpki_verifier(provider: Arc<CryptoProvider>) -> Result<Arc<WebPkiServerVerifier>> {
    let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider)
        .build()
        .map_err(|e| Error::Tls(rustls::Error::General(e.to_string())))
}

/// Builds the TLS client configuration for a gateway.
///
/// With `pin`, only a leaf certificate with that SHA-256 fingerprint is
/// accepted and the CA chain and hostname are not checked (self-signed
/// gateways). Without it, the certificate must chain to a public CA.
pub fn client_config(pin: Option<Fingerprint>) -> Result<Arc<ClientConfig>> {
    let provider = provider();
    let verifier: Arc<dyn ServerCertVerifier> = match pin {
        Some(pin) => Arc::new(PinnedVerifier {
            pin,
            algorithms: provider.signature_verification_algorithms,
        }),
        None => webpki_verifier(provider.clone())?,
    };
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// TLS server name for a gateway host (DNS name or IP address).
pub fn server_name(gateway: &Gateway) -> Result<ServerName<'static>> {
    ServerName::try_from(gateway.host().to_owned()).map_err(|_| {
        Error::InvalidGateway(format!(
            "'{}' is not a valid TLS server name",
            gateway.host()
        ))
    })
}

/// The gateway presented a different certificate than the pinned one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PinMismatch {
    pub expected: Fingerprint,
    pub actual: Fingerprint,
}

impl fmt::Display for PinMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "certificate fingerprint {} does not match the pinned {}",
            self.actual, self.expected
        )
    }
}

impl std::error::Error for PinMismatch {}

/// Finds a certificate problem anywhere in an error chain (reqwest and
/// tokio-rustls wrap rustls errors in their own and in `io::Error`) and
/// turns it into the matching [`Error`].
pub(crate) fn certificate_error(err: &(dyn std::error::Error + 'static)) -> Option<Error> {
    let mut current = err;
    loop {
        let rustls_err = current.downcast_ref::<rustls::Error>().or_else(|| {
            current
                .downcast_ref::<std::io::Error>()
                .and_then(|io| io.get_ref())
                .and_then(|inner| inner.downcast_ref::<rustls::Error>())
        });
        if let Some(rustls::Error::InvalidCertificate(cert)) = rustls_err {
            return Some(match cert {
                CertificateError::Other(OtherError(other)) => {
                    match other.downcast_ref::<PinMismatch>() {
                        Some(m) => Error::CertificateChanged {
                            expected: m.expected.to_string(),
                            actual: m.actual.to_string(),
                        },
                        None => Error::CertificateUntrusted(other.to_string()),
                    }
                }
                other => Error::CertificateUntrusted(format!("{other:?}")),
            });
        }
        // io::Error::source() skips the wrapped error, so step into it.
        current = match current
            .downcast_ref::<std::io::Error>()
            .and_then(|io| io.get_ref())
        {
            Some(inner) => inner,
            None => current.source()?,
        };
    }
}

#[derive(Debug)]
struct PinnedVerifier {
    pin: Fingerprint,
    algorithms: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let actual = Fingerprint::of(end_entity);
        if actual == self.pin {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(CertificateError::Other(
                OtherError(Arc::new(PinMismatch {
                    expected: self.pin,
                    actual,
                })),
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

/// What the gateway presented during a TLS handshake.
#[derive(Debug, Clone)]
pub struct CertificateInfo {
    pub fingerprint: Fingerprint,
    /// `None` if the certificate chains to a public CA and matches the host,
    /// otherwise why it does not.
    pub public_ca_error: Option<String>,
}

/// Connects to the gateway and reports its certificate fingerprint without
/// sending any request. Used to find the value to pin.
pub async fn inspect_certificate(gateway: &Gateway) -> Result<CertificateInfo> {
    let provider = provider();
    let recorder = Arc::new(RecordingVerifier {
        inner: webpki_verifier(provider.clone())?,
        seen: Mutex::new(None),
    });
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(recorder.clone())
        .with_no_client_auth();

    let tcp = TcpStream::connect((gateway.host(), gateway.port())).await?;
    let connector = TlsConnector::from(Arc::new(config));
    let _ = connector.connect(server_name(gateway)?, tcp).await?;

    recorder
        .seen
        .lock()
        .expect("verifier mutex poisoned")
        .take()
        .ok_or_else(|| Error::Tls(rustls::Error::General("gateway sent no certificate".into())))
}

#[derive(Debug)]
struct RecordingVerifier {
    inner: Arc<WebPkiServerVerifier>,
    seen: Mutex<Option<CertificateInfo>>,
}

impl ServerCertVerifier for RecordingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let public_ca_error = self
            .inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
            .err()
            .map(|e| e.to_string());
        *self.seen.lock().expect("verifier mutex poisoned") = Some(CertificateInfo {
            fingerprint: Fingerprint::of(end_entity),
            public_ca_error,
        });
        // Only the certificate is wanted; the connection is dropped right after.
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEX: &str = "3f1c5e0b9a7d2c4e6f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6";

    #[test]
    fn fingerprint_round_trips_plain_hex() {
        let fp: Fingerprint = HEX.parse().unwrap();
        assert_eq!(fp.to_string(), HEX);
    }

    #[test]
    fn fingerprint_accepts_colons_and_uppercase() {
        let colon = HEX
            .as_bytes()
            .chunks(2)
            .map(|c| std::str::from_utf8(c).unwrap().to_uppercase())
            .collect::<Vec<_>>()
            .join(":");
        assert_eq!(colon.parse::<Fingerprint>().unwrap().to_string(), HEX);
    }

    #[test]
    fn fingerprint_rejects_wrong_length() {
        assert!("abcd".parse::<Fingerprint>().is_err());
    }

    #[test]
    fn pin_mismatch_is_found_through_io_wrappers() {
        let expected: Fingerprint = HEX.parse().unwrap();
        let actual: Fingerprint = "11".repeat(32).parse().unwrap();
        let tls_err = rustls::Error::InvalidCertificate(CertificateError::Other(OtherError(
            Arc::new(PinMismatch { expected, actual }),
        )));
        let wrapped = std::io::Error::other(std::io::Error::other(tls_err));
        match certificate_error(&wrapped) {
            Some(Error::CertificateChanged {
                expected: e,
                actual: a,
            }) => {
                assert_eq!(e, HEX);
                assert_eq!(a, "11".repeat(32));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn unknown_issuer_is_untrusted() {
        let wrapped = std::io::Error::other(rustls::Error::InvalidCertificate(
            CertificateError::UnknownIssuer,
        ));
        assert!(matches!(
            certificate_error(&wrapped),
            Some(Error::CertificateUntrusted(_))
        ));
        assert!(certificate_error(&std::io::Error::other("plain")).is_none());
    }

    #[test]
    fn client_config_builds_with_and_without_pin() {
        client_config(None).unwrap();
        client_config(Some(HEX.parse().unwrap())).unwrap();
    }
}
