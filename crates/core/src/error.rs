/// Errors from talking to a FortiGate gateway.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid gateway address: {0}")]
    InvalidGateway(String),

    #[error("invalid certificate fingerprint: expected 64 hex characters (SHA-256)")]
    InvalidFingerprint,

    #[error("TLS error: {0}")]
    Tls(#[from] rustls::Error),

    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("network error: {0}")]
    Io(#[from] std::io::Error),

    #[error("username or password was rejected")]
    BadCredentials,

    #[error("the token code was rejected")]
    BadToken,

    #[error("the gateway requires a password change; change it in the web portal first")]
    PasswordChangeRequired,

    #[error("the gateway uses SAML single sign-on, which is not supported yet")]
    SamlRequired,

    #[error("the session is no longer valid")]
    SessionExpired,

    #[error(
        "the gateway returned no tunnel configuration (HTTP {status}); SSL-VPN tunnel mode may be disabled"
    )]
    ConfigUnavailable { status: u16 },

    #[error("could not parse tunnel configuration: {0}")]
    ConfigParse(String),

    #[error("unexpected login response (HTTP {status}): {body}")]
    UnexpectedLogin { status: u16, body: String },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
