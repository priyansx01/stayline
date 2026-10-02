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
    Http(reqwest::Error),

    #[error("network error: {0}")]
    Io(std::io::Error),

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

    #[error(
        "the gateway's certificate changed (now {actual}, pinned {expected}); this can mean the connection is being intercepted, so check with IT before trusting it"
    )]
    CertificateChanged { expected: String, actual: String },

    #[error(
        "the gateway's certificate is not trusted ({0}); check its fingerprint with IT and pin it"
    )]
    CertificateUntrusted(String),

    #[error("tunnel protocol error: {0}")]
    Protocol(String),

    #[error("the gateway asked for a token code")]
    TokenRequired,

    #[error("{0} has no IPv4 address")]
    NoIpv4Address(String),

    #[error("network setup failed: {0}")]
    Platform(String),

    #[error("unexpected login response (HTTP {status}): {body}")]
    UnexpectedLogin { status: u16, body: String },
}

impl Error {
    /// Errors that retrying cannot fix: the user has to do something.
    /// Retrying a rejected password could also lock the account.
    pub fn needs_user(&self) -> bool {
        matches!(
            self,
            Error::BadCredentials
                | Error::BadToken
                | Error::TokenRequired
                | Error::PasswordChangeRequired
                | Error::SamlRequired
                | Error::InvalidGateway(_)
                | Error::InvalidFingerprint
                | Error::CertificateChanged { .. }
                | Error::CertificateUntrusted(_)
        )
    }
}

impl From<reqwest::Error> for Error {
    fn from(e: reqwest::Error) -> Self {
        crate::tls::certificate_error(&e).unwrap_or(Error::Http(e))
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        crate::tls::certificate_error(&e).unwrap_or(Error::Io(e))
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
