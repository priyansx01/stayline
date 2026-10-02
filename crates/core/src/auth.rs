use std::fmt;

use url::form_urlencoded;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

pub(crate) const COOKIE_NAME: &str = "SVPNCOOKIE";

/// What the user types to log in.
#[derive(Clone)]
pub struct Credentials {
    pub username: String,
    pub password: Zeroizing<String>,
    pub realm: Option<String>,
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("realm", &self.realm)
            .finish()
    }
}

/// The `SVPNCOOKIE` session cookie. Kept in memory only and never logged.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionCookie(Zeroizing<String>);

impl SessionCookie {
    pub(crate) fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    /// Value for a `Cookie:` request header.
    pub fn header_value(&self) -> Zeroizing<String> {
        Zeroizing::new(format!("{COOKIE_NAME}={}", self.0.as_str()))
    }
}

impl fmt::Debug for SessionCookie {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionCookie(<redacted>)")
    }
}

/// The gateway asked for a one-time code after the password was accepted.
#[derive(Debug, Clone)]
pub struct TokenChallenge {
    /// Message from the gateway, e.g. "Please enter your token code".
    pub message: Option<String>,
    fields: Vec<(String, String)>,
}

#[derive(Debug)]
pub enum LoginOutcome {
    LoggedIn(SessionCookie),
    TokenRequired(TokenChallenge),
}

pub(crate) fn login_form(creds: &Credentials) -> Zeroizing<String> {
    Zeroizing::new(
        form_urlencoded::Serializer::new(String::new())
            .append_pair("username", &creds.username)
            .append_pair("credential", &creds.password)
            .append_pair("realm", creds.realm.as_deref().unwrap_or(""))
            .append_pair("ajax", "1")
            .append_pair("redir", "/remote/index")
            .append_pair("just_logged_in", "1")
            .finish(),
    )
}

pub(crate) fn token_form(
    creds: &Credentials,
    challenge: &TokenChallenge,
    code: &str,
) -> Zeroizing<String> {
    let mut form = form_urlencoded::Serializer::new(String::new());
    form.append_pair("username", &creds.username);
    form.append_pair("realm", creds.realm.as_deref().unwrap_or(""));
    for key in ["reqid", "polid", "grp", "portal", "peer", "magic"] {
        if let Some((_, v)) = challenge.fields.iter().find(|(k, _)| k == key) {
            form.append_pair(key, v);
        }
    }
    form.append_pair("code", code);
    form.append_pair("code2", "");
    Zeroizing::new(form.finish())
}

/// Finds a non-empty `SVPNCOOKIE` in `Set-Cookie` header values.
pub(crate) fn cookie_from_headers<'a>(
    set_cookie: impl IntoIterator<Item = &'a str>,
) -> Option<SessionCookie> {
    set_cookie.into_iter().find_map(|header| {
        let pair = header.split(';').next()?.trim();
        let (name, value) = pair.split_once('=')?;
        (name.trim() == COOKIE_NAME && !value.trim().is_empty())
            .then(|| SessionCookie::new(value.trim().to_owned()))
    })
}

/// Parses the comma-separated `key=value` body FortiOS returns from
/// `/remote/logincheck`, e.g. `ret=2,reqid=123,polid=1-1-2,...`.
fn parse_fields(body: &str) -> Vec<(String, String)> {
    body.trim()
        .split(',')
        .filter_map(|part| {
            let (k, v) = part.split_once('=')?;
            Some((k.trim().to_owned(), v.trim().to_owned()))
        })
        .collect()
}

/// Decides what a `/remote/logincheck` response means.
pub(crate) fn classify_login(
    status: u16,
    location: Option<&str>,
    cookie: Option<SessionCookie>,
    body: &str,
) -> Result<LoginOutcome> {
    if let Some(cookie) = cookie {
        return Ok(LoginOutcome::LoggedIn(cookie));
    }

    let lower_location = location.map(str::to_ascii_lowercase).unwrap_or_default();
    if lower_location.contains("saml") {
        return Err(Error::SamlRequired);
    }

    let fields = parse_fields(body);
    let get = |key: &str| {
        fields
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    };
    let lower_body = body.to_ascii_lowercase();

    if get("tokeninfo").is_some() || get("ret") == Some("2") {
        let message = get("chal_msg").filter(|m| !m.is_empty()).map(str::to_owned);
        return Ok(LoginOutcome::TokenRequired(TokenChallenge {
            message,
            fields,
        }));
    }

    const PASSWORD_CHANGE_MARKERS: [&str; 4] = [
        "pwd_expired",
        "passwd_expired",
        "password_expired",
        "chgpwd",
    ];
    if PASSWORD_CHANGE_MARKERS
        .iter()
        .any(|m| lower_body.contains(m) || lower_location.contains(m))
    {
        return Err(Error::PasswordChangeRequired);
    }

    if get("ret") == Some("0")
        || lower_body.contains("permission denied")
        || status == 401
        || status == 403
    {
        return Err(Error::BadCredentials);
    }

    Err(Error::UnexpectedLogin {
        status,
        body: body.chars().take(300).collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn creds() -> Credentials {
        Credentials {
            username: "alice@corp".into(),
            password: Zeroizing::new("p&ss=word".into()),
            realm: None,
        }
    }

    #[test]
    fn login_form_url_encodes_values() {
        let form = login_form(&creds());
        assert!(form.contains("username=alice%40corp"));
        assert!(form.contains("credential=p%26ss%3Dword"));
        assert!(form.contains("redir=%2Fremote%2Findex"));
    }

    #[test]
    fn finds_cookie_among_headers() {
        let headers = [
            "SVPNTMPCOOKIE=abc; path=/",
            "SVPNCOOKIE=XyZ123%3D%3D; path=/; secure; httponly",
        ];
        let cookie = cookie_from_headers(headers).unwrap();
        assert_eq!(cookie.header_value().as_str(), "SVPNCOOKIE=XyZ123%3D%3D");
    }

    #[test]
    fn ignores_cleared_cookie() {
        assert!(
            cookie_from_headers(["SVPNCOOKIE=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT"])
                .is_none()
        );
    }

    #[test]
    fn cookie_means_logged_in() {
        let cookie = Some(SessionCookie::new("abc".into()));
        assert!(matches!(
            classify_login(200, None, cookie, "ret=1,redir=/remote/index"),
            Ok(LoginOutcome::LoggedIn(_))
        ));
    }

    #[test]
    fn ret_zero_is_bad_credentials() {
        assert!(matches!(
            classify_login(
                200,
                None,
                None,
                "ret=0,redir=/remote/login?&err=sslvpn_login_permission_denied"
            ),
            Err(Error::BadCredentials)
        ));
    }

    #[test]
    fn token_challenge_is_detected_and_echoed_back() {
        let body = "ret=2,reqid=4242,polid=1-1-7,grp=staff,portal=full,magic=1-99,tokeninfo=,chal_msg=Enter token";
        let Ok(LoginOutcome::TokenRequired(ch)) = classify_login(200, None, None, body) else {
            panic!("expected token challenge");
        };
        assert_eq!(ch.message.as_deref(), Some("Enter token"));
        let form = token_form(&creds(), &ch, "123456");
        assert!(form.contains("reqid=4242"));
        assert!(form.contains("polid=1-1-7"));
        assert!(form.contains("magic=1-99"));
        assert!(form.contains("code=123456"));
        assert!(!form.contains("credential"));
    }

    #[test]
    fn saml_redirect_is_detected() {
        assert!(matches!(
            classify_login(302, Some("/remote/saml/start"), None, ""),
            Err(Error::SamlRequired)
        ));
    }

    #[test]
    fn expired_password_is_detected() {
        assert!(matches!(
            classify_login(
                200,
                None,
                None,
                "ret=1,redir=/remote/login?err=sslvpn_login_pwd_expired&chgpwd=1"
            ),
            Err(Error::PasswordChangeRequired)
        ));
    }

    #[test]
    fn unknown_response_keeps_body_for_diagnosis() {
        let Err(Error::UnexpectedLogin { status, body }) =
            classify_login(500, None, None, "something odd")
        else {
            panic!("expected unexpected-login error");
        };
        assert_eq!(status, 500);
        assert_eq!(body, "something odd");
    }

    #[test]
    fn secrets_are_not_in_debug_output() {
        let dbg = format!("{:?} {:?}", creds(), SessionCookie::new("topsecret".into()));
        assert!(!dbg.contains("p&ss"));
        assert!(!dbg.contains("topsecret"));
    }
}
