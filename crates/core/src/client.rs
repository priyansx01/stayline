use std::time::Duration;

use reqwest::header::{CONTENT_TYPE, COOKIE, HeaderValue, LOCATION, SET_COOKIE};
use reqwest::{Client, Response, StatusCode, redirect};

use crate::auth::{self, Credentials, LoginOutcome, SessionCookie, TokenChallenge};
use crate::config::TunnelConfig;
use crate::error::{Error, Result};
use crate::gateway::Gateway;
use crate::tls::{self, Fingerprint};

/// FortiGates drop `/remote/logincheck` requests from unknown user agents
/// without a reply; this is the one openfortivpn uses.
const USER_AGENT: &str = "Mozilla/5.0 SV1";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

/// HTTP side of the FortiGate SSL-VPN protocol: login, token code, tunnel
/// configuration and logout.
#[derive(Debug, Clone)]
pub struct GatewayClient {
    gateway: Gateway,
    http: Client,
}

impl GatewayClient {
    pub fn new(gateway: Gateway, pin: Option<Fingerprint>) -> Result<Self> {
        let tls = tls::client_config(pin)?;
        let http = Client::builder()
            .tls_backend_preconfigured((*tls).clone())
            .http1_only()
            .redirect(redirect::Policy::none())
            .user_agent(USER_AGENT)
            .connect_timeout(REQUEST_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .build()?;
        Ok(Self { gateway, http })
    }

    pub fn gateway(&self) -> &Gateway {
        &self.gateway
    }

    /// Logs in with username and password.
    pub async fn login(&self, creds: &Credentials) -> Result<LoginOutcome> {
        self.post_logincheck(auth::login_form(creds).as_str()).await
    }

    /// Answers a token-code challenge returned by [`login`](Self::login).
    pub async fn submit_token(
        &self,
        creds: &Credentials,
        challenge: &TokenChallenge,
        code: &str,
    ) -> Result<SessionCookie> {
        match self
            .post_logincheck(auth::token_form(creds, challenge, code).as_str())
            .await
        {
            Ok(LoginOutcome::LoggedIn(cookie)) => Ok(cookie),
            Ok(LoginOutcome::TokenRequired(_)) | Err(Error::BadCredentials) => Err(Error::BadToken),
            Err(e) => Err(e),
        }
    }

    async fn post_logincheck(&self, form: &str) -> Result<LoginOutcome> {
        let resp = self
            .http
            .post(self.gateway.url("/remote/logincheck"))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(form.to_owned())
            .send()
            .await?;

        let status = resp.status().as_u16();
        let location = header_str(&resp, LOCATION);
        let cookie = auth::cookie_from_headers(
            resp.headers()
                .get_all(SET_COOKIE)
                .iter()
                .filter_map(|v| v.to_str().ok()),
        );
        let body = resp.text().await.unwrap_or_default();
        auth::classify_login(status, location.as_deref(), cookie, &body)
    }

    /// Fetches the tunnel configuration. Also serves as a cheap check that a
    /// session cookie is still accepted.
    pub async fn tunnel_config(&self, cookie: &SessionCookie) -> Result<TunnelConfig> {
        // Newer FortiOS allocates the tunnel on this request; older ones 404 it.
        let warmup = self.get("/remote/fortisslvpn", cookie).await?;
        ensure_session(&warmup)?;

        let resp = self.get("/remote/fortisslvpn_xml", cookie).await?;
        ensure_session(&resp)?;
        let status = resp.status();
        if !status.is_success() {
            return Err(Error::ConfigUnavailable {
                status: status.as_u16(),
            });
        }
        let body = resp.text().await?;
        TunnelConfig::parse(&body).map_err(|e| match e {
            Error::ConfigParse(_)
                if body.trim_start().starts_with("<html") || body.contains("logincheck") =>
            {
                Error::SessionExpired
            }
            other => other,
        })
    }

    /// Ends the session on the gateway. Errors are not interesting to callers.
    pub async fn logout(&self, cookie: &SessionCookie) {
        if let Err(e) = self.get("/remote/logout", cookie).await {
            tracing::debug!(error = %e, "logout request failed");
        }
    }

    async fn get(&self, path: &str, cookie: &SessionCookie) -> Result<Response> {
        let mut value = HeaderValue::from_str(cookie.header_value().as_str())
            .map_err(|_| Error::SessionExpired)?;
        value.set_sensitive(true);
        Ok(self
            .http
            .get(self.gateway.url(path))
            .header(COOKIE, value)
            .send()
            .await?)
    }
}

fn header_str(resp: &Response, name: reqwest::header::HeaderName) -> Option<String> {
    resp.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
}

/// A rejected cookie shows up as 401/403 or a redirect to the login page.
fn ensure_session(resp: &Response) -> Result<()> {
    let status = resp.status();
    if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
        return Err(Error::SessionExpired);
    }
    if status.is_redirection()
        && header_str(resp, LOCATION)
            .is_some_and(|l| l.contains("/remote/login") || l.contains("/remote/saml"))
    {
        return Err(Error::SessionExpired);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reqwest_accepts_our_rustls_config() {
        let gw = Gateway::parse("vpn.example.com:10443").unwrap();
        GatewayClient::new(gw.clone(), None).unwrap();
        let pin = "00".repeat(32).parse().unwrap();
        GatewayClient::new(gw, Some(pin)).unwrap();
    }
}
