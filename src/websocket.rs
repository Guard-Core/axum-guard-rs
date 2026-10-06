//! The WebSocket guard, ported from fastapi-guard `guard/websocket.py`
//! (`guard_websocket` / `_run_websocket_checks`): the guard checks an
//! upgrade request must pass before the handshake completes, mapped onto the
//! reference's close shapes.
//!
//! axum exposes no pre-accept WebSocket close frame: the upgrade request
//! arrives as a plain request the layer chain sees before the `101 Switching
//! Protocols` is ever rendered (axum's `WebSocketUpgrade` extractor completes
//! the handshake inside the handler), so a blocked handshake answers like the
//! Go sibling's net/http translation - a `403 Forbidden` pre-accept rejection
//! carrying the close shape on dedicated headers ([`WS_CLOSE_CODE_HEADER`] /
//! [`WS_CLOSE_REASON_HEADER`]). Starlette's `WebSocketException(code,
//! reason)` denial is the reference shape being translated.
//!
//! The check sequence is the reference's:
//!
//! 1. an undeterminable client address fails the handshake closed under
//!    `fail_secure` ([`WS_CLOSE_CLIENT_ADDRESS_UNKNOWN`]);
//! 2. a live IP ban ([`WS_CLOSE_IP_BANNED`]);
//! 3. `is_ip_allowed`: the global IP gate lists and the country rules
//!    ([`WS_CLOSE_IP_NOT_ALLOWED`]; a whitelist match skips the countries);
//! 4. the rate limit over the `ws` endpoint ([`WS_CLOSE_RATE_LIMIT_EXCEEDED`];
//!    skipped for whitelisted IPs, exactly like the reference's
//!    `not config.whitelist` gate);
//! 5. penetration detection over the path, query, and header views - an
//!    upgrade carries no body ([`WS_CLOSE_SUSPICIOUS_ACTIVITY`]).
//!
//! The close codes are the reference's: every policy denial is
//! [`WS_1008_POLICY_VIOLATION`], an engine malfunction is
//! [`WS_1013_TRY_AGAIN_LATER`] ([`WS_CLOSE_SECURITY_CHECK_FAILED`]). The
//! engine primitives the sequence runs on are infallible, so the 1013 shape
//! is reachable through exactly the reference's remaining arm: the check
//! machinery panicking mid-handshake, which [`WebSocketGuardLayer`]
//! contains.
//!
//! The client IP resolves through the [`GuardClientIp`] extension
//! (`client_ip_layer` copies it from `ConnectInfo<SocketAddr>`) and falls
//! back to `ConnectInfo<SocketAddr>` itself: serve the router with
//! `into_make_service_with_connect_info::<SocketAddr>()` for either to be
//! present. Non-upgrade requests pass through untouched (the
//! [`GuardLayer`](tower_guard_rs::GuardLayer) domain).

use axum::body::Body;
use axum::extract::{ConnectInfo, Request};
use axum::http::{StatusCode, header::HeaderName, header::HeaderValue};
use axum::response::Response;
use guard_core_engine::detect::DetectConfig;
use guard_core_engine::detection_exclusions::{
    DetectionExclusionConfig, RequestSurfaces, ResolvedExclusions, resolve as resolve_exclusions,
    scan_request,
};
use guard_core_engine::geo::{CountryGate, GeoIpHandler, check_countries};
use guard_core_engine::ip_ban::IpBanManager;
use guard_core_engine::ip_gate::{IpGateConfig, IpGateVerdict};
use guard_core_engine::rate_limit::RateLimiter;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tower::Layer;
use tower_guard_rs::GuardClientIp;

/// `WS_1008_POLICY_VIOLATION`: every policy denial's close code.
pub const WS_1008_POLICY_VIOLATION: u16 = 1008;

/// `WS_1013_TRY_AGAIN_LATER`: the engine-malfunction close code.
pub const WS_1013_TRY_AGAIN_LATER: u16 = 1013;

/// One of the reference's close shapes (the `WS_CLOSE_*` table).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WebSocketCloseReason {
    /// The WebSocket close code.
    pub code: u16,
    /// The close reason phrase.
    pub reason: &'static str,
}

/// `IP banned` - a live ban on the client IP.
pub const WS_CLOSE_IP_BANNED: WebSocketCloseReason = WebSocketCloseReason {
    code: WS_1008_POLICY_VIOLATION,
    reason: "IP banned",
};

/// `IP not allowed` - the `is_ip_allowed` family: gate lists, country rules.
pub const WS_CLOSE_IP_NOT_ALLOWED: WebSocketCloseReason = WebSocketCloseReason {
    code: WS_1008_POLICY_VIOLATION,
    reason: "IP not allowed",
};

/// `Rate limit exceeded` - the `ws` endpoint window crossed.
pub const WS_CLOSE_RATE_LIMIT_EXCEEDED: WebSocketCloseReason = WebSocketCloseReason {
    code: WS_1008_POLICY_VIOLATION,
    reason: "Rate limit exceeded",
};

/// `Client address could not be determined` - the fail-secure unknown
/// address denial.
pub const WS_CLOSE_CLIENT_ADDRESS_UNKNOWN: WebSocketCloseReason = WebSocketCloseReason {
    code: WS_1008_POLICY_VIOLATION,
    reason: "Client address could not be determined",
};

/// `Security check failed` - the engine-malfunction denial, try again later.
pub const WS_CLOSE_SECURITY_CHECK_FAILED: WebSocketCloseReason = WebSocketCloseReason {
    code: WS_1013_TRY_AGAIN_LATER,
    reason: "Security check failed",
};

/// `Suspicious activity detected` - a scanned view produced a threat.
pub const WS_CLOSE_SUSPICIOUS_ACTIVITY: WebSocketCloseReason = WebSocketCloseReason {
    code: WS_1008_POLICY_VIOLATION,
    reason: "Suspicious activity detected",
};

/// The response header carrying the close code on a rejected handshake.
pub const WS_CLOSE_CODE_HEADER: &str = "x-guard-websocket-close";

/// The response header carrying the close reason on a rejected handshake.
pub const WS_CLOSE_REASON_HEADER: &str = "x-guard-websocket-close-reason";

/// Whether the request is a WebSocket upgrade: an `Upgrade: websocket`
/// header plus an `upgrade` token in `Connection` (the token list may carry
/// other connections, e.g. `keep-alive, Upgrade`).
#[must_use]
pub fn is_websocket_upgrade<B>(request: &axum::http::Request<B>) -> bool {
    let upgrade_ok = request
        .headers()
        .get("Upgrade")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("websocket"));
    if !upgrade_ok {
        return false;
    }
    request
        .headers()
        .get("Connection")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
        })
}

/// Map a generic block answer onto the reference's close shapes - the
/// mapping the HTTP guard's domain uses when it renders a rejected
/// handshake for a verdict produced outside this module: `1013` for the
/// fail-secure 500, the rate-limit close for 429, the ban close for a
/// banned body, the suspicious close for a detection block, and everything
/// else the IP-not-allowed close (the `is_ip_allowed` family).
#[must_use]
pub fn websocket_close_for_status(status: u16, body: &str) -> WebSocketCloseReason {
    if status == StatusCode::INTERNAL_SERVER_ERROR.as_u16() {
        return WS_CLOSE_SECURITY_CHECK_FAILED;
    }
    if status == StatusCode::TOO_MANY_REQUESTS.as_u16() {
        return WS_CLOSE_RATE_LIMIT_EXCEEDED;
    }
    let lowered = body.to_ascii_lowercase();
    if lowered.contains("banned") {
        return WS_CLOSE_IP_BANNED;
    }
    if lowered.contains("suspicious") {
        return WS_CLOSE_SUSPICIOUS_ACTIVITY;
    }
    WS_CLOSE_IP_NOT_ALLOWED
}

/// The handles the upgrade check sequence runs on. Every handle is optional:
/// an absent handle skips its arm, and the sequence stays infallible (the
/// engine's ban, gate, limiter, and scan primitives report through plain
/// values, so the reference's Redis failure branches have no counterpart
/// here).
#[derive(Clone)]
pub struct WebSocketGuardConfig {
    detect_config: DetectConfig,
    ip_gate: Option<IpGateConfig>,
    ban_manager: Option<IpBanManager>,
    rate_limiter: Option<RateLimiter>,
    country_rules: Option<(CountryGate, Arc<dyn GeoIpHandler>)>,
    fail_secure: bool,
    exclusions: ResolvedExclusions,
}

/// Manual [`core::fmt::Debug`]: the geo handler is a trait object without
/// `Debug`, so the config prints its shape and stops
/// (`finish_non_exhaustive`), the family's `BanState` convention.
impl core::fmt::Debug for WebSocketGuardConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WebSocketGuardConfig")
            .field("detect_config", &self.detect_config)
            .field("ip_gate", &self.ip_gate)
            .field("ban_manager", &self.ban_manager)
            .field("rate_limiter", &self.rate_limiter)
            .field("fail_secure", &self.fail_secure)
            .field("exclusions", &self.exclusions)
            .finish_non_exhaustive()
    }
}

impl WebSocketGuardConfig {
    /// A config with no handles: only the penetration scan runs, and an
    /// unattributable upgrade passes (fail-open, the reference default).
    #[must_use]
    pub fn new(detect_config: DetectConfig) -> Self {
        Self {
            detect_config,
            ip_gate: None,
            ban_manager: None,
            rate_limiter: None,
            country_rules: None,
            fail_secure: false,
            exclusions: resolve_exclusions(None, None),
        }
    }

    /// Install the global IP gate (`whitelist`/`blacklist`/`exempt_ips`)
    /// the `is_ip_allowed` list arms evaluate.
    #[must_use]
    pub fn with_ip_gate(mut self, ip_gate: IpGateConfig) -> Self {
        self.ip_gate = Some(ip_gate);
        self
    }

    /// Install the ban manager the `is_ip_banned` arm consults.
    #[must_use]
    pub fn with_ip_banning(mut self, ban_manager: IpBanManager) -> Self {
        self.ban_manager = Some(ban_manager);
        self
    }

    /// Install the rate limiter the `check_rate_limit_by_ip` arm records
    /// through (the `ws` endpoint key, the reference's `endpoint_path`).
    #[must_use]
    pub fn with_rate_limiting(mut self, rate_limiter: RateLimiter) -> Self {
        self.rate_limiter = Some(rate_limiter);
        self
    }

    /// Install the country rules (`whitelist_countries`/`blocked_countries`
    /// resolved through [`parse_country_lists`](guard_core_engine::geo::parse_country_lists))
    /// and the [`GeoIpHandler`] they resolve countries through.
    #[must_use]
    pub fn with_country_rules(mut self, gate: CountryGate, handler: Arc<dyn GeoIpHandler>) -> Self {
        self.country_rules = Some((gate, handler));
        self
    }

    /// Fail the handshake closed when the client address cannot be
    /// determined (the reference `fail_secure` arm).
    #[must_use]
    pub const fn with_fail_secure(mut self, fail_secure: bool) -> Self {
        self.fail_secure = fail_secure;
        self
    }

    /// Install global detection exclusions for the scan arm (the header set
    /// merges over the engine defaults; every other surface overrides).
    #[must_use]
    pub fn with_detection_exclusions(
        mut self,
        detection_exclusions: &DetectionExclusionConfig,
    ) -> Self {
        self.exclusions = resolve_exclusions(Some(detection_exclusions), None);
        self
    }
}

/// The upgrade request's scan inputs, extracted as owned strings so the
/// check sequence runs on plain data (and can be contained on panic).
#[derive(Debug, Clone, Default)]
struct WebSocketRequestParts {
    client_ip: Option<IpAddr>,
    url_path: String,
    query_params: Vec<(String, String)>,
    headers: Vec<(String, String)>,
}

impl WebSocketRequestParts {
    fn extract(request: &Request) -> Self {
        let client_ip = request
            .extensions()
            .get::<GuardClientIp>()
            .map(|GuardClientIp(ip)| *ip)
            .or_else(|| {
                request
                    .extensions()
                    .get::<ConnectInfo<SocketAddr>>()
                    .map(|ConnectInfo(peer)| peer.ip())
            });
        Self {
            client_ip,
            url_path: request.uri().path().to_owned(),
            query_params: parse_query_pairs(request.uri().query().unwrap_or_default()),
            headers: request
                .headers()
                .iter()
                .filter_map(|(name, value)| {
                    value
                        .to_str()
                        .ok()
                        .map(|value| (name.as_str().to_owned(), value.to_owned()))
                })
                .collect(),
        }
    }
}

/// The `parse_qsl`-decoded query pairs (`+` is a space, percent escapes
/// decode, a malformed escape stays literal): the family's query surface.
fn parse_query_pairs(raw_query: &str) -> Vec<(String, String)> {
    if raw_query.is_empty() {
        return Vec::new();
    }
    raw_query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| match pair.split_once('=') {
            Some((name, value)) => (decode_component(name), decode_component(value)),
            None => (decode_component(pair), String::new()),
        })
        .collect()
}

fn decode_component(component: &str) -> String {
    let bytes = component.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            b'%' if bytes.len() >= index + 3 => {
                let high = (bytes[index + 1] as char).to_digit(16);
                let low = (bytes[index + 2] as char).to_digit(16);
                if let (Some(high), Some(low)) = (high, low) {
                    out.push(u8::try_from(high * 16 + low).expect("hex pair"));
                    index += 3;
                } else {
                    out.push(b'%');
                    index += 1;
                }
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The reference check sequence (`_run_websocket_checks`): ban arm, the
/// `is_ip_allowed` family, the `ws` rate limit, then the penetration scan
/// over path, query, and headers (an upgrade carries no body).
///
/// # Errors
///
/// The close shape the handshake must be rejected with. Unattributable
/// requests (`client_ip` absent) skip the stateful arms - there is no
/// identity to ban, gate, or limit - and stay detection-screened; under
/// [`WebSocketGuardConfig::with_fail_secure`] they are rejected outright.
pub fn run_websocket_checks(
    config: &WebSocketGuardConfig,
    client_ip: Option<IpAddr>,
    url_path: &str,
    query_params: &[(String, String)],
    headers: &[(String, String)],
) -> Result<(), WebSocketCloseReason> {
    if client_ip.is_none() && config.fail_secure {
        return Err(WS_CLOSE_CLIENT_ADDRESS_UNKNOWN);
    }

    if let (Some(manager), Some(ip)) = (&config.ban_manager, client_ip)
        && manager.is_banned(ip)
    {
        return Err(WS_CLOSE_IP_BANNED);
    }

    let mut whitelisted = false;
    if let (Some(gate), Some(ip)) = (&config.ip_gate, client_ip) {
        match gate.evaluate(ip) {
            IpGateVerdict::Denied(_) => return Err(WS_CLOSE_IP_NOT_ALLOWED),
            IpGateVerdict::Allowed(decision) => whitelisted = decision.is_whitelisted,
        }
    }

    if let (Some((gate, handler)), Some(ip)) = (&config.country_rules, client_ip)
        && check_countries(ip, gate, handler.as_ref(), whitelisted).is_some()
    {
        return Err(WS_CLOSE_IP_NOT_ALLOWED);
    }

    if let (Some(limiter), Some(ip)) = (&config.rate_limiter, client_ip)
        && !whitelisted
        && !limiter.check(ip, Some("ws")).allowed
    {
        return Err(WS_CLOSE_RATE_LIMIT_EXCEEDED);
    }

    let surfaces = RequestSurfaces {
        url_path: Some(url_path),
        query_params,
        headers,
        content_type: "",
        raw_body: "",
    };
    let verdict = scan_request(&surfaces, &config.exclusions, &config.detect_config);
    if verdict.is_threat {
        return Err(WS_CLOSE_SUSPICIOUS_ACTIVITY);
    }
    Ok(())
}

/// [`run_websocket_checks`] contained: a panic anywhere in the sequence
/// (an injected [`GeoIpHandler`], a foreign handle) maps to the reference's
/// engine-malfunction close shape, `1013 Try again later`.
fn run_checks_guarded(
    config: &WebSocketGuardConfig,
    parts: &WebSocketRequestParts,
) -> Result<(), WebSocketCloseReason> {
    catch_unwind(AssertUnwindSafe(|| {
        run_websocket_checks(
            config,
            parts.client_ip,
            &parts.url_path,
            &parts.query_params,
            &parts.headers,
        )
    }))
    .unwrap_or(Err(WS_CLOSE_SECURITY_CHECK_FAILED))
}

/// The rejected handshake answer: `403 Forbidden` (pre-accept) carrying the
/// close shape on [`WS_CLOSE_CODE_HEADER`] / [`WS_CLOSE_REASON_HEADER`],
/// with the family's plain-text body naming the reason. The response is
/// rendered fresh per rejection.
#[must_use = "render the close response into the handshake answer"]
pub fn close_response(reason: WebSocketCloseReason) -> Response {
    let code = HeaderValue::from_str(&reason.code.to_string()).expect("numeric header value");
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header(HeaderName::from_static(WS_CLOSE_CODE_HEADER), code)
        .header(
            HeaderName::from_static(WS_CLOSE_REASON_HEADER),
            HeaderValue::from_static(reason.reason),
        )
        .header(
            axum::http::header::CONTENT_TYPE,
            "text/plain; charset=utf-8",
        )
        .body(Body::from(format!(
            "WebSocket connection rejected: {}",
            reason.reason
        )))
        .expect("static close response parts")
}

/// The WebSocket upgrade guard as a [`tower::Layer`]: upgrade requests run
/// the reference check sequence before the inner service (and the axum
/// handler's `WebSocketUpgrade` extractor) ever see them; non-upgrade
/// requests pass through untouched.
///
/// Mount it on the application's WebSocket routes (or the whole router),
/// next to the HTTP [`GuardLayer`](tower_guard_rs::GuardLayer):
///
/// ```
/// use axum::Router;
/// use axum_guard_rs::{default_config, websocket::WebSocketGuard, websocket::WebSocketGuardConfig};
///
/// let app: Router = Router::new().layer(WebSocketGuard::new(WebSocketGuardConfig::new(
///     default_config(),
/// )));
/// # let _ = app;
/// ```
#[derive(Debug, Clone)]
pub struct WebSocketGuard {
    config: Arc<WebSocketGuardConfig>,
}

impl WebSocketGuard {
    /// Build the guard from its handles.
    #[must_use]
    pub fn new(config: WebSocketGuardConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }
}

impl<S> Layer<S> for WebSocketGuard {
    type Service = WebSocketGuardService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        WebSocketGuardService {
            inner,
            config: Arc::clone(&self.config),
        }
    }
}

/// A [`WebSocketGuard`], in the style of the axum layer constructors.
#[must_use]
pub fn websocket_guard(config: WebSocketGuardConfig) -> WebSocketGuard {
    WebSocketGuard::new(config)
}

/// The [`tower::Service`](tower::Service) produced by
/// [`WebSocketGuard::layer`]. `Clone` (axum's `Router::layer` requires it):
/// clones share the one config through its `Arc`.
#[derive(Clone)]
pub struct WebSocketGuardService<S> {
    inner: S,
    config: Arc<WebSocketGuardConfig>,
}

impl<S> WebSocketGuardService<S> {
    /// The verdict an upgrade request gets before dispatch (also the
    /// programmatic seam: the same sequence the middleware runs). `Err`
    /// carries the close shape the handshake must be rejected with.
    pub fn upgrade_verdict(&self, request: &Request) -> Result<(), WebSocketCloseReason> {
        let parts = WebSocketRequestParts::extract(request);
        run_checks_guarded(&self.config, &parts)
    }
}

impl<S> tower::Service<Request> for WebSocketGuardService<S>
where
    S: tower::Service<Request, Response = Response> + Send + 'static,
    S::Error: Send,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request) -> Self::Future {
        if !is_websocket_upgrade(&request) {
            return Box::pin(self.inner.call(request));
        }
        match self.upgrade_verdict(&request) {
            Ok(()) => Box::pin(self.inner.call(request)),
            Err(reason) => Box::pin(std::future::ready(Ok(close_response(reason)))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::routing::get;
    use guard_core_engine::geo::parse_country_lists;
    use guard_core_engine::rate_limit::RateLimitConfig;
    use tower::ServiceExt;

    fn detect_config() -> DetectConfig {
        crate::default_config()
    }

    #[test]
    fn close_table_matches_the_reference() {
        assert_eq!(
            WS_CLOSE_IP_BANNED,
            WebSocketCloseReason {
                code: 1008,
                reason: "IP banned"
            }
        );
        assert_eq!(
            WS_CLOSE_IP_NOT_ALLOWED,
            WebSocketCloseReason {
                code: 1008,
                reason: "IP not allowed"
            }
        );
        assert_eq!(
            WS_CLOSE_RATE_LIMIT_EXCEEDED,
            WebSocketCloseReason {
                code: 1008,
                reason: "Rate limit exceeded"
            }
        );
        assert_eq!(
            WS_CLOSE_CLIENT_ADDRESS_UNKNOWN,
            WebSocketCloseReason {
                code: 1008,
                reason: "Client address could not be determined"
            }
        );
        assert_eq!(
            WS_CLOSE_SECURITY_CHECK_FAILED,
            WebSocketCloseReason {
                code: 1013,
                reason: "Security check failed"
            }
        );
        assert_eq!(
            WS_CLOSE_SUSPICIOUS_ACTIVITY,
            WebSocketCloseReason {
                code: 1008,
                reason: "Suspicious activity detected"
            }
        );
    }

    #[test]
    fn upgrade_detection_reads_both_headers() {
        let upgrade = |upgrade: &'static str, connection: Option<&'static str>| {
            let mut builder = Request::builder().uri("/ws");
            if let Some(connection) = connection {
                builder = builder.header("Connection", connection);
            }
            if !upgrade.is_empty() {
                builder = builder.header("Upgrade", upgrade);
            }
            is_websocket_upgrade(&builder.body(()).expect("request"))
        };
        assert!(upgrade("websocket", Some("upgrade")));
        assert!(upgrade("WebSocket", Some("keep-alive, Upgrade")));
        assert!(!upgrade("websocket", Some("keep-alive")));
        assert!(!upgrade("websocket", None));
        assert!(!upgrade("h2c", Some("upgrade")));
        assert!(!upgrade("", Some("upgrade")));
    }

    #[test]
    fn close_for_status_maps_the_block_shapes() {
        assert_eq!(
            websocket_close_for_status(500, "Security check failed"),
            WS_CLOSE_SECURITY_CHECK_FAILED
        );
        assert_eq!(
            websocket_close_for_status(429, "Too many requests"),
            WS_CLOSE_RATE_LIMIT_EXCEEDED
        );
        assert_eq!(
            websocket_close_for_status(403, "IP address banned"),
            WS_CLOSE_IP_BANNED
        );
        assert_eq!(
            websocket_close_for_status(400, "Suspicious activity detected"),
            WS_CLOSE_SUSPICIOUS_ACTIVITY
        );
        assert_eq!(
            websocket_close_for_status(403, "Forbidden"),
            WS_CLOSE_IP_NOT_ALLOWED
        );
    }

    #[test]
    fn query_pairs_decode_like_parse_qsl() {
        assert_eq!(
            parse_query_pairs("q=%3Cscript%3E&x=a+b&flag&bad=%zz"),
            vec![
                (String::from("q"), String::from("<script>")),
                (String::from("x"), String::from("a b")),
                (String::from("flag"), String::new()),
                (String::from("bad"), String::from("%zz")),
            ]
        );
        assert!(parse_query_pairs("").is_empty());
        assert_eq!(decode_component("caf%C3%A9"), "café");
    }

    #[test]
    fn clean_upgrade_passes_every_arm() {
        let config = WebSocketGuardConfig::new(detect_config());
        assert_eq!(
            run_websocket_checks(
                &config,
                Some("203.0.113.7".parse().expect("ip")),
                "/ws",
                &[],
                &[]
            ),
            Ok(())
        );
    }

    #[test]
    fn unknown_address_is_fail_open_by_default_and_fail_secure_on_request() {
        let config = WebSocketGuardConfig::new(detect_config());
        assert_eq!(run_websocket_checks(&config, None, "/ws", &[], &[]), Ok(()));
        let config = config.with_fail_secure(true);
        assert_eq!(
            run_websocket_checks(&config, None, "/ws", &[], &[]),
            Err(WS_CLOSE_CLIENT_ADDRESS_UNKNOWN)
        );
    }

    #[test]
    fn ban_arm_answers_ip_banned() {
        let manager = IpBanManager::new();
        let ip: IpAddr = "203.0.113.9".parse().expect("ip");
        manager.ban_ip(ip, 60, "test ban").expect("ban");
        let config = WebSocketGuardConfig::new(detect_config()).with_ip_banning(manager);
        assert_eq!(
            run_websocket_checks(&config, Some(ip), "/ws", &[], &[]),
            Err(WS_CLOSE_IP_BANNED)
        );
    }

    #[test]
    fn gate_lists_answer_ip_not_allowed() {
        let blacklist = IpGateConfig::new([] as [&str; 0], ["203.0.113.0/24"], [] as [&str; 0])
            .expect("valid lists");
        let config = WebSocketGuardConfig::new(detect_config()).with_ip_gate(blacklist);
        let ip: IpAddr = "203.0.113.9".parse().expect("ip");
        assert_eq!(
            run_websocket_checks(&config, Some(ip), "/ws", &[], &[]),
            Err(WS_CLOSE_IP_NOT_ALLOWED)
        );

        let whitelist = IpGateConfig::new(
            ["198.51.100.0/24"] as [&str; 1],
            [] as [&str; 0],
            [] as [&str; 0],
        )
        .expect("valid lists");
        let config = WebSocketGuardConfig::new(detect_config()).with_ip_gate(whitelist);
        assert_eq!(
            run_websocket_checks(&config, Some(ip), "/ws", &[], &[]),
            Err(WS_CLOSE_IP_NOT_ALLOWED)
        );
        let allowed: IpAddr = "198.51.100.4".parse().expect("ip");
        assert_eq!(
            run_websocket_checks(&config, Some(allowed), "/ws", &[], &[]),
            Ok(())
        );
    }

    struct FixedCountry(&'static str);

    impl GeoIpHandler for FixedCountry {
        fn get_country(&self, _ip: IpAddr) -> Option<String> {
            Some(self.0.to_owned())
        }
    }

    #[test]
    fn country_rules_answer_ip_not_allowed_and_whitelist_skips_them() {
        let gate = parse_country_lists(["US"], [] as [&str; 0]);
        let config = WebSocketGuardConfig::new(detect_config())
            .with_country_rules(gate, Arc::new(FixedCountry("DE")));
        let ip: IpAddr = "203.0.113.9".parse().expect("ip");
        assert_eq!(
            run_websocket_checks(&config, Some(ip), "/ws", &[], &[]),
            Err(WS_CLOSE_IP_NOT_ALLOWED)
        );

        let whitelist_gate = IpGateConfig::new([ip.to_string()], [] as [&str; 0], [] as [&str; 0])
            .expect("valid lists");
        let country = parse_country_lists(["US"], [] as [&str; 0]);
        let config = WebSocketGuardConfig::new(detect_config())
            .with_ip_gate(whitelist_gate)
            .with_country_rules(country, Arc::new(FixedCountry("DE")));
        assert_eq!(
            run_websocket_checks(&config, Some(ip), "/ws", &[], &[]),
            Ok(())
        );
    }

    #[test]
    fn rate_limit_arm_answers_rate_limit_exceeded_and_skips_whitelisted() {
        let limiter = RateLimiter::new(RateLimitConfig {
            enable_rate_limiting: true,
            rate_limit: 1,
            rate_limit_window: 10,
            ..RateLimitConfig::default()
        })
        .expect("valid config");
        let config = WebSocketGuardConfig::new(detect_config()).with_rate_limiting(limiter);
        let ip: IpAddr = "203.0.113.9".parse().expect("ip");
        assert_eq!(
            run_websocket_checks(&config, Some(ip), "/ws", &[], &[]),
            Ok(())
        );
        assert_eq!(
            run_websocket_checks(&config, Some(ip), "/ws", &[], &[]),
            Err(WS_CLOSE_RATE_LIMIT_EXCEEDED)
        );

        let whitelist = IpGateConfig::new([ip.to_string()], [] as [&str; 0], [] as [&str; 0])
            .expect("valid lists");
        let limiter = RateLimiter::new(RateLimitConfig {
            enable_rate_limiting: true,
            rate_limit: 1,
            rate_limit_window: 10,
            ..RateLimitConfig::default()
        })
        .expect("valid config");
        let config = WebSocketGuardConfig::new(detect_config())
            .with_ip_gate(whitelist)
            .with_rate_limiting(limiter);
        assert_eq!(
            run_websocket_checks(&config, Some(ip), "/ws", &[], &[]),
            Ok(())
        );
        assert_eq!(
            run_websocket_checks(&config, Some(ip), "/ws", &[], &[]),
            Ok(())
        );
    }

    #[test]
    fn scan_arm_answers_suspicious_activity() {
        let config = WebSocketGuardConfig::new(detect_config());
        let ip: IpAddr = "203.0.113.9".parse().expect("ip");
        assert_eq!(
            run_websocket_checks(&config, Some(ip), "/etc/passwd", &[], &[]),
            Err(WS_CLOSE_SUSPICIOUS_ACTIVITY)
        );
        assert_eq!(
            run_websocket_checks(
                &config,
                Some(ip),
                "/ws",
                &[("cmd".to_owned(), String::from("$(whoami)"))],
                &[],
            ),
            Err(WS_CLOSE_SUSPICIOUS_ACTIVITY)
        );
        assert_eq!(
            run_websocket_checks(
                &config,
                Some(ip),
                "/ws",
                &[],
                &[(
                    "x-inject".to_owned(),
                    String::from("<script>alert(1)</script>")
                )],
            ),
            Err(WS_CLOSE_SUSPICIOUS_ACTIVITY)
        );
    }

    struct PanickingCountry;

    impl GeoIpHandler for PanickingCountry {
        fn get_country(&self, _ip: IpAddr) -> Option<String> {
            panic!("geo backend down");
        }
    }

    #[test]
    fn check_panic_maps_to_try_again_later() {
        let country = parse_country_lists([] as [&str; 0], ["US"]);
        let config = WebSocketGuardConfig::new(detect_config())
            .with_country_rules(country, Arc::new(PanickingCountry));
        let parts = WebSocketRequestParts {
            client_ip: Some("203.0.113.9".parse().expect("ip")),
            url_path: "/ws".to_owned(),
            query_params: Vec::new(),
            headers: Vec::new(),
        };
        assert_eq!(
            run_checks_guarded(&config, &parts),
            Err(WS_CLOSE_SECURITY_CHECK_FAILED)
        );
    }

    #[test]
    fn close_response_carries_the_shape() {
        let response = close_response(WS_CLOSE_IP_BANNED);
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let headers = response.headers();
        assert_eq!(
            headers
                .get(WS_CLOSE_CODE_HEADER)
                .and_then(|value| value.to_str().ok()),
            Some("1008")
        );
        assert_eq!(
            headers
                .get(WS_CLOSE_REASON_HEADER)
                .and_then(|value| value.to_str().ok()),
            Some("IP banned")
        );
    }

    fn upgrade_request(ip: Option<std::net::SocketAddr>) -> Request {
        let mut request = Request::builder()
            .uri("/ws")
            .header("Upgrade", "websocket")
            .header("Connection", "Upgrade")
            .body(Body::empty())
            .expect("request");
        if let Some(ip) = ip {
            request.extensions_mut().insert(ConnectInfo(ip));
        }
        request
    }

    #[tokio::test]
    async fn blocked_upgrade_is_rejected_pre_accept() {
        let manager = IpBanManager::new();
        let ip: IpAddr = "203.0.113.9".parse().expect("ip");
        manager.ban_ip(ip, 60, "test ban").expect("ban");
        let config = WebSocketGuardConfig::new(detect_config()).with_ip_banning(manager);
        let app: Router = Router::new()
            .route("/ws", get(|| async { "upgraded" }))
            .layer(WebSocketGuard::new(config));
        let request = upgrade_request(Some("203.0.113.9:41000".parse().expect("addr")));
        let response = app.oneshot(request).await.expect("response");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            response
                .headers()
                .get(WS_CLOSE_CODE_HEADER)
                .and_then(|value| value.to_str().ok()),
            Some("1008")
        );
        assert_eq!(
            response
                .headers()
                .get(WS_CLOSE_REASON_HEADER)
                .and_then(|value| value.to_str().ok()),
            Some("IP banned")
        );
    }

    #[tokio::test]
    async fn clean_upgrade_reaches_the_handler() {
        let config = WebSocketGuardConfig::new(detect_config()).with_rate_limiting(
            RateLimiter::new(RateLimitConfig {
                enable_rate_limiting: true,
                rate_limit: 10,
                rate_limit_window: 10,
                ..RateLimitConfig::default()
            })
            .expect("valid config"),
        );
        let app: Router = Router::new()
            .route("/ws", get(|| async { "upgraded" }))
            .layer(WebSocketGuard::new(config));
        let request = upgrade_request(Some("203.0.113.7:41000".parse().expect("addr")));
        let response = app.oneshot(request).await.expect("response");
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn non_upgrade_traffic_passes_through_untouched() {
        let manager = IpBanManager::new();
        let ip: IpAddr = "203.0.113.9".parse().expect("ip");
        manager.ban_ip(ip, 60, "test ban").expect("ban");
        let config = WebSocketGuardConfig::new(detect_config()).with_ip_banning(manager);
        let app: Router = Router::new()
            .route("/ws", get(|| async { "plain" }))
            .layer(WebSocketGuard::new(config));
        // A banned client's plain request is not this guard's domain: the
        // HTTP guard screens it.
        let request = Request::builder()
            .uri("/ws")
            .body(Body::empty())
            .expect("request");
        let response = app.oneshot(request).await.expect("response");
        assert_eq!(response.status(), StatusCode::OK);
    }
}
