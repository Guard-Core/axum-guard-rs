//! # axum-guard-rs
//!
//! Application-layer security middleware for [axum](https://github.com/tokio-rs/axum),
//! powered by the [guard-core-rs](https://github.com/rennf93/guard-core-rs)
//! detection engine. Part of the [Guard ecosystem](https://github.com/rennf93).
//!
//! ## Status: implemented (v0.1.0)
//!
//! [`with_guard`] returns the generic [`GuardLayer`] from
//! [`tower-guard-rs`](https://github.com/rennf93/tower-guard-rs), which is
//! already axum-shaped: axum routers are `tower` services, so
//! [`Router::layer`](axum::Router::layer) is the whole integration. This crate
//! is the thin axum-facing surface: the `with_guard` constructor, the
//! re-exports an axum application needs, and the axum-specific tests that pin
//! the behavior against `axum::body::Body`.
//!
//! Per the ecosystem boundary rules this crate contains no security logic:
//! detection comes from the engine, request screening from `tower-guard-rs`.
//!
//! ## What the guard does
//!
//! One engine call per request view (`url_path` for the path, `query_param`
//! for the query string, `header` for non-excluded header values,
//! `request_body` for the buffered body). Bodies are buffered up to a bounded
//! cap (262 144 bytes by default) and oversized bodies are rejected with `413`
//! rather than forwarded unscanned. The adapter is fail-secure: a body read
//! error or an engine panic answers `500`, never an uninspected passthrough.
//! See the [`tower-guard-rs`](https://github.com/rennf93/tower-guard-rs)
//! documentation for the full behavior tables, response shapes, and the
//! header exclusion list.
//!
//! ## The stateful stage: rate limiting, bans, auto-ban
//!
//! Two opt-in builders on [`GuardLayer`] install the engine's stateful
//! machinery, mirroring the tower reference exactly:
//!
//! - [`GuardLayer::with_rate_limiting`]: a crossing of the
//!   sliding window answers `429 Too Many Requests` carrying
//!   `Retry-After: <window seconds>`. With the limiter's
//!   `enable_rate_limit_auto_ban` on, every crossing counts one `rate_limit`
//!   violation toward the auto-ban engine; the response stays 429 and the ban
//!   bites on the next request.
//! - [`GuardLayer::with_ip_banning`]: a live ban on
//!   the client IP answers `403 Forbidden` (`IP address banned`) **before**
//!   the limiter, so banned traffic never consumes rate budget. Every detected
//!   threat counts its categories per client IP, and a crossed
//!   `threat_ban_config` entry (or the flat `auto_ban_threshold`) bans on the
//!   spot, answering `403 Forbidden` (`IP has been banned`); without it the
//!   plain detection block stays `400 Bad Request`. With
//!   `enable_ip_banning = false` violations count but never ban.
//!
//! Both stages honor the `exempt_ips` contract: whitelisted and exempt IPs
//! (via [`client_ip_layer`] + [`IpGateConfig`]) are never rate limited, never
//! banned, and never counted, and unattributed requests (no
//! `ConnectInfo<SocketAddr>`, so no [`GuardClientIp`]) skip the stage but
//! stay detection-screened. Cloning the layer shares the one limiter and ban
//! store: they are process-global by design.
//!
//! ## The full stage surface (the reference 17-check pipeline, wired)
//!
//! Every reference check the engine ships is installable on the
//! [`GuardLayer`] [`with_guard`] returns, and the service runs the installed
//! set in the reference pipeline order ([`provided_layers`] hands the same
//! stages back as standalone tower layers in that order):
//!
//! | Reference check | Builder |
//! |---|---|
//! | 2 `emergency_mode` | [`GuardLayer::with_emergency_mode`] |
//! | 3 `https_enforcement` | [`GuardLayer::with_https_enforcement`] |
//! | 4 `request_logging` | [`GuardLayer::with_request_logging`] |
//! | 5 `request_size_content` | [`GuardLayer::with_body_cap`] (413) |
//! | 6 + 7 `required_headers` / authentication | [`GuardLayer::with_headers_auth`] |
//! | 8 referrer | [`GuardLayer::with_referrer_gate`] |
//! | 9 `custom_validators` | [`GuardLayer::with_custom_checks`] |
//! | 10 `time_window` | [`GuardLayer::with_time_window_gate`] |
//! | 12b geo country blocking | [`GuardLayer::with_geo_blocking`] |
//! | 13 `cloud_provider` | [`GuardLayer::with_cloud_provider`] |
//! | 14 `user_agent` | [`GuardLayer::with_user_agent`] |
//! | 12a / 15 / 16 bans / `rate_limit` / detection feed | [`GuardLayer::with_rate_limiting`] + [`GuardLayer::with_ip_banning`] |
//! | 17 `custom_request` | [`GuardLayer::with_custom_checks`] |
//! | response pass (return rules + security headers + CORS) | [`GuardLayer::with_response_processor`] |
//!
//! ## The 4.2.0 wave surfaces (re-exported, axum-shaped)
//!
//! Every wave surface configurable on [`GuardLayer`] is reachable through
//! `with_guard`'s return value, so an axum application turns each one on
//! with a chain before [`Router::layer`](axum::Router::layer):
//! route/geo rate-limit tiers ([`GuardLayer::with_route_tiers`] with a
//! [`RouteRateLimits`] request extension winning, [`GuardLayer::with_geo_handler`]),
//! per-route detection exclusions ([`GuardLayer::with_detection_exclusions`]
//! plus the [`RouteDetectionExclusions`] request extension), the event bus
//! and observability knobs ([`GuardLayer::with_event_bus`],
//! [`GuardLayer::with_observability`]), `on_block` + custom error bodies
//! ([`GuardLayer::with_on_block`], [`GuardLayer::with_custom_error_responses`]),
//! the distributed stores ([`GuardLayer::with_distributed_store`] +
//! [`GuardLayer::with_distributed_ban_store`]), and passive mode
//! ([`GuardLayer::with_passive_mode`]). The axum tests pin each surface end
//! to end through a `Router`.

//! # Example
//!
//! ```
//! use axum::Router;
//! use axum::routing::get;
//! use axum_guard_rs::{IpBanConfig, IpBanManager, RateLimitConfig, RateLimiter, ThreatBanEntry, with_guard};
//!
//! let limiter = RateLimiter::new(RateLimitConfig {
//!     enable_rate_limiting: true,
//!     rate_limit: 30,
//!     rate_limit_window: 10,
//!     ..RateLimitConfig::default()
//! })
//! .expect("valid config");
//! let bans = IpBanConfig::new(
//!     true,
//!     10,
//!     3600,
//!     [] as [(String, ThreatBanEntry); 0],
//! )
//! .expect("valid config");
//!
//! let app: Router = Router::new()
//!     .route("/hello", get(|| async { "hello" }))
//!     .layer(
//!         with_guard(axum_guard_rs::default_config())
//!             .with_rate_limiting(limiter)
//!             .with_ip_banning(IpBanManager::new(), bans),
//!     );
//! # let _ = app;
//! ```
//!
//! ## Example
//!
//! ```
//! use axum::body::Body;
//! use axum::routing::get;
//! use axum::{Router, http::Request};
//! use tower::ServiceExt;
//!
//! # let runtime = tokio::runtime::Builder::new_current_thread()
//! #     .enable_all()
//! #     .build()
//! #     .unwrap();
//! # runtime.block_on(async {
//! let app = Router::new()
//!     .route("/hello", get(|| async { "hello" }))
//!     .layer(axum_guard_rs::with_guard(axum_guard_rs::default_config()));
//!
//! let request = Request::builder()
//!     .uri("/hello")
//!     .body(Body::empty())
//!     .unwrap();
//! let response = app.oneshot(request).await.unwrap();
//! assert_eq!(response.status(), 200);
//!
//! // Attack traffic is blocked by the engine.
//! let request = Request::builder()
//!     .uri("/hello?cmd=$(whoami)")
//!     .body(Body::empty())
//!     .unwrap();
//! let response = Router::new()
//!     .route("/hello", get(|| async { "hello" }))
//!     .layer(axum_guard_rs::with_guard(axum_guard_rs::default_config()))
//!     .oneshot(request)
//!     .await
//!     .unwrap();
//! assert_eq!(response.status(), 400);
//! # });
//! ```

pub use tower_guard_rs::{
    ACTIVITY_BANNED_MESSAGE, BANNED_MESSAGE, BLOCKED_MESSAGE, BanError, BanRecord, BanStore,
    BlockPayload, BoxError, BufferOverflowPolicy, Clock, CloudDecision, CloudProviderStage,
    CorsConfig, CustomChecksStage, CustomErrorResponses, DetectConfig, DetectVerdict,
    DetectionExclusionConfig, EmergencyAnswer, EmergencyModeStage, FAILURE_MESSAGE,
    FORBIDDEN_MESSAGE, GateAnswer, GeoDecision, GeoIpHandler, GeoStage, GeoStageConfig, GuardBody,
    GuardClientIp, GuardConfigError, GuardLayer, GuardService, GuardStageLayer, GuardStageService,
    HeaderAuthRules, HeadersAuthAnswer, HeadersAuthStage, HttpsEnforcementStage, HttpsRedirect,
    IpBanConfig, IpBanConfigError, IpBanManager, IpGateConfig, IpGateDecision, IpGateDenial,
    IpGateError, IpGateVerdict, LogFormat, LogLevel, OVERSIZE_MESSAGE, ObservabilityConfig,
    OnBlockHook, RATE_LIMITED_MESSAGE, REQUIRED_SENTINEL, RateLimitConfig, RateLimitConfigError,
    RateLimitDecision, RateLimitEntry, RateLimitStage, RateLimitStageConfig, RateLimitTier,
    RateLimiter, RequestLoggingStage, RequestLoggingStageConfig, RequestObservation,
    RequiredHeader, ResolvedBan, ResponseProcessor, RouteConfig, RouteConfigResolver,
    RouteDetectionExclusions, RouteGuard, RouteRateLimits, RouteRateResolver, SecurityConfig,
    SecurityConfigError, SecurityEventBus, SecurityHeadersConfig, SlidingWindowStore,
    StageResponse, Threat, ThreatBanEntry, TierDecision, TimeWindowStage, UserAgentConfigError,
    UserAgentStage, UserAgentStageConfig, ViolationCounters, default_config, provided_layers,
};

pub mod status;
pub mod websocket;

use axum::extract::connect_info::ConnectInfo;
use std::net::SocketAddr;
use std::task::{Context, Poll};
use tower::{Layer, Service};

/// Copy the axum connection info into the extension the IP gate reads.
///
/// `ConnectInfo<SocketAddr>` is only present when the router is served with
/// `into_make_service_with_connect_info::<SocketAddr>()`. The layer copies
/// its peer address into [`GuardClientIp`], the extension
/// [`GuardLayer::with_ip_gate`] evaluates. Apply it **after** the guard layer
/// so it wraps the outside: axum runs the last-added layer first, and the
/// guard needs the extension in place when the request arrives.
///
/// # Example
///
/// ```
/// use axum::Router;
/// use axum::extract::ConnectInfo;
/// use axum_guard_rs::{IpGateConfig, client_ip_layer, with_guard};
///
/// let gate = IpGateConfig::new(
///     [] as [&str; 0],
///     ["203.0.113.9"],
///     ["198.51.100.0/28"],
/// )
/// .expect("valid lists");
///
/// let app: Router = Router::new()
///     .layer(with_guard(axum_guard_rs::default_config()).with_ip_gate(gate))
///     .layer(client_ip_layer());
/// # let _ = app;
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct ClientIpLayer;

impl<S> Layer<S> for ClientIpLayer {
    type Service = ClientIpService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ClientIpService { inner }
    }
}

/// The [`tower::Service`] produced by [`ClientIpLayer`].
#[derive(Debug, Clone)]
pub struct ClientIpService<S> {
    inner: S,
}

impl<S, B> Service<axum::extract::Request<B>> for ClientIpService<S>
where
    S: Service<axum::extract::Request<B>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), S::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: axum::extract::Request<B>) -> Self::Future {
        let client_ip = request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ConnectInfo(peer)| tower_guard_rs::GuardClientIp(peer.ip()));
        if let Some(client_ip) = client_ip {
            request.extensions_mut().insert(client_ip);
        }
        self.inner.call(request)
    }
}

/// A [`ClientIpLayer`], in the style of the axum layer constructors.
#[must_use]
pub const fn client_ip_layer() -> ClientIpLayer {
    ClientIpLayer
}

/// Build the Guard layer for an axum [`Router`](axum::Router).
///
/// Apply it with [`Router::layer`](axum::Router::layer) (every registered
/// route) or [`Router::route_layer`](axum::Router::route_layer) (routes only,
/// skipping the fallback). Chain [`GuardLayer::with_body_cap`] to change the
/// body buffering cap, [`GuardLayer::with_ip_gate`] to install the global IP
/// gate, and [`GuardLayer::with_rate_limiting`] / [`GuardLayer::with_ip_banning`]
/// to install the stateful stage (rate limiting, dynamic bans, auto-ban).
///
/// # Example
///
/// ```
/// use axum::Router;
/// use axum_guard_rs::{DetectConfig, with_guard};
///
/// let config = DetectConfig {
///     max_content_length: 10_000,
///     max_full_scan_bytes: 262_144,
///     preserve_attack_patterns: true,
///     semantic_threshold: 0.7,
///     threat_score_threshold: 1.0,
///     binary_min_run_length: 16,
/// };
///
/// let app: Router = Router::new().layer(with_guard(config));
/// # let _ = app;
/// ```
#[must_use]
pub fn with_guard(config: DetectConfig) -> GuardLayer {
    GuardLayer::new(config)
}

/// Build the Guard layer from the unified [`SecurityConfig`]
/// (the reference configuration surface).
///
/// This is [`GuardLayer::from_security_config`] under the axum constructor
/// name, the same one-call consumption the tower adapter ships: every field
/// the layer consumes maps onto the wired stage or knob it owns (the
/// detection budgets, the IP lists onto the gate, the rate-limit and ban
/// groups, `enforce_https` onto the HTTPS stage, `emergency_mode` and its
/// whitelist, `custom_error_responses`/`on_block`, the detection-exclusion
/// group, the observability group, the ReDoS-validated
/// `blocked_user_agents`, and the security-headers/CORS/behavior response
/// pass), the reference `exclude_paths` carve-out rides along as a
/// first-class builder, and invalid values fail closed through
/// [`GuardConfigError`]. Chain further builders (the geo handler, the
/// distributed stores, the event bus, the per-route resolvers) onto the
/// return value exactly like [`with_guard`]'s.
///
/// # Errors
///
/// [`GuardConfigError`] when an engine constructor rejects a value (an
/// invalid IP/CIDR list entry, a zero rate-limit knob, or a ReDoS-unsafe
/// blocked user-agent pattern).
///
/// # Example
///
/// ```
/// use axum::Router;
/// use axum_guard_rs::{SecurityConfig, with_security_config};
///
/// let config = SecurityConfig {
///     blacklist: vec![String::from("203.0.113.9")],
///     ..SecurityConfig::default()
/// };
/// let layer = with_security_config(&config).expect("valid config");
/// let app: Router = Router::new().layer(layer);
/// # let _ = app;
/// ```
pub fn with_security_config(config: &SecurityConfig) -> Result<GuardLayer, GuardConfigError> {
    GuardLayer::from_security_config(config)
}
