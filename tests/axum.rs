//! axum-specific behavior: `Router::layer` + `with_guard`, exercised end to
//! end through `tower::ServiceExt::oneshot` with `axum::body::Body`.

use axum::body::Body;
use axum::extract::State;
use axum::http::Request;
use axum::routing::{get, post};
use axum::{Json, Router};
use axum_guard_rs::{BLOCKED_MESSAGE, OVERSIZE_MESSAGE, default_config, with_guard};
use http::StatusCode;
use http::header::CONTENT_TYPE;
use http_body_util::BodyExt;
use std::str::FromStr;
use std::sync::Arc;
use tower::{Service, ServiceExt};

/// A small router with a variety of handler shapes.
fn app() -> Router {
    Router::new()
        .route("/hello", get(|| async { "hello" }))
        .route("/state", get(read_state))
        .route("/echo", post(echo_json))
        .route("/files/{*path}", get(|| async { "files" }))
        .layer(with_guard(default_config()))
        .with_state(Arc::new("state reached".to_owned()))
}

async fn read_state(State(state): State<Arc<String>>) -> String {
    (*state).clone()
}

async fn echo_json(Json(value): Json<serde_json::Value>) -> Json<serde_json::Value> {
    Json(value)
}

fn get_request(uri: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .body(Body::empty())
        .expect("request")
}

fn post_request(uri: &str, body: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_owned()))
        .expect("request")
}

async fn body_text(response: axum::response::Response) -> String {
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    String::from_utf8_lossy(&bytes).into_owned()
}

#[tokio::test]
async fn benign_get_passes_through_the_router() {
    let response = app()
        .oneshot(get_request("/hello"))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_text(response).await, "hello");
}

#[tokio::test]
async fn json_body_round_trips_through_extraction_and_guard() {
    let response = app()
        .oneshot(post_request("/echo", r#"{"name":"renn","id":7}"#))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    // Compare as parsed values: `serde_json::Value` re-serializes map keys in
    // sorted order, so byte-equality against the request body would not hold.
    let text = body_text(response).await;
    let parsed: serde_json::Value = serde_json::from_str(&text).expect("json");
    assert_eq!(parsed, serde_json::json!({"name": "renn", "id": 7}));
}

#[tokio::test]
async fn handler_state_extraction_is_unaffected() {
    let response = app()
        .oneshot(get_request("/state"))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_text(response).await, "state reached");
}

#[tokio::test]
async fn xss_payload_in_body_is_blocked() {
    let response = app()
        .oneshot(post_request("/echo", r"<script>alert(1)</script>"))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response.headers().get(CONTENT_TYPE).expect("content type"),
        "text/plain; charset=utf-8"
    );
    assert_eq!(body_text(response).await, BLOCKED_MESSAGE);
}

#[tokio::test]
async fn traversal_payload_in_path_is_blocked_in_url_path_context() {
    let response = app()
        .oneshot(get_request("/files/../../etc/passwd"))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn command_injection_in_query_is_blocked_in_query_param_context() {
    let response = app()
        .oneshot(get_request("/hello?cmd=$(whoami)"))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn xss_payload_in_scanned_header_is_blocked() {
    let request = Request::builder()
        .uri("/hello")
        .header("x-comment", "<script>alert(1)</script>")
        .body(Body::empty())
        .expect("request");
    let response = app().oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn benign_headers_do_not_trip_the_guard() {
    let request = Request::builder()
        .uri("/hello")
        .header(
            "authorization",
            "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig",
        )
        .header("cookie", "session=5f4dcc3b5aa765d61d8327deb882cf99")
        .header("user-agent", "guard-tests/0.1")
        .body(Body::empty())
        .expect("request");
    let response = app().oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn body_over_the_cap_is_rejected_with_413() {
    let app = Router::new()
        .route("/echo", post(echo_json))
        .layer(with_guard(default_config()).with_body_cap(16));
    let response = app
        .oneshot(post_request(
            "/echo",
            r#"{"note":"this is longer than sixteen bytes"}"#,
        ))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(body_text(response).await, OVERSIZE_MESSAGE);
}

#[tokio::test]
async fn unmatched_route_still_answers_404() {
    // The guard layer wraps registered routes; a request that matches nothing
    // reaches the fallback untouched. This pins that the guard does not turn
    // unrelated 404s into blocks.
    let response = app().oneshot(get_request("/nope")).await.expect("response");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn concurrent_requests_are_screened_independently() {
    let app = app();
    let handles: Vec<_> = (0..16)
        .map(|index| {
            let app = app.clone();
            tokio::spawn(async move {
                let request = if index % 2 == 0 {
                    get_request("/hello")
                } else {
                    post_request("/echo", r"<script>alert(1)</script>")
                };
                app.oneshot(request).await.expect("response").status()
            })
        })
        .collect();

    for (index, handle) in handles.into_iter().enumerate() {
        let status = handle.await.expect("task");
        if index % 2 == 0 {
            assert_eq!(status, StatusCode::OK, "benign request {index}");
        } else {
            assert_eq!(status, StatusCode::BAD_REQUEST, "threat request {index}");
        }
    }
}

#[tokio::test]
async fn poll_ready_forwards_through_the_router() {
    let mut app = app();
    let waker = std::task::Waker::noop();
    let mut cx = std::task::Context::from_waker(waker);
    match Service::<Request<Body>>::poll_ready(&mut app, &mut cx) {
        std::task::Poll::Ready(result) => result.expect("ready"),
        std::task::Poll::Pending => panic!("router is always ready"),
    }
}

// --- the global IP gate (exempt_ips contract checklist) ---

use axum::extract::ConnectInfo;
use axum_guard_rs::{FORBIDDEN_MESSAGE, IpGateConfig, client_ip_layer};

/// The checklist gate: a blacklisted exact IP and a blacklisted /24
/// (192.0.2.x), an exempt exact IP and an exempt /28 (198.51.100.x), all
/// disjoint.
fn checklist_gate() -> IpGateConfig {
    IpGateConfig::new(
        [] as [&str; 0],
        ["203.0.113.9", "192.0.2.0/24"],
        ["198.51.100.7", "198.51.100.16/28"],
    )
    .expect("valid lists")
}

/// A router guarded by `gate`, with the client-ip layer applied after the
/// guard so the extension is in place when the guard runs.
fn gated_app(gate: IpGateConfig) -> Router {
    Router::new()
        .route("/hello", get(|| async { "hello" }))
        .layer(with_guard(default_config()).with_ip_gate(gate))
        .layer(client_ip_layer())
}

fn attributed_request(uri: &str, ip: &str) -> Request<Body> {
    let peer = std::net::SocketAddr::new(std::net::IpAddr::from_str(ip).unwrap(), 45_000);
    Request::builder()
        .uri(uri)
        .extension(ConnectInfo(peer))
        .body(Body::empty())
        .expect("request")
}

async fn gated_status(app: Router, request: Request<Body>) -> (StatusCode, String) {
    let response = app.oneshot(request).await.expect("response");
    let status = response.status();
    (status, body_text(response).await)
}

#[tokio::test]
async fn blacklisted_ip_is_denied_with_the_forbidden_body() {
    let (status, body) = gated_status(
        gated_app(checklist_gate()),
        attributed_request("/hello", "203.0.113.9"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body, FORBIDDEN_MESSAGE);

    let (status, body) = gated_status(
        gated_app(checklist_gate()),
        attributed_request("/hello", "192.0.2.77"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body, FORBIDDEN_MESSAGE);
}

#[tokio::test]
async fn exempt_exact_and_cidr_ips_pass() {
    let app = gated_app(checklist_gate());
    let (status, _) = gated_status(app.clone(), attributed_request("/hello", "198.51.100.7")).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = gated_status(app, attributed_request("/hello", "198.51.100.20")).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn exempt_ip_on_the_blacklist_is_still_denied() {
    let gate = IpGateConfig::new([] as [&str; 0], ["198.51.100.7"], ["198.51.100.7"])
        .expect("valid lists");
    let (status, body) = gated_status(
        gated_app(gate),
        attributed_request("/hello", "198.51.100.7"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body, FORBIDDEN_MESSAGE);
}

#[tokio::test]
async fn exemption_never_opens_a_restrictive_whitelist() {
    let gate =
        IpGateConfig::new(["192.0.2.1"], [] as [&str; 0], ["198.51.100.7"]).expect("valid lists");
    let (status, body) = gated_status(
        gated_app(gate),
        attributed_request("/hello", "198.51.100.7"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body, FORBIDDEN_MESSAGE);
}

#[tokio::test]
async fn an_attack_from_an_exempt_ip_is_still_blocked_by_detection() {
    // Checklist: penetration detection still applies to exempt IPs.
    let (status, body) = gated_status(
        gated_app(checklist_gate()),
        attributed_request("/files/../../etc/passwd", "198.51.100.7"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body, BLOCKED_MESSAGE);
}

#[tokio::test]
async fn without_connect_info_the_gate_is_inert_and_detection_still_applies() {
    let app = gated_app(checklist_gate());
    let status = app
        .clone()
        .oneshot(get_request("/hello"))
        .await
        .expect("response")
        .status();
    assert_eq!(status, StatusCode::OK, "unattributed benign traffic passes");

    let (status, body) = gated_status(app, get_request("/files/../../etc/passwd")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body, BLOCKED_MESSAGE);
}

#[test]
fn invalid_exempt_entry_fails_closed_at_config_time() {
    let error = IpGateConfig::new([] as [&str; 0], [] as [&str; 0], ["not-an-ip"]).unwrap_err();
    assert_eq!(error.list, "exempt_ips");
    assert_eq!(error.entry, "not-an-ip");
}

#[test]
fn ipv4_mapped_peer_matches_v4_entries() {
    // Checklist: IPv4-mapped parity, same matching semantics as the whitelist
    // matcher (std parses the mapped form as an IPv6 address).
    let mapped = std::net::IpAddr::from_str("::ffff:198.51.100.7").unwrap();
    let gate = IpGateConfig::new(["198.51.100.0/28"], [] as [&str; 0], ["198.51.100.7"]).unwrap();
    assert!(matches!(
        gate.evaluate(mapped),
        axum_guard_rs::IpGateVerdict::Allowed(decision) if decision.is_exempt
    ));
}

// --- the stateful stage: rate limiting, bans, auto-ban ---

use axum_guard_rs::{
    ACTIVITY_BANNED_MESSAGE, BANNED_MESSAGE, IpBanConfig, IpBanManager, RATE_LIMITED_MESSAGE,
    RateLimitConfig, RateLimiter, ThreatBanEntry,
};
use std::sync::atomic::{AtomicU64, Ordering};

/// An enabled rate limiter with the given limit and auto-ban switch.
fn limiter(limit: u32, auto_ban: bool) -> RateLimiter {
    RateLimiter::new(RateLimitConfig {
        enable_rate_limiting: true,
        rate_limit: limit,
        rate_limit_window: 60,
        enable_rate_limit_auto_ban: auto_ban,
    })
    .expect("valid config")
}

/// The empty `threat_ban_config`, typed for `IpBanConfig::new`.
fn no_entries() -> Vec<(String, ThreatBanEntry)> {
    Vec::new()
}

/// A fake clock (unix seconds starting at `1_000`) plus its handle, for
/// deterministic ban-expiry coverage.
fn fake_clock() -> (axum_guard_rs::Clock, Arc<AtomicU64>) {
    let state = Arc::new(AtomicU64::new(1_000));
    let clock: axum_guard_rs::Clock = {
        let seconds = state.clone();
        #[allow(clippy::cast_precision_loss)]
        Arc::new(move || seconds.load(Ordering::Relaxed) as f64)
    };
    (clock, state)
}

/// A router guarded by the given layer, with the client-ip layer applied
/// after the guard so the extension is in place when the guard runs.
fn guarded_app(layer: axum_guard_rs::GuardLayer) -> Router {
    Router::new()
        .route("/hello", get(|| async { "hello" }))
        .layer(layer)
        .layer(client_ip_layer())
}

/// Status, body, and the `Retry-After` header of one guarded request.
async fn full_status(app: Router, request: Request<Body>) -> (StatusCode, String, Option<String>) {
    let response = app.oneshot(request).await.expect("response");
    let status = response.status();
    let retry_after = response
        .headers()
        .get(http::header::RETRY_AFTER)
        .map(|value| value.to_str().expect("ascii header").to_owned());
    (status, body_text(response).await, retry_after)
}

async fn status_body(app: Router, request: Request<Body>) -> (StatusCode, String) {
    let (status, body, _) = full_status(app, request).await;
    (status, body)
}

#[tokio::test]
async fn rate_limit_crossing_is_blocked_429_with_retry_after() {
    let app = guarded_app(with_guard(default_config()).with_rate_limiting(limiter(2, false)));
    for _ in 0..2 {
        let (status, _, retry_after) =
            full_status(app.clone(), attributed_request("/hello", "192.0.2.55")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(retry_after, None, "allowed requests carry no Retry-After");
    }
    let (status, body, retry_after) =
        full_status(app, attributed_request("/hello", "192.0.2.55")).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body, RATE_LIMITED_MESSAGE);
    assert_eq!(
        retry_after.as_deref(),
        Some("60"),
        "Retry-After is the window"
    );
}

#[tokio::test]
async fn exempt_ip_exceeds_the_limit_and_still_gets_200() {
    // Checklist: the exempt flag is observable - exemption skips rate
    // limiting exactly like a whitelist match.
    let gate =
        IpGateConfig::new([] as [&str; 0], [] as [&str; 0], ["198.51.100.7"]).expect("valid lists");
    let app = guarded_app(
        with_guard(default_config())
            .with_ip_gate(gate)
            .with_rate_limiting(limiter(1, false)),
    );
    for _ in 0..5 {
        let (status, _, _) =
            full_status(app.clone(), attributed_request("/hello", "198.51.100.7")).await;
        assert_eq!(status, StatusCode::OK, "exempt IPs are never rate limited");
    }
    // A non-exempt peer under the same config is limited as usual.
    let (status, _, _) = full_status(app.clone(), attributed_request("/hello", "192.0.2.55")).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _, _) = full_status(app, attributed_request("/hello", "192.0.2.55")).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn unattributed_requests_are_not_rate_limited() {
    // No `ConnectInfo` extension: the request cannot be attributed, so the
    // stateful stage skips it (detection still screens).
    let app = guarded_app(with_guard(default_config()).with_rate_limiting(limiter(1, false)));
    for _ in 0..5 {
        let (status, _, _) = full_status(app.clone(), get_request("/hello")).await;
        assert_eq!(status, StatusCode::OK);
    }
}

#[tokio::test]
async fn banned_ip_is_blocked_with_the_banned_body() {
    let manager = IpBanManager::new();
    let config = IpBanConfig::new(true, 10, 3600, no_entries()).expect("valid config");
    let app = guarded_app(with_guard(default_config()).with_ip_banning(manager.clone(), config));
    // Ban out of band through the shared handle (an operator or the auto-ban
    // engine did it).
    manager
        .ban_ip(
            std::net::IpAddr::from_str("192.0.2.55").unwrap(),
            60,
            "operator",
        )
        .expect("ban");
    let (status, body) = status_body(app.clone(), attributed_request("/hello", "192.0.2.55")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body, BANNED_MESSAGE);

    // Other IPs are untouched.
    let (status, _, _) = full_status(app, attributed_request("/hello", "192.0.2.56")).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn ban_expiry_is_honored_for_a_short_duration() {
    let (clock, seconds) = fake_clock();
    let manager = IpBanManager::with_clock(clock);
    let config = IpBanConfig::new(true, 10, 3600, no_entries()).expect("valid config");
    let app = guarded_app(with_guard(default_config()).with_ip_banning(manager.clone(), config));
    manager
        .ban_ip(
            std::net::IpAddr::from_str("192.0.2.55").unwrap(),
            5,
            "short",
        )
        .expect("ban");
    let (status, body) = status_body(app.clone(), attributed_request("/hello", "192.0.2.55")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body, BANNED_MESSAGE);

    seconds.store(1_000 + 6, Ordering::Relaxed);
    let (status, _, _) = full_status(app, attributed_request("/hello", "192.0.2.55")).await;
    assert_eq!(status, StatusCode::OK, "the ban expired");
}

#[tokio::test]
async fn banned_ip_blocks_before_detection_and_rate_limiting() {
    let manager = IpBanManager::new();
    let config = IpBanConfig::new(true, 10, 3600, no_entries()).expect("valid config");
    let app = guarded_app(
        with_guard(default_config())
            .with_rate_limiting(limiter(1, false))
            .with_ip_banning(manager.clone(), config),
    );
    manager
        .ban_ip(
            std::net::IpAddr::from_str("192.0.2.55").unwrap(),
            60,
            "operator",
        )
        .expect("ban");
    // An attack from the banned IP: the ban stage wins over the detection
    // block shape...
    let (status, body) = status_body(
        app.clone(),
        attributed_request("/files/../../etc/passwd", "192.0.2.55"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body, BANNED_MESSAGE);
    // ...and over the rate limiter: banned traffic never consumes budget.
    let (status, body) = status_body(
        app,
        attributed_request("/files/../../etc/passwd", "192.0.2.55"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body, BANNED_MESSAGE);
}

#[tokio::test]
async fn detection_violations_ban_at_the_category_threshold() {
    let config = IpBanConfig::new(
        true,
        100,
        3600,
        [(
            "dir_traversal",
            ThreatBanEntry {
                threshold: 2,
                duration: 60,
            },
        )],
    )
    .expect("valid config");
    let app =
        guarded_app(with_guard(default_config()).with_ip_banning(IpBanManager::new(), config));
    // First violation: the plain block shape.
    let (status, body) = status_body(
        app.clone(),
        attributed_request("/files/../../etc/passwd", "192.0.2.55"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body, BLOCKED_MESSAGE);
    // Second violation crosses the entry: banned on the spot.
    let (status, body) = status_body(
        app.clone(),
        attributed_request("/files/../../etc/passwd", "192.0.2.55"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body, ACTIVITY_BANNED_MESSAGE);
    // From then on the ban stage answers everything.
    let (status, body) = status_body(app, attributed_request("/hello", "192.0.2.55")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body, BANNED_MESSAGE);
}

#[tokio::test]
async fn enable_ip_banning_false_never_bans() {
    let config = IpBanConfig::new(
        false,
        1,
        3600,
        [(
            "dir_traversal",
            ThreatBanEntry {
                threshold: 1,
                duration: 60,
            },
        )],
    )
    .expect("valid config");
    let app =
        guarded_app(with_guard(default_config()).with_ip_banning(IpBanManager::new(), config));
    for _ in 0..3 {
        let (status, body) = status_body(
            app.clone(),
            attributed_request("/files/../../etc/passwd", "192.0.2.55"),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            body, BLOCKED_MESSAGE,
            "banning is off: the plain block shape"
        );
    }
    let (status, _, _) = full_status(app, attributed_request("/hello", "192.0.2.55")).await;
    assert_eq!(status, StatusCode::OK, "nobody was banned");
}

#[tokio::test]
async fn exempt_ip_never_counts_detection_violations() {
    // Checklist: the exempt flag makes violation counting observable - an
    // exempt attacker can never be auto-banned.
    let gate =
        IpGateConfig::new([] as [&str; 0], [] as [&str; 0], ["198.51.100.7"]).expect("valid lists");
    let config = IpBanConfig::new(
        true,
        1,
        3600,
        [(
            "dir_traversal",
            ThreatBanEntry {
                threshold: 1,
                duration: 60,
            },
        )],
    )
    .expect("valid config");
    let app = guarded_app(
        with_guard(default_config())
            .with_ip_gate(gate)
            .with_ip_banning(IpBanManager::new(), config),
    );
    for _ in 0..3 {
        let (status, body) = status_body(
            app.clone(),
            attributed_request("/files/../../etc/passwd", "198.51.100.7"),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            body, BLOCKED_MESSAGE,
            "exempt violations are not counted, so no ban can fire"
        );
    }
}

#[tokio::test]
async fn rate_limit_autoban_is_off_by_default() {
    let config = IpBanConfig::new(true, 1, 3600, no_entries()).expect("valid config");
    let app = guarded_app(
        with_guard(default_config())
            .with_rate_limiting(limiter(1, false))
            .with_ip_banning(IpBanManager::new(), config),
    );
    let (status, _, _) = full_status(app.clone(), attributed_request("/hello", "192.0.2.55")).await;
    assert_eq!(status, StatusCode::OK);
    for _ in 0..5 {
        let (status, body, _) =
            full_status(app.clone(), attributed_request("/hello", "192.0.2.55")).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(body, RATE_LIMITED_MESSAGE, "crossings stay rate limited");
    }
}

#[tokio::test]
async fn rate_limit_autoban_bans_at_the_threshold() {
    let config = IpBanConfig::new(
        true,
        100,
        3600,
        [(
            "rate_limit",
            ThreatBanEntry {
                threshold: 2,
                duration: 30,
            },
        )],
    )
    .expect("valid config");
    let app = guarded_app(
        with_guard(default_config())
            .with_rate_limiting(limiter(1, true))
            .with_ip_banning(IpBanManager::new(), config),
    );
    let (status, _, _) = full_status(app.clone(), attributed_request("/hello", "192.0.2.55")).await;
    assert_eq!(status, StatusCode::OK);
    // First crossing: violation 1, below the entry threshold.
    let (status, body, _) =
        full_status(app.clone(), attributed_request("/hello", "192.0.2.55")).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body, RATE_LIMITED_MESSAGE);
    // Second crossing: violation 2 crosses the entry, the ban fires (the
    // response of this request is still the 429 it earned).
    let (status, _, _) = full_status(app.clone(), attributed_request("/hello", "192.0.2.55")).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    // From then on the ban stage answers first.
    let (status, body, _) = full_status(app, attributed_request("/hello", "192.0.2.55")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body, BANNED_MESSAGE);
}
