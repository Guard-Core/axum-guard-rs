//! The `security_headers_applied` funnel through the axum idiom: the
//! funnel lands in the tower `GuardLayer`'s response pass (the H6 tower
//! leg), and these twins pin the axum-facing contract end to end - a
//! `Router` layered with `with_guard`, the bus installed through
//! `GuardLayer::with_event_bus`, the event's metadata, count, and
//! CSP/HSTS flags, and the silences (the generated lane, a disabled set).

use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::Request;
use axum::routing::get;
use axum_guard_rs::{
    IpBanManager, RateLimitConfig, RateLimiter, ResponseProcessor, SecurityEventBus,
    SecurityHeadersConfig, client_ip_layer, default_config, with_guard,
};
use guard_core_engine::behavior::{BehaviorTracker, DEFAULT_MAX_RESPONSE_BODY_INSPECT_BYTES};
use http::StatusCode;
use http_body_util::BodyExt;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

type EventLog = Arc<Mutex<Vec<guard_core_rs::events::SecurityEvent>>>;

fn recording_bus(sink: EventLog) -> Arc<SecurityEventBus> {
    Arc::new(SecurityEventBus::new(true).on_event(Arc::new(move |event| {
        sink.lock().expect("events").push(event.clone());
    })))
}

fn bare_processor() -> ResponseProcessor {
    ResponseProcessor::new(
        Some(SecurityHeadersConfig::reference_default()),
        None,
        Vec::new(),
        Arc::new(Mutex::new(BehaviorTracker::new())),
        IpBanManager::new(),
        false,
        DEFAULT_MAX_RESPONSE_BODY_INSPECT_BYTES,
        false,
    )
}

fn limiter(limit: u32) -> RateLimiter {
    RateLimiter::new(RateLimitConfig {
        enable_rate_limiting: true,
        rate_limit: limit,
        rate_limit_window: 60,
        ..RateLimitConfig::default()
    })
    .expect("valid limiter")
}

fn router(layer: axum_guard_rs::GuardLayer) -> Router {
    Router::new()
        .route("/hello", get(|| async { "hello" }))
        .layer(layer)
        .layer(client_ip_layer())
}

fn attributed_request(uri: &str, ip: &str) -> Request<Body> {
    let peer = SocketAddr::new(IpAddr::from_str(ip).expect("test ip"), 45_000);
    Request::builder()
        .uri(uri)
        .extension(ConnectInfo(peer))
        .body(Body::empty())
        .expect("request")
}

async fn dispatch(
    app: Router,
    request: Request<Body>,
) -> (StatusCode, axum::http::HeaderMap, String) {
    let response = app.oneshot(request).await.expect("response");
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    (
        status,
        headers,
        String::from_utf8_lossy(&bytes).into_owned(),
    )
}

#[tokio::test]
async fn the_forwarded_router_response_dispatches_the_headers_applied_event() {
    let events: EventLog = Arc::new(Mutex::new(Vec::new()));
    let layer = with_guard(default_config())
        .with_response_processor(bare_processor())
        .with_event_bus(recording_bus(Arc::clone(&events)));
    let (status, headers, _) =
        dispatch(router(layer), attributed_request("/hello", "192.0.2.94")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers
            .get("x-content-type-options")
            .map(|value| value.to_str().expect("ascii")),
        Some("nosniff"),
        "the header set lands on the response"
    );
    let events = events.lock().expect("events");
    let applied: Vec<&guard_core_rs::events::SecurityEvent> = events
        .iter()
        .filter(|event| event.event_type == "security_headers_applied")
        .collect();
    assert_eq!(
        applied.len(),
        1,
        "one event per forwarded response: {events:?}"
    );
    let event = applied[0];
    assert_eq!(event.action_taken, "headers_added");
    assert_eq!(event.handler_name.as_deref(), Some("security_headers"));
    assert_eq!(event.metadata["path"].as_str(), Some("/hello"));
    // The count is the rendered security-header set (the reference
    // default carries HSTS and no CSP).
    let set = guard_core_engine::security_headers::security_headers(
        &SecurityHeadersConfig::reference_default(),
    );
    assert_eq!(
        event.metadata["headers_count"].as_u64(),
        Some(set.len() as u64)
    );
    assert_eq!(event.metadata["has_csp"].as_bool(), Some(false));
    assert_eq!(event.metadata["has_hsts"].as_bool(), Some(true));
}

#[tokio::test]
async fn the_generated_lane_applies_headers_without_the_event() {
    // A guard block answers with the security-header set (the reference
    // `create_error_response` applies the headers) but fires no event:
    // that lane passes no request path. The first (forwarded) request
    // pins the positive control: the bus is wired and the funnel fired
    // exactly once for it.
    let events: EventLog = Arc::new(Mutex::new(Vec::new()));
    let layer = with_guard(default_config())
        .with_response_processor(bare_processor())
        .with_event_bus(recording_bus(Arc::clone(&events)));
    let app = router(layer);
    let (status, _, _) = dispatch(app.clone(), attributed_request("/hello", "192.0.2.95")).await;
    assert_eq!(status, StatusCode::OK);
    let (status, headers, _) = dispatch(
        app,
        attributed_request("/hello?cmd=$(whoami)", "192.0.2.95"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        headers
            .get("x-content-type-options")
            .map(|value| value.to_str().expect("ascii")),
        Some("nosniff"),
        "the block still carries the security-header set"
    );
    let events = events.lock().expect("events");
    let applied: Vec<&guard_core_rs::events::SecurityEvent> = events
        .iter()
        .filter(|event| event.event_type == "security_headers_applied")
        .collect();
    assert_eq!(
        applied.len(),
        1,
        "the forwarded request fired once and the block stayed silent: {applied:?}"
    );
    assert_eq!(applied[0].metadata["path"].as_str(), Some("/hello"));
}

#[tokio::test]
async fn a_disabled_security_header_set_stays_silent() {
    // The reference fires the event from `get_headers` behind the
    // `enabled` gate: a disabled set renders no headers and dispatches
    // nothing, even with a bus installed. The rate-limit crossing is the
    // positive control: the bus is wired and carries the limiter's event,
    // and nothing else.
    let events: EventLog = Arc::new(Mutex::new(Vec::new()));
    let disabled = ResponseProcessor::new(
        Some(SecurityHeadersConfig {
            enabled: false,
            ..SecurityHeadersConfig::reference_default()
        }),
        None,
        Vec::new(),
        Arc::new(Mutex::new(BehaviorTracker::new())),
        IpBanManager::new(),
        false,
        DEFAULT_MAX_RESPONSE_BODY_INSPECT_BYTES,
        false,
    );
    let layer = with_guard(default_config())
        .with_response_processor(disabled)
        .with_rate_limiting(limiter(1))
        .with_event_bus(recording_bus(Arc::clone(&events)));
    let app = router(layer);
    let (status, headers, _) =
        dispatch(app.clone(), attributed_request("/hello", "192.0.2.96")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers.get("x-content-type-options"),
        None,
        "a disabled set renders no headers"
    );
    let (status, _, _) = dispatch(app, attributed_request("/hello", "192.0.2.96")).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "the control fires");
    let events = events.lock().expect("events");
    let applied: Vec<&guard_core_rs::events::SecurityEvent> = events
        .iter()
        .filter(|event| event.event_type == "security_headers_applied")
        .collect();
    assert_eq!(applied.len(), 0, "a disabled set stays silent: {applied:?}");
    assert_eq!(
        events.len(),
        1,
        "only the limiter's control event: {events:?}"
    );
    assert_eq!(events[0].event_type, "rate_limited");
}
