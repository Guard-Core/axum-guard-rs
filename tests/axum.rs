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
