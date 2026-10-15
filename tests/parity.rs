//! Reference-parity surface through the axum adapter: the re-exported tower
//! wiring surface, `with_security_config_with`, the scoped exclusion and
//! client resolution behavior a `Router` inherits, the websocket client
//! policy and the status route fed from the wiring.

use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::Request;
use axum::routing::get;
use axum_guard_rs::status::GuardStatus;
use axum_guard_rs::websocket::{
    WS_CLOSE_CLIENT_ADDRESS_UNKNOWN, WS_CLOSE_IP_NOT_ALLOWED, WebSocketGuard, WebSocketGuardConfig,
};
use axum_guard_rs::{
    ClientPolicy, CompositeAgentHandler, GuardExclusionScoped, IpGateConfig, PathExclusions,
    SecurityConfig, SecurityEvent, TelemetryError, TelemetryHandler, Wiring, WiringError,
    WiringOptions, client_ip_layer, default_config, with_security_config,
    with_security_config_with,
};
use http::StatusCode;
use std::net::SocketAddr;
use std::sync::Arc;
use tower::ServiceExt;

struct Sink;

impl TelemetryHandler for Sink {
    fn handler_name(&self) -> &'static str {
        "sink"
    }
    fn start(&self) -> Result<(), TelemetryError> {
        Ok(())
    }
    fn stop(&self) -> Result<(), TelemetryError> {
        Ok(())
    }
    fn send_event(&self, _event: &SecurityEvent) -> Result<(), TelemetryError> {
        Ok(())
    }
    fn send_metric(&self, _metric: &axum_guard_rs::SecurityMetric) -> Result<(), TelemetryError> {
        Ok(())
    }
    fn get_dynamic_rules(&self) -> Result<Option<serde_json::Value>, TelemetryError> {
        Ok(None)
    }
    fn health_check(&self) -> bool {
        true
    }
}

fn app(config: &SecurityConfig) -> Router {
    Router::new()
        .route("/static/app.js", get(|| async { "js" }))
        .route("/hello", get(|| async { "hello" }))
        .layer(with_security_config(config).expect("valid config"))
        .layer(client_ip_layer())
}

fn from_peer(uri: &str, peer: &str) -> Request<Body> {
    let addr: SocketAddr = format!("{peer}:45000").parse().expect("addr");
    Request::builder()
        .uri(uri)
        .extension(ConnectInfo(addr))
        .body(Body::empty())
        .expect("request")
}

fn no_peer(uri: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .body(Body::empty())
        .expect("request")
}

#[tokio::test]
async fn excluded_paths_still_hit_the_global_ip_gate() {
    let config = SecurityConfig {
        blacklist: vec![String::from("203.0.113.9")],
        exclude_paths: vec![String::from("/static")],
        ..SecurityConfig::default()
    };
    let blocked = app(&config)
        .oneshot(from_peer("/static/app.js", "203.0.113.9"))
        .await
        .expect("response");
    assert_eq!(blocked.status(), StatusCode::FORBIDDEN);
    let allowed = app(&config)
        .oneshot(from_peer("/static/app.js", "198.51.100.7"))
        .await
        .expect("response");
    assert_eq!(allowed.status(), StatusCode::OK);
}

#[tokio::test]
async fn a_request_without_a_peer_is_refused_under_fail_secure() {
    let config = SecurityConfig::default();
    let response = app(&config)
        .oneshot(no_peer("/hello"))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn excluded_path_without_a_peer_continues_scoped() {
    let config = SecurityConfig {
        exclude_paths: vec![String::from("/static")],
        ..SecurityConfig::default()
    };
    let response = app(&config)
        .oneshot(no_peer("/static/app.js"))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn trusted_proxy_forwarded_client_is_the_identity() {
    let config = SecurityConfig {
        blacklist: vec![String::from("203.0.113.9")],
        trusted_proxies: vec![String::from("10.0.0.0/8")],
        ..SecurityConfig::default()
    };
    let mut request = from_peer("/hello", "10.0.0.1");
    request
        .headers_mut()
        .insert("x-forwarded-for", "203.0.113.9".parse().expect("header"));
    let response = app(&config).oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[test]
fn the_wiring_surface_is_reexported() {
    let _ = GuardExclusionScoped;
    assert!(PathExclusions::new(["/static"]).is_excluded("/static/app.js"));
    let layer = with_security_config_with(
        &SecurityConfig::default(),
        &WiringOptions {
            agent: Some(Arc::new(Sink)),
            logfire_client: None,
        },
    )
    .expect("valid config");
    assert!(layer.agent_stats().enabled);
    assert!(
        !with_security_config(&SecurityConfig::default())
            .expect("valid")
            .agent_stats()
            .enabled
    );
    let wiring = Wiring::from_security_config(&SecurityConfig::default()).expect("wiring");
    assert!(wiring.client.fail_secure);
    let _: Option<Arc<CompositeAgentHandler>> = wiring.telemetry;
    let bad = SecurityConfig {
        whitelist: Some(vec![String::from("nope")]),
        ..SecurityConfig::default()
    };
    assert!(matches!(
        Wiring::from_security_config(&bad),
        Err(WiringError::IpGate(_))
    ));
}

// --- websocket client policy ---

fn ws_upgrade(peer: &str, forwarded: Option<&str>) -> Request<Body> {
    let mut request = from_peer("/ws", peer);
    request
        .headers_mut()
        .insert("upgrade", "websocket".parse().expect("header"));
    request
        .headers_mut()
        .insert("connection", "Upgrade".parse().expect("header"));
    if let Some(forwarded) = forwarded {
        request
            .headers_mut()
            .insert("x-forwarded-for", forwarded.parse().expect("header"));
    }
    request
}

fn ws_app(config: WebSocketGuardConfig) -> Router {
    Router::new()
        .route("/ws", get(|| async { "upgraded" }))
        .layer(WebSocketGuard::new(config))
}

fn ws_gate() -> IpGateConfig {
    IpGateConfig::new([] as [&str; 0], ["203.0.113.9"], [] as [&str; 0]).expect("lists")
}

#[tokio::test]
async fn websocket_resolves_the_forwarded_client_through_the_policy() {
    let policy = ClientPolicy {
        trusted_proxies: vec![String::from("10.0.0.0/8")],
        trusted_proxy_depth: 1,
        fail_secure: true,
    };
    let config = WebSocketGuardConfig::new(default_config())
        .with_ip_gate(ws_gate())
        .with_client_policy(policy);
    let blocked = ws_app(config.clone())
        .oneshot(ws_upgrade("10.0.0.1", Some("203.0.113.9")))
        .await
        .expect("response");
    assert_eq!(blocked.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        blocked
            .headers()
            .get("x-guard-websocket-close-reason")
            .and_then(|value| value.to_str().ok()),
        Some(WS_CLOSE_IP_NOT_ALLOWED.reason)
    );
    // An untrusted peer's header is ignored: the peer itself is the identity.
    let allowed = ws_app(config)
        .oneshot(ws_upgrade("198.51.100.7", Some("203.0.113.9")))
        .await
        .expect("response");
    assert_eq!(allowed.status(), StatusCode::OK);
}

#[tokio::test]
async fn websocket_policy_fail_secure_refuses_an_unknown_peer() {
    let policy = ClientPolicy {
        trusted_proxies: Vec::new(),
        trusted_proxy_depth: 1,
        fail_secure: true,
    };
    let config = WebSocketGuardConfig::new(default_config()).with_client_policy(policy);
    let mut request = no_peer("/ws");
    request
        .headers_mut()
        .insert("upgrade", "websocket".parse().expect("header"));
    request
        .headers_mut()
        .insert("connection", "Upgrade".parse().expect("header"));
    let response = ws_app(config).oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response
            .headers()
            .get("x-guard-websocket-close-reason")
            .and_then(|value| value.to_str().ok()),
        Some(WS_CLOSE_CLIENT_ADDRESS_UNKNOWN.reason)
    );
}

// --- the status route fed from the wiring ---

#[test]
fn status_reflects_the_wiring_cloud_table_and_geo() {
    let config = SecurityConfig {
        block_cloud_providers: Some(["AWS".to_owned()].into_iter().collect()),
        ..SecurityConfig::default()
    };
    let wiring = Wiring::from_security_config(&config).expect("wiring");
    let refresh = wiring.cloud_refresh.as_ref().expect("cloud refresh");
    refresh
        .table
        .set_provider_ranges("AWS", vec![("203.0.113.0/24".to_owned(), None)])
        .expect("ranges");
    let payload = GuardStatus::from_wiring(&wiring).payload();
    assert!(
        payload.contains(r#""AWS":{"ready":true,"last_refreshed":"#),
        "{payload}"
    );
    let plain = Wiring::from_security_config(&SecurityConfig::default()).expect("wiring");
    assert!(
        GuardStatus::from_wiring(&plain)
            .payload()
            .contains(r#""geo_ip":null"#)
    );
}
