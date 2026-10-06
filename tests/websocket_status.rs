//! End-to-end pin of the websocket guard and status route surface, driven
//! from outside the crate the way an application consumes it: the upgrade
//! sequence through a `Router`, the pre-accept rejection shapes, and the
//! status route's payload.

use axum::Router;
use axum::body::Body;
use axum::extract::{ConnectInfo, Request};
use axum::http::StatusCode;
use axum::routing::get;
use axum_guard_rs::status::{GuardStatus, status_router};
use axum_guard_rs::websocket::{
    WS_CLOSE_RATE_LIMIT_EXCEEDED, is_websocket_upgrade, websocket_close_for_status, websocket_guard,
};
use axum_guard_rs::{
    IpBanManager, RateLimitConfig, RateLimiter, default_config, websocket::WebSocketGuard,
    websocket::WebSocketGuardConfig,
};
use guard_core_engine::cloud_provider::CloudIpTable;
use std::net::SocketAddr;
use tower::ServiceExt;

fn peer(ip: &str) -> SocketAddr {
    format!("{ip}:41000").parse().expect("addr")
}

fn upgrade_request(addr: SocketAddr) -> Request {
    let mut request = Request::builder()
        .uri("/ws")
        .header("Upgrade", "websocket")
        .header("Connection", "Upgrade")
        .body(Body::empty())
        .expect("request");
    request.extensions_mut().insert(ConnectInfo(addr));
    request
}

/// The route handler the clean and blocked upgrade tests share: one fn
/// item, one routing instantiation, exercised by the clean test (the
/// blocked test's handshake is rejected before dispatch).
async fn upgraded() -> &'static str {
    "upgraded"
}

#[tokio::test]
async fn blocked_handshake_is_rejected_with_the_close_shape() {
    let manager = IpBanManager::new();
    let ip = peer("203.0.113.9").ip();
    manager.ban_ip(ip, 60, "parity test").expect("ban");
    let config = WebSocketGuardConfig::new(default_config()).with_ip_banning(manager);
    let app: Router = Router::new()
        .route("/ws", get(upgraded))
        .layer(websocket_guard(config));
    let response = app
        .oneshot(upgrade_request(peer("203.0.113.9")))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response
            .headers()
            .get("x-guard-websocket-close")
            .and_then(|value| value.to_str().ok()),
        Some("1008")
    );
    assert_eq!(
        response
            .headers()
            .get("x-guard-websocket-close-reason")
            .and_then(|value| value.to_str().ok()),
        Some("IP banned")
    );
}

#[tokio::test]
async fn rate_limited_handshake_carries_the_rate_limit_close() {
    let limiter = RateLimiter::new(RateLimitConfig {
        enable_rate_limiting: true,
        rate_limit: 1,
        rate_limit_window: 10,
        ..RateLimitConfig::default()
    })
    .expect("valid config");
    let config = WebSocketGuardConfig::new(default_config()).with_rate_limiting(limiter);
    let app: Router = Router::new()
        .route("/ws", get(upgraded))
        .layer(WebSocketGuard::new(config));
    // First upgrade passes; the second crosses the window.
    let first = app
        .clone()
        .oneshot(upgrade_request(peer("203.0.113.7")))
        .await
        .expect("response");
    assert_eq!(first.status(), StatusCode::OK);
    let second = app
        .oneshot(upgrade_request(peer("203.0.113.7")))
        .await
        .expect("response");
    assert_eq!(second.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        second
            .headers()
            .get("x-guard-websocket-close")
            .and_then(|value| value.to_str().ok()),
        Some("1008")
    );
    assert_eq!(
        second
            .headers()
            .get("x-guard-websocket-close-reason")
            .and_then(|value| value.to_str().ok()),
        Some("Rate limit exceeded")
    );
}

#[tokio::test]
async fn status_route_serves_the_snapshot_next_to_the_guard() {
    let table = CloudIpTable::default();
    table
        .set_provider_ranges("AWS", vec![("203.0.113.0/24".to_owned(), None)])
        .expect("valid ranges");
    let app: Router = Router::new()
        .route("/ws", get(upgraded))
        .layer(WebSocketGuard::new(WebSocketGuardConfig::new(
            default_config(),
        )))
        .merge(status_router(
            GuardStatus::new()
                .with_cloud_table(table)
                .with_geo_configured(true),
        ));
    let response = app
        .oneshot(
            Request::builder()
                .uri("/_guard/status")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(response.into_body())
        .await
        .expect("body")
        .to_bytes();
    let payload = String::from_utf8_lossy(&body);
    assert!(payload.contains(r#""AWS":{"ready":true}"#));
    assert!(payload.contains(r#""geo_ip":{"configured":true}"#));
}

#[test]
fn the_surface_helpers_stay_reachable_from_outside_the_crate() {
    let request = Request::builder()
        .uri("/ws")
        .header("Upgrade", "websocket")
        .header("Connection", "keep-alive")
        .body(())
        .expect("request");
    // A Connection without the upgrade token is not a handshake.
    assert!(!is_websocket_upgrade(&request));
    assert_eq!(
        websocket_close_for_status(429, "Too many requests"),
        WS_CLOSE_RATE_LIMIT_EXCEEDED
    );
}
