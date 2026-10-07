//! The route-config carrier consumption, exercised end to end through axum
//! `Router`s: the tower `with_route_configs` pipeline consumption pinned
//! through the axum surface (resolver + extension precedence, the bypass
//! semantics, `require_https`, the per-route size cap and UA list, the
//! route rate tier).

use axum::Router;
use axum::body::Body;
use axum::http::Request;
use axum::routing::get;
use axum_guard_rs::{GuardClientIp, GuardLayer, RouteConfig, with_guard};
use http::StatusCode;
use http_body_util::BodyExt;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use tower::ServiceExt;

fn resolver_for(paths: &[(&str, &str)], config: RouteConfig) -> axum_guard_rs::RouteConfigResolver {
    let owned: Vec<(String, String)> = paths
        .iter()
        .map(|(method, path)| ((*method).to_owned(), (*path).to_owned()))
        .collect();
    Arc::new(move |method, path| {
        owned
            .iter()
            .any(|(route_method, route_path)| route_method == method && route_path == path)
            .then(|| Arc::new(config.clone()))
    })
}

fn guarded(layer: GuardLayer) -> Router {
    Router::new()
        .route("/hello", get(|| async { "hello" }))
        .route("/open", get(|| async { "open" }))
        .route("/tls", get(|| async { "tls" }))
        .layer(layer)
}

async fn status_for(router: Router, request: Request<Body>) -> (StatusCode, String) {
    let response = router.oneshot(request).await.expect("response");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let body = String::from_utf8_lossy(&bytes).into_owned();
    (status, body)
}

fn request_from(ip: &str, uri: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .extension(GuardClientIp(IpAddr::from_str(ip).expect("test ip")))
        .body(Body::empty())
        .expect("request")
}

#[tokio::test]
async fn the_route_bypass_skips_the_scan_for_its_path_only() {
    let config = RouteConfig {
        bypassed_checks: {
            let mut set = std::collections::BTreeSet::new();
            set.insert(String::from("penetration"));
            set
        },
        ..RouteConfig::default()
    };
    let layer = with_guard(axum_guard_rs::default_config())
        .with_route_configs(resolver_for(&[("GET", "/open")], config));
    // The sqli probe on the bypassed route forwards; next door it is 400.
    let (open, _) = status_for(
        guarded(layer.clone()),
        request_from("203.0.113.9", "/open?q=1%27+OR+1%3D1"),
    )
    .await;
    assert_eq!(open, StatusCode::OK);
    let (blocked, _) = status_for(
        guarded(layer),
        request_from("203.0.113.9", "/hello?q=1%27+OR+1%3D1"),
    )
    .await;
    assert_eq!(blocked, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn route_require_https_forces_the_redirect() {
    let config = RouteConfig {
        require_https: true,
        ..RouteConfig::default()
    };
    let layer = with_guard(axum_guard_rs::default_config())
        .with_route_configs(resolver_for(&[("GET", "/tls")], config));
    let mut request = request_from("203.0.113.9", "/tls");
    request
        .headers_mut()
        .insert("host", http::HeaderValue::from_static("guard.example"));
    let (status, _) = status_for(guarded(layer), request).await;
    assert_eq!(status.as_u16(), 301);
}

#[tokio::test]
async fn the_route_rate_view_becomes_the_tier_through_the_router() {
    let config = RouteConfig {
        rate_limit: Some(1),
        rate_limit_window: Some(60),
        ..RouteConfig::default()
    };
    let limiter = axum_guard_rs::RateLimiter::new(axum_guard_rs::RateLimitConfig {
        enable_rate_limiting: true,
        rate_limit: 1000,
        rate_limit_window: 60,
        ..axum_guard_rs::RateLimitConfig::default()
    })
    .expect("valid config");
    let layer = with_guard(axum_guard_rs::default_config())
        .with_rate_limiting(limiter)
        .with_route_configs(resolver_for(&[("GET", "/hello")], config));
    let router = guarded(layer);
    let (first, _) = status_for(router.clone(), request_from("203.0.113.9", "/hello")).await;
    assert_eq!(first, StatusCode::OK);
    let (second, body) = status_for(router.clone(), request_from("203.0.113.9", "/hello")).await;
    assert_eq!(second, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body, "Too many requests");
}

#[tokio::test]
async fn the_carrier_extension_wins_over_the_resolver_through_the_router() {
    let config = RouteConfig {
        rate_limit: Some(1),
        rate_limit_window: Some(60),
        ..RouteConfig::default()
    };
    let limiter = axum_guard_rs::RateLimiter::new(axum_guard_rs::RateLimitConfig {
        enable_rate_limiting: true,
        rate_limit: 1000,
        rate_limit_window: 60,
        ..axum_guard_rs::RateLimitConfig::default()
    })
    .expect("valid config");
    let layer = with_guard(axum_guard_rs::default_config())
        .with_rate_limiting(limiter)
        .with_route_configs(resolver_for(&[("GET", "/hello")], config));
    // The per-route extension carries no tier: the resolver's 1-request
    // tier never applies.
    let mut request = request_from("203.0.113.9", "/hello");
    request
        .extensions_mut()
        .insert(Arc::new(RouteConfig::default()));
    let (first, _) = status_for(guarded(layer.clone()), request).await;
    assert_eq!(first, StatusCode::OK);
    let (second, _) = status_for(guarded(layer), request_from("203.0.113.9", "/hello")).await;
    assert_eq!(second, StatusCode::OK);
}

#[tokio::test]
async fn route_blocked_user_agents_answer_the_403_through_the_router() {
    let config = RouteConfig {
        blocked_user_agents: vec![String::from("route-bot")],
        ..RouteConfig::default()
    };
    let layer = with_guard(axum_guard_rs::default_config())
        .with_route_configs(resolver_for(&[("GET", "/hello")], config));
    let mut request = request_from("203.0.113.9", "/hello");
    request.headers_mut().insert(
        "user-agent",
        http::HeaderValue::from_static("route-bot/2.0"),
    );
    let (status, body) = status_for(guarded(layer), request).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body, "User-Agent not allowed");
}

#[tokio::test]
async fn an_invalid_carrier_tier_fails_secure_through_the_router() {
    let config = RouteConfig {
        rate_limit: Some(0),
        ..RouteConfig::default()
    };
    let layer = with_guard(axum_guard_rs::default_config())
        .with_route_configs(resolver_for(&[("GET", "/hello")], config));
    let (status, _) = status_for(guarded(layer), request_from("203.0.113.9", "/hello")).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}
