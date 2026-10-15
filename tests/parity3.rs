//! Reference parity, third pass, through the axum surface: the usage-rule
//! order, rule-driven config changes, `route_resolution_strict` with the
//! route-resolution layer, the `body_read_timeout` timer and the config
//! validation.

use axum::Router;
use axum::body::Body;
use axum::http::Request;
use axum::routing::{get, post};
use axum_guard_rs::{
    BehaviorRule, GuardClientIp, GuardConfigError, GuardLayer, IpBanManager, ResponseProcessor,
    RouteConfig, SecurityConfig, Wiring, route_resolution_layer, with_security_config,
};
use bytes::Bytes;
use http::StatusCode;
use http_body_util::BodyExt;
use std::convert::Infallible;
use std::net::IpAddr;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::{Arc, Mutex, RwLock};
use std::task::{Context, Poll};
use tower::ServiceExt;

fn config() -> SecurityConfig {
    SecurityConfig {
        enable_redis: false,
        ..SecurityConfig::default()
    }
}

async fn send(router: Router, request: Request<Body>) -> (StatusCode, String) {
    let response = router.oneshot(request).await.expect("response");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

fn request_at(uri: &str, ip: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .extension(GuardClientIp(IpAddr::from_str(ip).expect("test ip")))
        .body(Body::empty())
        .expect("request")
}

fn app(layer: GuardLayer) -> Router {
    Router::new()
        .route("/api", get(|| async { "api" }))
        .route("/hello", get(|| async { "hello" }))
        .layer(layer)
}

#[tokio::test]
async fn usage_rules_run_after_the_pipeline() {
    let route = RouteConfig {
        behavior_rules: vec![BehaviorRule {
            rule_type: String::from("usage"),
            threshold: 2,
            window: 60,
            pattern: String::new(),
            action: String::from("ban"),
            ban_duration: Some(3600),
            correlate_with_detection: false,
        }],
        ..RouteConfig::default()
    };
    let resolver: axum_guard_rs::RouteConfigResolver = Arc::new(move |method, path| {
        (method == "GET" && path == "/api").then(|| Arc::new(route.clone()))
    });
    let processor = ResponseProcessor::new(
        None,
        None,
        Vec::new(),
        Arc::new(Mutex::new(axum_guard_rs_behavior_tracker())),
        IpBanManager::new(),
        true,
        262_144,
        false,
    );
    let layer = GuardLayer::new(axum_guard_rs::default_config())
        .with_response_processor(processor)
        .with_route_configs(resolver);
    let router = app(layer);
    for _ in 0..3 {
        let (status, _) = send(
            router.clone(),
            request_at("/api?cmd=$(whoami)", "192.0.2.81"),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
    let (status, body) = send(router, request_at("/api", "192.0.2.81")).await;
    assert_eq!((status, body.as_str()), (StatusCode::OK, "api"));
}

fn axum_guard_rs_behavior_tracker() -> guard_core_engine::behavior::BehaviorTracker {
    guard_core_engine::behavior::BehaviorTracker::new()
}

#[tokio::test]
async fn a_rate_limit_rule_reaches_the_router() {
    let mut config = config();
    config.enable_rate_limiting = true;
    config.rate_limit = 1;
    config.rate_limit_window = 60;
    let wiring = Wiring::from_security_config(&config).expect("wired");
    let live: Arc<RwLock<SecurityConfig>> = Arc::clone(&wiring.live_config);
    let router = app(GuardLayer::from_wiring(wiring));
    let (first, _) = send(router.clone(), request_at("/hello", "192.0.2.91")).await;
    assert_eq!(first, StatusCode::OK);
    let (second, _) = send(router.clone(), request_at("/hello", "192.0.2.91")).await;
    assert_eq!(second, StatusCode::TOO_MANY_REQUESTS);
    live.write().expect("live config").rate_limit = 100;
    let (third, _) = send(router, request_at("/hello", "192.0.2.91")).await;
    assert_eq!(third, StatusCode::OK);
}

#[tokio::test]
async fn strict_route_resolution_refuses_a_path_axum_cannot_route() {
    let strict = SecurityConfig {
        route_resolution_strict: true,
        ..config()
    };
    let router = Router::new()
        .route("/hello", get(|| async { "hello" }))
        .layer(with_security_config(&strict).expect("layer"))
        .layer(route_resolution_layer());
    let (status, body) = send(router.clone(), request_at("/hello", "192.0.2.61")).await;
    assert_eq!((status, body.as_str()), (StatusCode::OK, "hello"));
    let (status, body) = send(router, request_at("/nowhere", "192.0.2.61")).await;
    assert_eq!(
        (status, body.as_str()),
        (StatusCode::INTERNAL_SERVER_ERROR, "Route resolution failed")
    );

    // The default (not strict) lets the same path reach axum's 404.
    let router = Router::new()
        .route("/hello", get(|| async { "hello" }))
        .layer(with_security_config(&config()).expect("layer"))
        .layer(route_resolution_layer());
    let (status, _) = send(router, request_at("/nowhere", "192.0.2.61")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// A request body that never delivers a frame.
struct Stalled;

impl http_body::Body for Stalled {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Bytes>, Infallible>>> {
        Poll::Pending
    }
}

#[tokio::test]
async fn a_stalled_upload_is_answered_408_after_body_read_timeout() {
    let config = SecurityConfig {
        body_read_timeout: 0.05,
        ..config()
    };
    let router = Router::new()
        .route("/upload", post(|| async { "ok" }))
        .layer(with_security_config(&config).expect("layer"));
    let request = Request::builder()
        .method("POST")
        .uri("/upload")
        .extension(GuardClientIp(IpAddr::from_str("192.0.2.71").expect("ip")))
        .body(Body::new(Stalled))
        .expect("request");
    let (status, body) = send(router, request).await;
    assert_eq!(
        (status, body.as_str()),
        (StatusCode::REQUEST_TIMEOUT, "Request body read timed out")
    );
}

#[test]
fn the_config_is_validated_before_the_layer_is_built() {
    let config = SecurityConfig {
        auto_ban_threshold: 0,
        ..config()
    };
    let error = with_security_config(&config).expect_err("rejected");
    assert!(matches!(error, GuardConfigError::Config(_)));
}
