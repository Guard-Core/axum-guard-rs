//! The unified-config consumption, exercised end to end through axum
//! `Router`s (`with_security_config` + `Router::layer` + `oneshot`): the
//! same arms the tower adapter's `from_security_config` twins drive, pinned
//! through the axum surface.

use axum::Router;
use axum::body::Body;
use axum::http::Request;
use axum::routing::get;
use axum_guard_rs::{
    BlockPayload, GuardClientIp, GuardConfigError, RATE_LIMITED_MESSAGE, SecurityConfig,
    with_security_config,
};
use http::StatusCode;
use http_body_util::BodyExt;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

fn guarded(config: &SecurityConfig) -> Router {
    Router::new()
        .route("/hello", get(|| async { "hello" }))
        .route("/docs", get(|| async { "docs" }))
        .layer(with_security_config(config).expect("valid config"))
}

fn request_from(ip: &str, uri: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .extension(GuardClientIp(IpAddr::from_str(ip).expect("test ip")))
        .body(Body::empty())
        .expect("request")
}

async fn status_and_body(config: &SecurityConfig, request: Request<Body>) -> (StatusCode, String) {
    let response = guarded(config).oneshot(request).await.expect("response");
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

async fn config_status_and_body(
    config: &SecurityConfig,
    request: Request<Body>,
) -> (StatusCode, String) {
    status_and_body(config, request).await
}

#[tokio::test]
async fn defaults_screen_clean_traffic() {
    let config = SecurityConfig::default();
    let (status, body) =
        config_status_and_body(&config, request_from("203.0.113.9", "/hello")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "hello");
}

#[tokio::test]
async fn enforce_https_redirects_http() {
    let config = SecurityConfig {
        enforce_https: true,
        ..SecurityConfig::default()
    };
    let (status, body) =
        config_status_and_body(&config, request_from("203.0.113.9", "/hello")).await;
    assert_eq!(status.as_u16(), 301);
    assert!(body.is_empty(), "the reference redirect carries no body");
}

#[tokio::test]
async fn emergency_mode_blocks_outside_the_whitelist() {
    let config = SecurityConfig {
        emergency_mode: true,
        emergency_whitelist: vec![String::from("198.51.100.7")],
        ..SecurityConfig::default()
    };
    let (blocked, _) = config_status_and_body(&config, request_from("203.0.113.9", "/hello")).await;
    assert_eq!(blocked, StatusCode::SERVICE_UNAVAILABLE);
    let (allowed, _) =
        config_status_and_body(&config, request_from("198.51.100.7", "/hello")).await;
    assert_eq!(allowed, StatusCode::OK);
}

#[tokio::test]
async fn blocked_user_agent_answers_the_403() {
    let config = SecurityConfig {
        blocked_user_agents: vec![String::from("bad-bot")],
        ..SecurityConfig::default()
    };
    let mut request = request_from("203.0.113.9", "/hello");
    request
        .headers_mut()
        .insert("user-agent", http::HeaderValue::from_static("bad-bot/1.0"));
    let (blocked, body) = config_status_and_body(&config, request).await;
    assert_eq!(blocked, StatusCode::FORBIDDEN);
    assert_eq!(body, "User-Agent not allowed");

    let (allowed, _) = config_status_and_body(&config, request_from("203.0.113.9", "/hello")).await;
    assert_eq!(allowed, StatusCode::OK);
}

#[tokio::test]
async fn exclude_paths_bypass_the_pipeline() {
    let config = SecurityConfig {
        blacklist: vec![String::from("203.0.113.9")],
        exclude_paths: vec![String::from("/docs")],
        ..SecurityConfig::default()
    };
    // An excluded path bypasses every check, gate included: the
    // blacklisted IP forwards on /docs.
    let (bypassed, body) =
        config_status_and_body(&config, request_from("203.0.113.9", "/docs")).await;
    assert_eq!(bypassed, StatusCode::OK);
    assert_eq!(body, "docs");
    // Any other path takes the gate denial.
    let (blocked, _) = config_status_and_body(&config, request_from("203.0.113.9", "/hello")).await;
    assert_eq!(blocked, StatusCode::FORBIDDEN);
}

#[test]
fn invalid_ip_list_entry_fails_closed() {
    let config = SecurityConfig {
        whitelist: Some(vec![String::from("not-an-ip")]),
        ..SecurityConfig::default()
    };
    let error = with_security_config(&config).unwrap_err();
    assert!(matches!(error, GuardConfigError::IpGate(_)));
}

#[test]
fn invalid_state_fails_closed_before_any_builder_runs() {
    // The reference validate() semantics: a struct-invalid config is
    // refused up front, listing every problem.
    let mut config = SecurityConfig {
        auto_ban_threshold: 0,
        ..SecurityConfig::default()
    };
    let error = config.validate().unwrap_err();
    assert!(
        error
            .problems
            .iter()
            .any(|problem| problem.contains("auto_ban_threshold"))
    );
    config.auto_ban_threshold = 5;
    assert!(config.validate().is_ok());
}

#[tokio::test]
async fn rate_limit_crossing_answers_429_with_retry_after() {
    let config = SecurityConfig {
        rate_limit: 1,
        ..SecurityConfig::default()
    };
    let layer = with_security_config(&config).expect("valid config");
    let router = Router::new()
        .route("/hello", get(|| async { "hello" }))
        .layer(layer);
    let (first, _) = status_body(router.clone(), request_from("203.0.113.9", "/hello")).await;
    assert_eq!(first, StatusCode::OK);
    let (second, body) = status_body(router.clone(), request_from("203.0.113.9", "/hello")).await;
    assert_eq!(second, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body, RATE_LIMITED_MESSAGE);
}

async fn status_body(router: Router, request: Request<Body>) -> (StatusCode, String) {
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

#[tokio::test]
async fn custom_error_responses_render_on_the_gate_denial() {
    let config = SecurityConfig {
        blacklist: vec![String::from("203.0.113.9")],
        custom_error_responses: {
            let mut map = std::collections::BTreeMap::new();
            map.insert(403, String::from("custom-forbidden"));
            map
        },
        ..SecurityConfig::default()
    };
    let (status, body) =
        config_status_and_body(&config, request_from("203.0.113.9", "/hello")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    // The custom-error body override wins over the family default.
    assert_eq!(body, "custom-forbidden");
}

#[tokio::test]
async fn ip_gate_denial_fires_the_on_block_hook_with_the_reference_keys() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&seen);
    let config = SecurityConfig {
        blacklist: vec![String::from("203.0.113.9")],
        on_block: Some(Arc::new(move |payload: &BlockPayload| {
            sink.lock()
                .expect("sink")
                .push((payload.check_name.clone(), payload.status_code));
        })),
        ..SecurityConfig::default()
    };
    let (status, _) = config_status_and_body(&config, request_from("203.0.113.9", "/hello")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let seen = seen.lock().expect("sink");
    assert!(
        seen.iter()
            .any(|(check, status)| check == "ip_security" && *status == Some(403)),
        "the reference on_block hook fires once with the ip_security keys: {seen:?}"
    );
}

#[tokio::test]
async fn ip_gate_denial_under_passive_mode_logs_and_forwards() {
    let config = SecurityConfig {
        passive_mode: true,
        blacklist: vec![String::from("203.0.113.9")],
        ..SecurityConfig::default()
    };
    let (status, _) = config_status_and_body(&config, request_from("203.0.113.9", "/hello")).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn security_headers_render_on_forwarded_responses() {
    let config = SecurityConfig::default();
    let response = guarded(&config)
        .oneshot(request_from("203.0.113.9", "/hello"))
        .await
        .expect("response");
    assert_eq!(
        response.headers().get("x-content-type-options"),
        Some(&http::HeaderValue::from_static("nosniff"))
    );
}

#[tokio::test]
async fn cors_config_enables_the_cors_response_headers() {
    let config = SecurityConfig {
        enable_cors: true,
        cors_allow_origins: vec![String::from("https://app.test")],
        ..SecurityConfig::default()
    };
    let mut request = request_from("203.0.113.9", "/hello");
    request
        .headers_mut()
        .insert("origin", http::HeaderValue::from_static("https://app.test"));
    let response = guarded(&config).oneshot(request).await.expect("response");
    assert_eq!(
        response.headers().get("access-control-allow-origin"),
        Some(&http::HeaderValue::from_static("https://app.test"))
    );
}

#[tokio::test]
async fn disabled_rate_limiting_forwards_freely() {
    let config = SecurityConfig {
        enable_rate_limiting: false,
        rate_limit: 1,
        ..SecurityConfig::default()
    };
    let layer = with_security_config(&config).expect("valid config");
    let router = Router::new()
        .route("/hello", get(|| async { "hello" }))
        .layer(layer);
    for _ in 0..3 {
        let (status, _) = status_body(router.clone(), request_from("203.0.113.9", "/hello")).await;
        assert_eq!(status, StatusCode::OK);
    }
}

#[test]
fn zero_rate_limit_fails_closed() {
    let config = SecurityConfig {
        rate_limit: 0,
        ..SecurityConfig::default()
    };
    let error = with_security_config(&config).unwrap_err();
    assert!(matches!(error, GuardConfigError::RateLimit(_)));
}

#[tokio::test]
async fn disabled_ip_banning_still_screens_through_the_gate() {
    let config = SecurityConfig {
        enable_ip_banning: false,
        blacklist: vec![String::from("203.0.113.9")],
        ..SecurityConfig::default()
    };
    let (status, _) = config_status_and_body(&config, request_from("203.0.113.9", "/hello")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn detection_exclusions_and_categories_reach_the_scan() {
    let config = SecurityConfig {
        enabled_detection_categories: {
            let mut set = std::collections::BTreeSet::new();
            set.insert(String::from("xss"));
            set
        },
        excluded_detection_params: {
            let mut set = std::collections::BTreeSet::new();
            set.insert(String::from("q"));
            set
        },
        detection_scan_body: false,
        ..SecurityConfig::default()
    };
    // The sqli category is disabled by the enabled-categories override:
    // the sqli probe forwards.
    let (status, _) = config_status_and_body(
        &config,
        request_from("203.0.113.9", "/hello?q=1%27+OR+1%3D1"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[test]
fn reexported_error_display_names_the_engine_surface() {
    let config = SecurityConfig {
        whitelist: Some(vec![String::from("nope")]),
        ..SecurityConfig::default()
    };
    let error = with_security_config(&config).unwrap_err();
    let rendered = error.to_string();
    assert!(rendered.contains("ip list"), "{rendered}");
    assert!(std::error::Error::source(&error).is_some());
}
