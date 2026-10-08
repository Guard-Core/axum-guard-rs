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

// --- the carrier's stage knobs (the RC1 axum leg): the tower pipeline's
// carrier lanes pinned through the axum surface, one matching-route twin
// and its off-route silence per knob ---

fn request_with_headers(ip: &str, uri: &str, headers: &[(&str, &str)]) -> Request<Body> {
    let mut builder = Request::builder()
        .uri(uri)
        .extension(GuardClientIp(IpAddr::from_str(ip).expect("test ip")));
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    builder.body(Body::empty()).expect("request")
}

#[tokio::test]
async fn route_ip_whitelist_overrides_the_global_lists() {
    // The global gate blacklists the address; the route's whitelist takes
    // over for its route and misses deny with the reference Forbidden
    // shape.
    let gate = axum_guard_rs::IpGateConfig::new([] as [&str; 0], ["203.0.113.9"], [] as [&str; 0])
        .expect("valid lists");
    let config = RouteConfig {
        ip_whitelist: Some(vec![String::from("203.0.113.9")]),
        ..RouteConfig::default()
    };
    let layer = with_guard(axum_guard_rs::default_config())
        .with_ip_gate(gate)
        .with_route_configs(resolver_for(&[("GET", "/hello")], config));
    let (status, _) = status_for(
        guarded(layer.clone()),
        request_from("203.0.113.9", "/hello"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the route whitelist match passes");
    let (status, _) = status_for(guarded(layer.clone()), request_from("192.0.2.5", "/hello")).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "the route whitelist miss denies"
    );
    let (status, _) = status_for(guarded(layer), request_from("203.0.113.9", "/open")).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "the global gate holds off-route"
    );
}

#[tokio::test]
async fn route_required_headers_demand_their_headers() {
    let config = RouteConfig {
        required_headers: [(String::from("X-Request-ID"), String::from("required"))]
            .into_iter()
            .collect(),
        ..RouteConfig::default()
    };
    let layer = with_guard(axum_guard_rs::default_config())
        .with_route_configs(resolver_for(&[("GET", "/hello")], config));
    let (status, body) =
        status_for(guarded(layer.clone()), request_from("192.0.2.9", "/hello")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body, "Missing required header: X-Request-ID");
    let (status, _) = status_for(
        guarded(layer),
        request_with_headers("192.0.2.9", "/hello", &[("x-request-id", "abc")]),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn route_require_referrer_gates_its_route() {
    let config = RouteConfig {
        require_referrer: Some(vec![String::from("partner.example.com")]),
        ..RouteConfig::default()
    };
    let layer = with_guard(axum_guard_rs::default_config())
        .with_route_configs(resolver_for(&[("GET", "/hello")], config));
    let (status, body) =
        status_for(guarded(layer.clone()), request_from("192.0.2.9", "/hello")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body, "Referrer required");
    let (status, _) = status_for(
        guarded(layer),
        request_with_headers(
            "192.0.2.9",
            "/hello",
            &[("referer", "https://partner.example.com/x")],
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn route_enable_suspicious_detection_false_skips_the_scan() {
    let config = RouteConfig {
        enable_suspicious_detection: false,
        ..RouteConfig::default()
    };
    let layer = with_guard(axum_guard_rs::default_config())
        .with_route_configs(resolver_for(&[("GET", "/open")], config));
    let (open, _) = status_for(
        guarded(layer.clone()),
        request_from("203.0.113.9", "/open?q=1%27+OR+1%3D1"),
    )
    .await;
    assert_eq!(open, StatusCode::OK, "the scan is off on its route");
    let (blocked, _) = status_for(
        guarded(layer),
        request_from("203.0.113.9", "/hello?q=1%27+OR+1%3D1"),
    )
    .await;
    assert_eq!(blocked, StatusCode::BAD_REQUEST, "the scan holds off-route");
}

#[tokio::test]
async fn route_cloud_provider_list_resolves_over_the_global() {
    // The RC2 route-over-global resolution through the axum surface: the
    // route's GCP list replaces the global AWS list for its route (the
    // AWS address the global lane blocks passes), and the global lane
    // holds off-route.
    let table = guard_core_rs::cloud_provider::CloudIpTable::default();
    table
        .set_provider_ranges("AWS", vec![("192.0.2.0/24".to_owned(), None)])
        .expect("valid ranges");
    table
        .set_provider_ranges("GCP", vec![("198.51.100.0/24".to_owned(), None)])
        .expect("valid ranges");
    let cloud = guard_core_rs::cloud_provider::CloudProviderStage::builder(
        guard_core_rs::cloud_provider::CloudProviderStageConfig {
            block_cloud_providers: guard_core_engine::cloud_provider::parse_cloud_selectors([
                "AWS",
            ])
            .expect("valid selectors"),
            table,
            passive_mode: false,
        },
    )
    .build();
    let config = RouteConfig {
        block_cloud_providers: [String::from("GCP")].into_iter().collect(),
        ..RouteConfig::default()
    };
    let layer = with_guard(axum_guard_rs::default_config())
        .with_cloud_provider(cloud)
        .with_route_configs(resolver_for(&[("GET", "/hello")], config));
    let (status, _) = status_for(guarded(layer.clone()), request_from("192.0.2.9", "/hello")).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the route list overrides the global"
    );
    let (status, _) = status_for(guarded(layer), request_from("192.0.2.9", "/open")).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "the global list holds off-route"
    );
}
