//! The maintenance surface (the GAP-R9 axum leg): the reference `reset`,
//! `refresh_cloud_ip_ranges`, and `agent_stats` ride the re-exported
//! `GuardLayer` (the axum thin surface keeps its own layer type), and the
//! guard-built router keeps serving through a maintenance call.

use axum::Router;
use axum::body::Body;
use axum::http::Request;
use axum_guard_rs::{AgentStats, default_config, with_guard};
use guard_core_engine::cloud_provider::CloudIpTable;
use guard_core_engine::rate_limit::{RateLimitConfig, RateLimiter};
use std::sync::Arc;
use tower::ServiceExt;

#[tokio::test]
async fn reset_drops_the_windows_and_the_router_keeps_serving() {
    let limiter = RateLimiter::new(RateLimitConfig {
        enable_rate_limiting: true,
        rate_limit: 1,
        rate_limit_window: 60,
        ..RateLimitConfig::default()
    })
    .expect("valid config");
    let probe = limiter.clone();
    let layer = with_guard(default_config()).with_rate_limiting(limiter);
    let client: std::net::IpAddr = "203.0.113.9".parse().expect("ip");
    assert!(probe.check(client, None).allowed);
    assert!(!probe.check(client, None).allowed);

    // The reference `reset()` through the guard surface.
    layer.reset();
    assert!(probe.check(client, None).allowed);

    // The router still answers through the guard.
    let app: Router = Router::new()
        .route("/plain", axum::routing::get(|| async { "ok" }))
        .layer(with_guard(default_config()));
    let response = app
        .oneshot(
            Request::builder()
                .uri("/plain")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("infallible");
    assert_eq!(response.status(), 200);
}

#[tokio::test]
async fn refresh_and_agent_stats_ride_the_guard_surface() {
    let table = Arc::new(CloudIpTable::default());
    // No scheduler installed: the reference's no-op arm answers false.
    let layer = with_guard(default_config());
    assert!(!layer.refresh_cloud_ip_ranges());
    assert_eq!(
        layer.agent_stats(),
        AgentStats {
            enabled: false,
            degraded: false
        }
    );

    // The installed scheduler starts (the unroutable probe endpoint fails
    // the fetch in the background; the gate clears when the body lands -
    // the tower suite pins the full lifecycle, the axum surface hands the
    // same types through). Point the fetch away from the real endpoints
    // via the override seam.
    let scheduler = Arc::new(
        guard_core_rs::geo_lifecycle::CloudRefreshScheduler::new()
            .with_providers(vec!["AWS"])
            .with_provider_endpoint("AWS", String::from("http://127.0.0.1:1/aws")),
    );
    let layer = with_guard(default_config())
        .with_cloud_refresh_scheduler(Arc::clone(&scheduler), Arc::clone(&table));
    assert!(layer.refresh_cloud_ip_ranges());
}
