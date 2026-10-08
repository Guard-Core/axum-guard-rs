//! Production-shaped guarded axum application.
//!
//! Differences from `simple_app`:
//!
//! - The engine [`DetectConfig`] and the adapter body cap are driven by
//!   environment variables (see `env_config` below), so a deployment tunes
//!   detection without a rebuild.
//! - Route-scoped guard configuration: the `/admin` sub-router is screened by
//!   a second, stricter `GuardLayer` (threat-score threshold halved by
//!   default), while general routes use the default-derived configuration.
//!   Axum's sub-router + merge composition is the route scoping mechanism;
//!   the adapter surface has no route IDs.
//! - `GET /health` stays on an unguarded router, mirroring excluded-path
//!   behavior.
//!
//! The guard-core-rs engine currently ships the CPU-bound detection pipeline
//! only: there is no rate limiter, ban manager, or Redis surface to drive, so
//! this example scopes guard configuration per route tree and stops there.

use axum::Router;
use axum::body::Bytes;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum_guard_rs::{DetectConfig, GuardLayer, default_config};

#[tokio::main]
async fn main() {
    let addr: std::net::SocketAddr = std::env::var("APP_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8080".to_string())
        .parse()
        .expect("APP_ADDR must be a socket address");

    let config = env_config();
    let body_cap = env_usize("GUARD_BODY_CAP", config.max_full_scan_bytes);
    // The admin tree screens with a stricter threshold: every env override
    // applies, but the score threshold is lowered relative to the general
    // config so borderline payloads are caught on admin surface only.
    let mut admin_config = config;
    admin_config.threat_score_threshold = env_f64(
        "GUARD_ADMIN_THREAT_SCORE_THRESHOLD",
        (config.threat_score_threshold * 0.5).min(1.0),
    );

    let general = Router::new()
        .route("/", get(root))
        .route("/search", get(search))
        .route("/echo", post(echo))
        .layer(GuardLayer::new(config).with_body_cap(body_cap));

    let admin = Router::new()
        .route("/stats", get(|| async { "stats" }))
        .layer(GuardLayer::new(admin_config).with_body_cap(body_cap));

    let app = Router::new()
        .route("/health", get(|| async { "ok" }))
        .nest("/admin", admin)
        .merge(general);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .unwrap_or_else(|error| panic!("failed to bind {addr}: {error}"));
    eprintln!("axum-guard-rs advanced app listening on {addr}");
    axum::serve(listener, app).await.expect("server error");
}

async fn root() -> &'static str {
    "axum-guard-rs advanced app"
}

async fn search() -> &'static str {
    "search ok"
}

async fn echo(body: Bytes) -> impl IntoResponse {
    (StatusCode::OK, String::from_utf8_lossy(&body).into_owned())
}

/// Build the engine [`DetectConfig`] from environment variables.
///
/// Every knob is optional; unset variables fall back to the ecosystem
/// defaults pinned in [`default_config`].
///
/// | Variable | Field | Default |
/// |---|---|---|
/// | `GUARD_MAX_CONTENT_LENGTH` | `max_content_length` | `10000` |
/// | `GUARD_MAX_FULL_SCAN_BYTES` | `max_full_scan_bytes` | `262144` |
/// | `GUARD_PRESERVE_ATTACK_PATTERNS` | `preserve_attack_patterns` | `true` |
/// | `GUARD_SEMANTIC_THRESHOLD` | `semantic_threshold` | `0.7` |
/// | `GUARD_THREAT_SCORE_THRESHOLD` | `threat_score_threshold` | `1.0` |
/// | `GUARD_BINARY_MIN_RUN_LENGTH` | `binary_min_run_length` | `16` |
fn env_config() -> DetectConfig {
    let defaults = default_config();
    DetectConfig {
        max_content_length: env_usize("GUARD_MAX_CONTENT_LENGTH", defaults.max_content_length),
        max_full_scan_bytes: env_usize("GUARD_MAX_FULL_SCAN_BYTES", defaults.max_full_scan_bytes),
        preserve_attack_patterns: env_bool(
            "GUARD_PRESERVE_ATTACK_PATTERNS",
            defaults.preserve_attack_patterns,
        ),
        semantic_threshold: env_f64("GUARD_SEMANTIC_THRESHOLD", defaults.semantic_threshold),
        threat_score_threshold: env_f64(
            "GUARD_THREAT_SCORE_THRESHOLD",
            defaults.threat_score_threshold,
        ),
        binary_min_run_length: env_usize(
            "GUARD_BINARY_MIN_RUN_LENGTH",
            defaults.binary_min_run_length,
        ),
        max_scan_values: env_usize("GUARD_MAX_SCAN_VALUES", defaults.max_scan_values),
        max_scan_chars: env_usize("GUARD_MAX_SCAN_CHARS", defaults.max_scan_chars),
        max_json_depth: env_usize("GUARD_MAX_JSON_DEPTH", defaults.max_json_depth),
    }
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn env_f64(name: &str, default: f64) -> f64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn env_bool(name: &str, default: bool) -> bool {
    match std::env::var(name) {
        Ok(value) => matches!(value.to_ascii_lowercase().as_str(), "1" | "true" | "yes"),
        Err(_) => default,
    }
}
