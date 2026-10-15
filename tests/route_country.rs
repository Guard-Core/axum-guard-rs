//! Route-level country rules and the unknown client identity through the
//! axum surface. The full reference tables run against the tower
//! middleware this crate wraps (`tower-guard-rs/tests/route_country.rs`);
//! these rows come from the same generated table
//! (`check_route_ip_access` / `check_ip_access` in the reference engine).

use axum::Router;
use axum::body::Body;
use axum::http::Request;
use axum::routing::get;
use axum_guard_rs::{
    GeoIpHandler, GuardClientIp, IpGateConfig, RouteConfig, default_config, with_guard,
};
use guard_core_engine::geo::parse_country_lists;
use guard_core_rs::geo::{GeoStage, GeoStageConfig};
use http::StatusCode;
use std::net::IpAddr;
use std::sync::Arc;
use tower::ServiceExt;

struct Countries;

impl GeoIpHandler for Countries {
    fn get_country(&self, ip: IpAddr) -> Option<String> {
        match ip.to_string().as_str() {
            "10.0.0.1" => Some("US".to_owned()),
            "10.0.0.2" => Some("CN".to_owned()),
            _ => None,
        }
    }
}

async fn status(
    route: RouteConfig,
    whitelist: &[&str],
    country_whitelist: &[&str],
    ip: Option<&str>,
) -> StatusCode {
    let route = Arc::new(route);
    let resolver: axum_guard_rs::RouteConfigResolver =
        Arc::new(move |_method, _path| Some(route.clone()));
    let mut layer = with_guard(default_config())
        .with_geo_handler(Arc::new(Countries))
        .with_route_configs(resolver);
    if !whitelist.is_empty() {
        layer = layer.with_ip_gate(
            IpGateConfig::new(whitelist, [] as [&str; 0], [] as [&str; 0]).expect("lists"),
        );
    }
    if !country_whitelist.is_empty() {
        layer = layer.with_geo_blocking(
            GeoStage::builder(GeoStageConfig {
                gate: parse_country_lists(country_whitelist, [] as [&str; 0]),
                handler: Some(Arc::new(Countries)),
                passive_mode: false,
            })
            .build(),
        );
    }
    let router = Router::new()
        .route("/api", get(|| async { "ok" }))
        .layer(layer);
    let mut request = Request::builder().uri("/api");
    if let Some(ip) = ip {
        request = request.extension(GuardClientIp(ip.parse::<IpAddr>().expect("ip")));
    }
    router
        .oneshot(request.body(Body::empty()).expect("request"))
        .await
        .expect("response")
        .status()
}

fn route(whitelist: &[&str], blocked: &[&str], countries: &[&str]) -> RouteConfig {
    let some = |list: &[&str]| {
        (!list.is_empty()).then(|| list.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>())
    };
    RouteConfig {
        ip_whitelist: some(whitelist),
        blocked_countries: some(blocked),
        whitelist_countries: some(countries),
        ..RouteConfig::default()
    }
}

#[tokio::test]
async fn a_route_whitelist_match_does_not_override_a_blocked_country() {
    let blocked = route(&["10.0.0.2"], &["CN"], &[]);
    assert_eq!(
        status(blocked, &[], &[], Some("10.0.0.2")).await,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn a_country_in_both_route_lists_is_blocked() {
    let both = route(&[], &["CN"], &["CN"]);
    assert_eq!(
        status(both, &[], &[], Some("10.0.0.2")).await,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn the_unknown_identity_follows_the_reference() {
    assert_eq!(
        status(route(&["10.0.0.1"], &[], &[]), &[], &[], None).await,
        StatusCode::FORBIDDEN,
        "a route whitelist denies it"
    );
    assert_eq!(
        status(route(&[], &[], &["US"]), &[], &[], None).await,
        StatusCode::FORBIDDEN,
        "a route country whitelist denies it"
    );
    assert_eq!(
        status(route(&[], &["CN"], &[]), &[], &[], None).await,
        StatusCode::OK,
        "a route blocklist alone lets it through"
    );
    assert_eq!(
        status(route(&[], &[], &[]), &["10.0.0.1"], &[], None).await,
        StatusCode::FORBIDDEN,
        "a global whitelist denies it"
    );
    assert_eq!(
        status(route(&[], &[], &[]), &[], &["US"], None).await,
        StatusCode::FORBIDDEN,
        "a global country whitelist denies it"
    );
}
