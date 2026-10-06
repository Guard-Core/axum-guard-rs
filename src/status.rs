//! The status route, ported from fastapi-guard `guard/status.py`
//! (`add_status_route`) serving the payload of
//! `HandlerInitializer.get_initialization_status`
//! (`guard_core/core/initialization/handler_initializer.py`): the
//! cloud-provider readiness table and the geo-ip component.
//!
//! The Rust engine tracks the cloud table's readiness only
//! ([`CloudIpTable::provider_is_ready`] is "the reference `get_status`'s
//! `ready` flag"), so each provider row carries `ready` alone - the
//! `entries`/`last_refreshed` keys the Python family serves have no engine
//! surface here and are not invented. The geo-ip component is `null` when no
//! handler is configured and `{"configured":true}` when one is: the engine
//! exposes no geo health readout ([`GeoIpHandler`] is the lookup trait).
//!
//! # Example
//!
//! ```
//! use axum::Router;
//! use axum_guard_rs::status::{GuardStatus, status_router};
//!
//! let app: Router = Router::new().merge(status_router(GuardStatus::new()));
//! # let _ = app;
//! ```

use axum::Router;
use axum::body::Body;
use axum::http::{StatusCode, header::CONTENT_TYPE};
use axum::response::Response;
use axum::routing::get;
use guard_core_engine::cloud_provider::{CloudIpTable, VALID_CLOUD_PROVIDERS};
use std::fmt::Write;

/// The path `add_status_route` registers by default (the reference's
/// `/_guard/status`).
pub const DEFAULT_STATUS_PATH: &str = "/_guard/status";

/// The initialization-status snapshot the status route serves.
///
/// Build it with the handles the application already owns: the
/// [`CloudIpTable`] the cloud-provider stage was built from (clones share
/// the store, so the snapshot always answers from the live table), and
/// whether a [`GeoIpHandler`] is configured.
///
/// The payload is serialized by hand (the crate carries no JSON
/// dependency); the shape is the reference's `get_initialization_status`
/// mapping with the caveats documented at the module level.
#[derive(Debug, Clone, Default)]
pub struct GuardStatus {
    cloud: Option<CloudIpTable>,
    geo_configured: bool,
}

impl GuardStatus {
    /// A snapshot with no cloud table and no geo handler: every provider
    /// reports `ready:false` and `geo_ip` is `null`, the reference's
    /// never-initialized shape.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Serve the readiness flags from this cloud table (the one the
    /// cloud-provider stage consults; clones share the store, so a
    /// background refresher's swaps are visible).
    #[must_use]
    pub fn with_cloud_table(mut self, cloud: CloudIpTable) -> Self {
        self.cloud = Some(cloud);
        self
    }

    /// Mark the geo-ip component configured (`{"configured":true}` instead
    /// of `null`).
    #[must_use]
    pub const fn with_geo_configured(mut self, geo_configured: bool) -> Self {
        self.geo_configured = geo_configured;
        self
    }

    /// The cloud providers with their readiness flags, in the engine's
    /// reference order.
    #[must_use]
    pub fn cloud_provider_status(&self) -> Vec<(&'static str, bool)> {
        VALID_CLOUD_PROVIDERS
            .iter()
            .map(|provider| {
                let ready = self
                    .cloud
                    .as_ref()
                    .is_some_and(|table| table.provider_is_ready(provider));
                (*provider, ready)
            })
            .collect()
    }

    /// The JSON document the status route serves.
    #[must_use]
    pub fn payload(&self) -> String {
        let mut payload = String::from(r#"{"cloud_providers":{"#);
        let mut first = true;
        for (provider, ready) in self.cloud_provider_status() {
            if first {
                first = false;
            } else {
                payload.push(',');
            }
            payload.push_str(&json_string(provider));
            payload.push_str(r#":{"ready":"#);
            payload.push_str(if ready { "true" } else { "false" });
            payload.push('}');
        }
        payload.push_str("},");
        if self.geo_configured {
            payload.push_str(r#""geo_ip":{"configured":true}"#);
        } else {
            payload.push_str(r#""geo_ip":null"#);
        }
        payload.push('}');
        payload
    }

    /// The status answer: `200 OK`, `application/json`, the snapshot
    /// document.
    #[must_use]
    pub fn response(&self) -> Response {
        Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(self.payload()))
            .expect("static status response parts")
    }
}

/// The `add_status_route` mirror: a [`Router`] carrying the status route at
/// [`DEFAULT_STATUS_PATH`], answering `GET` only. Merge it into the
/// application router (`Router::merge`); apply the guard layer around the
/// merge point when the status route should sit behind the checks. The
/// returned router is inert until merged or layered.
#[must_use = "merge the status router into the application router"]
pub fn status_router(status: GuardStatus) -> Router {
    Router::new().route(
        DEFAULT_STATUS_PATH,
        get(move || {
            let status = status.clone();
            async move { status.response() }
        }),
    )
}

/// Escape one JSON string body: the two mandatory controls plus the
/// characters every consumer chokes on. The provider names this module
/// serializes are static ASCII, so the escape exists for completeness and
/// for any future dynamic key.
fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            control if (control as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", control as u32);
            }
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;
    use tower::ServiceExt;

    #[test]
    fn empty_snapshot_reports_every_provider_unready_and_null_geo() {
        let payload = GuardStatus::new().payload();
        assert_eq!(
            payload,
            "{\"cloud_providers\":{\
             \"AWS\":{\"ready\":false},\
             \"GCP\":{\"ready\":false},\
             \"Azure\":{\"ready\":false},\
             \"DigitalOcean\":{\"ready\":false},\
             \"Linode\":{\"ready\":false},\
             \"Vultr\":{\"ready\":false}},\
             \"geo_ip\":null}"
        );
    }

    #[test]
    fn cloud_table_readiness_passes_through() {
        let table = CloudIpTable::default();
        table
            .set_provider_ranges("AWS", vec![("203.0.113.0/24".to_owned(), None)])
            .expect("valid ranges");
        let status = GuardStatus::new().with_cloud_table(table);
        let providers = status.cloud_provider_status();
        assert_eq!(providers.len(), 6);
        let aws = providers.iter().find(|(name, _)| *name == "AWS");
        assert_eq!(aws.copied(), Some(("AWS", true)));
        assert!(
            providers
                .iter()
                .all(|(name, ready)| *name == "AWS" || !ready)
        );
        let payload = status.payload();
        assert!(payload.contains(r#""AWS":{"ready":true}"#));
        assert!(payload.contains(r#""GCP":{"ready":false}"#));
    }

    #[test]
    fn geo_configured_flips_the_component_object() {
        let configured = GuardStatus::new().with_geo_configured(true).payload();
        assert!(configured.contains(r#""geo_ip":{"configured":true}"#));
        let plain = GuardStatus::new().payload();
        assert!(plain.contains(r#""geo_ip":null"#));
    }

    #[test]
    fn clearing_a_provider_reports_it_unready_again() {
        let table = CloudIpTable::default();
        table
            .set_provider_ranges("Vultr", vec![("192.0.2.1/32".to_owned(), None)])
            .expect("valid ranges");
        let snapshot = GuardStatus::new().with_cloud_table(table.clone());
        assert!(
            snapshot
                .cloud_provider_status()
                .iter()
                .any(|(name, ready)| *name == "Vultr" && *ready)
        );
        // The failed-refresh shape: the refresher drops the provider and the
        // snapshot follows (clones share the store).
        table.clear_provider("Vultr");
        assert!(
            !snapshot
                .cloud_provider_status()
                .iter()
                .any(|(_, ready)| *ready)
        );
    }

    #[test]
    fn json_string_escapes_the_control_family() {
        assert_eq!(json_string("plain"), "\"plain\"");
        assert_eq!(json_string("a\"b\\c\nd\r\te"), "\"a\\\"b\\\\c\\nd\\r\\te\"");
        assert_eq!(json_string("\u{1}"), "\"\\u0001\"");
    }

    #[tokio::test]
    async fn status_router_answers_the_default_path() {
        let table = CloudIpTable::default();
        table
            .set_provider_ranges("GCP", vec![("198.51.100.0/24".to_owned(), None)])
            .expect("valid ranges");
        let app: Router =
            Router::new().merge(status_router(GuardStatus::new().with_cloud_table(table)));
        let request = Request::builder()
            .uri(DEFAULT_STATUS_PATH)
            .body(Body::empty())
            .expect("request");
        let response = app.oneshot(request).await.expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).expect("content type"),
            "application/json"
        );
        let body = http_body_util::BodyExt::collect(response.into_body())
            .await
            .expect("body")
            .to_bytes();
        assert!(String::from_utf8_lossy(&body).contains(r#""GCP":{"ready":true}"#));
    }
}
