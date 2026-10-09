<p align="center">
    <a href="https://guard-core.github.io/guard-core/latest/">
        <img src="https://guard-core.github.io/guard-core/latest/assets/guard_core_legend.svg" alt="Guard Core">
    </a>
</p>

___

<p align="center">
    <strong>Application-layer security middleware for [axum](https://github.com/tokio-rs/axum), powered by the [guard-core-rs](https://github.com/Guard-Core/guard-core-rs) detection engine. Part of the [guard ecosystem](https://github.com/Guard-Core).</strong>
</p>

<p align="center">
    <a href="https://crates.io/crates/axum-guard-rs">
        <img src="https://img.shields.io/crates/v/axum-guard-rs?color=0080ff" alt="Crates.io version">
    </a>
    <a href="https://guard-core.github.io/axum-guard-rs/latest/">
        <img src="https://img.shields.io/badge/docs-latest-0080ff.svg" alt="Docs">
    </a>
    <a href="https://github.com/Guard-Core/axum-guard-rs/actions/workflows/release.yml">
        <img src="https://github.com/Guard-Core/axum-guard-rs/actions/workflows/release.yml/badge.svg" alt="Release">
    </a>
    <a href="https://opensource.org/licenses/MIT">
        <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License">
    </a>
    <a href="https://github.com/Guard-Core/axum-guard-rs/actions/workflows/ci.yml">
        <img src="https://github.com/Guard-Core/axum-guard-rs/actions/workflows/ci.yml/badge.svg" alt="CI">
    </a>
    <a href="https://github.com/Guard-Core/axum-guard-rs/actions/workflows/code-ql.yml">
        <img src="https://github.com/Guard-Core/axum-guard-rs/actions/workflows/code-ql.yml/badge.svg" alt="CodeQL">
    </a>
</p>

<p align="center">
    <a href="https://github.com/Guard-Core/axum-guard-rs/actions/workflows/pages/pages-build-deployment">
        <img src="https://github.com/Guard-Core/axum-guard-rs/actions/workflows/pages/pages-build-deployment/badge.svg?branch=gh-pages" alt="PagesBuildDeployment">
    </a>
    <a href="https://github.com/Guard-Core/axum-guard-rs/actions/workflows/docs.yml">
        <img src="https://github.com/Guard-Core/axum-guard-rs/actions/workflows/docs.yml/badge.svg" alt="DocsUpdate">
    </a>
    <img src="https://img.shields.io/github/last-commit/Guard-Core/axum-guard-rs?style=flat&amp;logo=git&amp;logoColor=white&amp;color=0080ff" alt="last-commit">
</p>

<p align="center">
    <img src="https://img.shields.io/badge/Axum-1B1B1B.svg?style=flat" alt="Axum">
    <a href="https://crates.io/crates/axum-guard-rs">
        <img src="https://img.shields.io/crates/d/axum-guard-rs" alt="Downloads">
    </a>
</p>

<p align="center">
    <a href="https://guard-core.com">Website</a> &middot;
    <a href="https://guard-core.github.io/axum-guard-rs/latest/">Docs</a> &middot;
    <a href="https://playground.guard-core.com">Playground</a> &middot;
    <a href="https://app.guard-core.com">Dashboard</a> &middot;
    <a href="https://discord.gg/ZW7ZJbjMkK">Discord</a>
</p>

---

## About

The guard ecosystem provides application-layer API security middleware across multiple languages and frameworks:

- **Python**: [fastapi-guard](https://github.com/Guard-Core/fastapi-guard), [flaskapi-guard](https://github.com/Guard-Core/flaskapi-guard), [djapi-guard](https://github.com/Guard-Core/djapi-guard), [tornadoapi-guard](https://github.com/Guard-Core/tornadoapi-guard)
- **TypeScript**: guard-core-ts with adapters for Express, Fastify, Hono, NestJS
- **Rust**: [guard-core-rs](https://github.com/Guard-Core/guard-core-rs) with adapters for [tower](https://github.com/Guard-Core/tower-guard-rs) (this repo wraps it), [actix-web](https://github.com/Guard-Core/actix-guard-rs), and [rocket](https://github.com/Guard-Core/rocket-guard-rs)

Axum middleware is tower middleware, so this crate is the thin axum-facing surface over [tower-guard-rs](https://github.com/Guard-Core/tower-guard-rs): the `with_guard` constructor, the re-exports an axum application needs, and the axum-specific tests that pin behavior against `axum::body::Body`. It contains no security logic of its own.

## Usage

```rust
use axum::Router;

let app = Router::new()
    .route("/", axum::routing::get(|| async { "hello" }))
    .layer(axum_guard_rs::with_guard(axum_guard_rs::default_config()));
```

Tune the body cap by chaining the underlying layer's builder:

```rust
let layer = axum_guard_rs::with_guard(axum_guard_rs::default_config()).with_body_cap(1_048_576);
let app = Router::new().layer(layer);
```

The full crate documentation is in [`src/lib.rs`](src/lib.rs) (build it with `cargo doc --open`).

## What it inspects

One engine call per request view, mirroring the mapping used by the sibling TypeScript adapters:

| Request part | Engine context | Notes |
|---|---|---|
| Path | `url_path` | Skipped for `/` |
| Query string | `query_param` | Skipped when empty |
| Header values | `header` | Skips `sec-*` and the negotiation/routing headers (`Host`, `User-Agent`, `Accept`, `Accept-Encoding`, `Connection`, `Origin`, `Referer`) |
| Body | `request_body` | Buffered first, capped |

The HTTP method is not fed to the engine: the engine's `detect(content, context, config)` takes content plus a context, and the reference adapters do not scan the method either.

## Engine surfaces (public config)

Every surface configurable on the tower `GuardLayer` is reachable through `with_guard`'s return value:

| Surface | Builder |
|---|---|
| Rate-limit tiers | `.with_route_tiers(resolver)` (`path -> Option<RouteRateLimits>`; a `RouteRateLimits` request extension wins), `.with_geo_handler(handler)` |
| Detection exclusions | `.with_detection_exclusions(config)`; per route via a `RouteDetectionExclusions` request extension |
| Events + log settings | `.with_event_bus(bus)`, `.with_observability(config)` |
| `on_block` + custom errors | `.with_on_block(hook)`, `.with_custom_error_responses(map)` |
| Distributed mode | `.with_distributed_store(window_store, prefix, fail_open)` + `.with_distributed_ban_store(ban_store)` |
| Passive mode | `.with_passive_mode(true)` |

All of the types (`RouteRateLimits`, `DetectionExclusionConfig`, `SecurityEventBus`, `ObservabilityConfig`, `OnBlockHook`, `CustomErrorResponses`, the store traits, and more) are re-exported at the crate root.

## Responses

| Situation | Status | Body |
|---|---|---|
| The IP gate denies the client IP (blacklisted, or a non-empty whitelist matches neither the IP nor an exemption) | `403 Forbidden` | `Forbidden` |
| The ban stage finds a live ban on the client IP | `403 Forbidden` | `IP address banned` |
| The rate limiter records a crossing of `rate_limit` | `429 Too Many Requests` (+ `Retry-After: <window>`) | `Too many requests` |
| Engine flags a view | `400 Bad Request` | `Suspicious activity detected` |
| Engine flags a view and the crossed auto-ban threshold bans on the spot | `403 Forbidden` | `IP has been banned` |
| Body exceeds the cap | `413 Payload Too Large` | `Payload too large` |
| Body read error or engine panic | `500 Internal Server Error` | `Security check failed` |

## Rate limiting, bans, and auto-ban

Two opt-in builders on the layer install the engine's stateful machinery, mirroring the tower reference:

```rust
let limiter = axum_guard_rs::RateLimiter::new(axum_guard_rs::RateLimitConfig {
    enable_rate_limiting: true,
    rate_limit: 30,
    rate_limit_window: 10,
    ..axum_guard_rs::RateLimitConfig::default()
})
.expect("valid config");
let bans = axum_guard_rs::IpBanConfig::new(
    true,
    10,
    3600,
    [] as [(String, axum_guard_rs::ThreatBanEntry); 0],
)
.expect("valid config");

let layer = axum_guard_rs::with_guard(axum_guard_rs::default_config())
    .with_rate_limiting(limiter)
    .with_ip_banning(axum_guard_rs::IpBanManager::new(), bans);
let app = Router::new().layer(layer);
```

A rate-limit crossing answers `429 Too Many Requests` with `Retry-After: <window seconds>`; with the limiter's `enable_rate_limit_auto_ban` on, every crossing counts one `rate_limit` violation toward the auto-ban engine (the response stays 429, the ban bites on the next request). A live ban answers `403 Forbidden` (`IP address banned`) before the limiter, so banned traffic never consumes rate budget. Every detected threat counts its categories per client IP; a crossed `threat_ban_config` entry (or the flat `auto_ban_threshold`) bans on the spot with `403 Forbidden` (`IP has been banned`), while the plain detection block stays `400`. With `enable_ip_banning = false`, violations count but never ban.

Both stages honor the `exempt_ips` contract (see the `with_ip_gate` docs): whitelisted and exempt IPs are never rate limited, never banned, and never counted; requests without attribution (no `ConnectInfo<SocketAddr>`, so no `client_ip_layer()`) skip the stage but stay detection-screened. The limiter and ban store are process-global by design, so cloning the layer or the `IpBanManager` shares one store (admin unban endpoints and stats work out of band).

The bodies follow the ecosystem's plain-text error convention (the bare message, `text/plain; charset=utf-8`, same as the Python family), but the adapter is deliberately **fail-secure**: unlike the TypeScript adapters, whose check pipeline logs and skips on error, any failure to complete the security check answers `500`, never an uninspected passthrough.

Engine panics are caught with `catch_unwind`, so a failed check still produces a response instead of unwinding out of the connection task. `panic = "abort"` in the release profile disables that recovery.

Note that `Router::layer` applies the layer to registered routes; a request that matches nothing goes to the fallback without passing the guard. Use `Router::route_layer`/`fallback` composition if your threat model requires guarding unmatched paths too.

## WebSocket guard (upgrades)

`websocket::WebSocketGuard` is a tower layer for the upgrade path, ported from fastapi-guard's `guard/websocket.py`: an upgrade request (`Upgrade: websocket` + an `upgrade` token in `Connection`) runs the reference check sequence before the axum handler's `WebSocketUpgrade` extractor ever completes the handshake, and a blocked handshake is rejected with `403 Forbidden` pre-accept, carrying the close shape on `X-Guard-WebSocket-Close` / `X-Guard-WebSocket-Close-Reason` (axum has no pre-accept close frame; this is the HTTP-level translation of Starlette's `WebSocketException` denial). The close codes are the reference's: `1008 Policy Violation` for every policy denial (IP banned, IP not allowed, rate limit exceeded, unknown client address under fail-secure, suspicious activity) and `1013 Try Again Later` for an engine malfunction (a panic in the check sequence, contained). The sequence: fail-secure unknown address, the ban arm, the `is_ip_allowed` gate + country arms (a whitelist match skips countries), the `ws` rate limit (skipped for whitelisted IPs), then the path/query/header penetration scan - an upgrade carries no body. The client IP resolves through the `GuardClientIp` extension (or `ConnectInfo<SocketAddr>` directly; serve with `into_make_service_with_connect_info::<SocketAddr>()`). Non-upgrade requests pass through untouched (the `GuardLayer` domain). Build it with `websocket::WebSocketGuardConfig::new(default_config())` + the `with_ip_gate` / `with_ip_banning` / `with_rate_limiting` / `with_country_rules` / `with_fail_secure` builders and `.layer(WebSocketGuard::new(config))`.

## Status route

`status::status_router(GuardStatus::new().with_cloud_table(table))` is the `add_status_route` mirror (fastapi-guard `guard/status.py` + `HandlerInitializer.get_initialization_status`): merge the returned router to mount `GET /_guard/status` (`status::DEFAULT_STATUS_PATH`), serving the cloud-provider status table (`{"ready":..., "last_refreshed":<unix-seconds|null>, "entries":N}` per provider from the live `CloudIpTable`) and the geo-ip component (`null` without a handler, `{"configured":true}` with the lookup trait only, the `{ready, last_refreshed, entries}` health snapshot with the `IpInfoManager` lifecycle manager). The maintenance trio rides the re-exported `GuardLayer`: `reset()` drops the rate-limit windows, `refresh_cloud_ip_ranges()` schedules one single-flight refresh through `with_cloud_refresh_scheduler`, and `agent_stats()` answers the reference property's no-agent shape.

## Engine dependency

The Cargo.toml pins `tower-guard-rs` 1.2.0 plus `guard-core-engine`/`guard-core-rs` 4.2.0, and carries paths pointing at sibling checkouts (`../tower-guard-rs`, `../guard-core-rs/crates/guard-core-engine`, `../guard-core-rs/crates/guard-core-rs`) so local builds and CI compile the dependencies from source. Registry note, stated plainly: the 4.1.0 dists were yanked (the version-accuracy fix for the family tag mistake), so 1.1.0 could not resolve its engine from the registry alone; the synchronized 4.2.0 train restores resolution (`axum-guard-rs` 1.2.0 over `tower-guard-rs` 1.2.0 and `guard-core-engine`/`guard-core-rs` 4.2.0).

CI checks out both sibling repositories (see [`.github/workflows/ci.yml`](.github/workflows/ci.yml)), mirroring the sibling adapter pattern in `laravel-guard`/`symfony-guard`.

The engine crate is used directly for the detect path; the `guard-core-rs` facade is also a dependency (its `events` module backs the `SecurityEventBus` re-exports and the test assertions). The facade re-exports the full engine stage set (`compiler`, `preprocessor`, `semantic`, `detect`, `detection_exclusions`), so nothing is blocked on the facade.

## Stage surface (the reference 17-check pipeline, wired)

Every reference check the engine ships is installable on the `GuardLayer` `with_guard` returns, and the service runs the installed set in the reference pipeline order (`provided_layers` hands the same stages back as standalone tower layers in that order): emergency mode, HTTPS enforcement, request logging, request size/content caps, required headers + authentication, referrer, custom validators, time windows, geo country blocking, cloud-provider blocking, user-agent filtering, bans, rate limiting, the custom-request check, and the response-side pass (behavioral return rules + security headers + CORS). The builder table lives in the crate docs; the composition ships in `tower-guard-rs`.

## Not wired on purpose

- **WebSocket guard**: an axum `Router` sees a WebSocket upgrade as an ordinary request, so the handshake is screened like any request; frames after the upgrade are not intercepted. There is no per-frame guard surface.
- **Status route**: no `add_status_route` equivalent ships (a gap tracked family-wide); expose engine state through your own route if you need it.

## Development

- MSRV: 1.92 (matches guard-core-rs); edition 2024
- Requires sibling checkouts: `../tower-guard-rs` and `../guard-core-rs`

```bash
cargo check --all-targets
cargo test
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
```

CI (`.github/workflows/ci.yml`) runs the same checks on stable plus an MSRV 1.92 job, checking out the siblings first so the path dependencies resolve.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE).
