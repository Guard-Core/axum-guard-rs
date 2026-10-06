# axum-guard-rs

Application-layer security middleware for [axum](https://github.com/tokio-rs/axum), powered by the [guard-core-rs](https://github.com/rennf93/guard-core-rs) detection engine. Part of the [guard ecosystem](https://github.com/rennf93).

Docs: <https://rennf93.github.io/axum-guard-rs/>

**Status:** Released. Version 1.2.0, published to crates.io. `with_guard(config)` returns a `tower` layer that drops straight into `Router::layer`.

## About

The guard ecosystem provides application-layer API security middleware across multiple languages and frameworks:

- **Python**: [fastapi-guard](https://github.com/rennf93/fastapi-guard), [flaskapi-guard](https://github.com/rennf93/flaskapi-guard), [djapi-guard](https://github.com/rennf93/djapi-guard), [tornadoapi-guard](https://github.com/rennf93/tornadoapi-guard)
- **TypeScript**: guard-core-ts with adapters for Express, Fastify, Hono, NestJS
- **Rust**: [guard-core-rs](https://github.com/rennf93/guard-core-rs) with adapters for [tower](https://github.com/rennf93/tower-guard-rs) (this repo wraps it), [actix-web](https://github.com/rennf93/actix-guard-rs), and [rocket](https://github.com/rennf93/rocket-guard-rs)

Axum middleware is tower middleware, so this crate is the thin axum-facing surface over [tower-guard-rs](https://github.com/rennf93/tower-guard-rs): the `with_guard` constructor, the re-exports an axum application needs, and the axum-specific tests that pin behavior against `axum::body::Body`. It contains no security logic of its own.

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
