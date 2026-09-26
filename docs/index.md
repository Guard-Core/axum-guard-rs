# axum-guard-rs

`axum-guard-rs` is application-layer security middleware for
[axum](https://github.com/tokio-rs/axum), powered by the
[guard-core-rs](https://github.com/rennf93/guard-core-rs) detection engine.
It is part of the [Guard ecosystem](https://github.com/rennf93).

The crate is the thin axum-facing surface over
[tower-guard-rs](https://github.com/rennf93/tower-guard-rs): axum routers are
`tower` services, so `Router::layer` with the generic `GuardLayer` is the
whole integration. The `with_guard` constructor, the re-exports an axum
application needs, and axum-specific tests pin the behavior against
`axum::body::Body`. Per the ecosystem boundary rules this crate contains no
security logic: detection comes from the engine, request screening from
`tower-guard-rs`.

## Ecosystem position

```text
guard-core (Python)           <- Reference implementation, spec owner
├── guard-core-rs             <- Rust engine: detection, preprocessing, semantics
│   ├── tower-guard-rs        <- Adapter: tower middleware
│   ├── axum-guard-rs         <- Adapter: axum layer over tower-guard-rs (this repo)
│   ├── actix-guard-rs        <- Adapter: actix-web middleware
│   └── rocket-guard-rs       <- Adapter: rocket fairing and guards
├── guard-core-go             <- Go port
└── guard-core-ts             <- TypeScript port
```

The guard translates native request content into engine inputs (path, query
string, header values, buffered body), runs one engine call per request view,
and translates a threat verdict into a native block response. The adapter is
fail-secure: any failure to complete the security check answers `500`, never
an uninspected passthrough.

## Installation

```bash
cargo add axum-guard-rs
```

The published crate is `1.0.0` and depends on the published
`tower-guard-rs` `1.0.0`, itself pinned to `guard-core-engine` `4.0.4`.
Requires Rust 1.92 or later (edition 2024) and axum 0.8. See
[Installation](installation.md) for details.

## Quick start

```rust
use axum::Router;

let app = Router::new()
    .route("/", axum::routing::get(|| async { "hello" }))
    .layer(axum_guard_rs::with_guard(axum_guard_rs::default_config()));
```

Apply the layer with `Router::layer` (every registered route) or
`Router::route_layer` (routes only, skipping the fallback).

## What it inspects

One engine call per request view:

| Request part | Engine context | Notes |
|---|---|---|
| Path | `url_path` | Skipped for `/` |
| Query string | `query_param` | Skipped when empty |
| Header values | `header` | Skips `sec-*` and the negotiation/routing headers |
| Body | `request_body` | Buffered first, capped (262 144 bytes by default) |

The HTTP method is not scanned.

## Responses

| Situation | Status | Body |
|---|---|---|
| Engine flags a view | `400 Bad Request` | `Suspicious activity detected` |
| Body exceeds the cap | `413 Payload Too Large` | `Payload too large` |
| Body read error or engine panic | `500 Internal Server Error` | `Security check failed` |

## Where to go next

- [Installation](installation.md) for requirements and dependency setup
- [API](api.md) for the full public surface and behavior tables
- [Examples](examples.md) for runnable applications
