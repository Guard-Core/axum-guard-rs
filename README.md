# axum-guard-rs

Application-layer security middleware for [axum](https://github.com/tokio-rs/axum), powered by the [guard-core-rs](https://github.com/rennf93/guard-core-rs) detection engine. Part of the [guard ecosystem](https://github.com/rennf93).

Docs: <https://rennf93.github.io/axum-guard-rs/>

**Status:** Released. Version 1.0.0, published to crates.io. `with_guard(config)` returns a `tower` layer that drops straight into `Router::layer`.

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

## Responses

| Situation | Status | Body |
|---|---|---|
| Engine flags a view | `400 Bad Request` | `Suspicious activity detected` |
| Body exceeds the cap | `413 Payload Too Large` | `Payload too large` |
| Body read error or engine panic | `500 Internal Server Error` | `Security check failed` |

The bodies follow the ecosystem's plain-text error convention (the bare message, `text/plain; charset=utf-8`, same as the Python family), but the adapter is deliberately **fail-secure**: unlike the TypeScript adapters, whose check pipeline logs and skips on error, any failure to complete the security check answers `500`, never an uninspected passthrough.

Engine panics are caught with `catch_unwind`, so a failed check still produces a response instead of unwinding out of the connection task. `panic = "abort"` in the release profile disables that recovery.

Note that `Router::layer` applies the layer to registered routes; a request that matches nothing goes to the fallback without passing the guard. Use `Router::route_layer`/`fallback` composition if your threat model requires guarding unmatched paths too.

## Engine dependency

`tower-guard-rs` 1.0.0 and `guard-core-engine` 4.0.4 are published to crates.io. The Cargo.toml pins those versions and also carries paths pointing at sibling checkouts (`../tower-guard-rs`, `../guard-core-rs/crates/guard-core-engine`) so local builds and CI compile the dependencies from source; consumers installing the crate from the registry resolve them normally.

CI checks out both sibling repositories (see [`.github/workflows/ci.yml`](.github/workflows/ci.yml)), mirroring the sibling adapter pattern in `laravel-guard`/`symfony-guard`.

The engine crate is used directly rather than through the `guard-core-rs` facade because the facade currently re-exports only `compiler`, `preprocessor`, and `semantic`; `detect` (the entry point the guard uses) is not re-exported there yet.

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
