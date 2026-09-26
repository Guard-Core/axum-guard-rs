# Installation

## Requirements

- Rust 1.92 or later (the crate uses edition 2024)
- axum 0.8

## Add the crate

```bash
cargo add axum-guard-rs
```

or add it to your `Cargo.toml` directly:

```toml
[dependencies]
axum-guard-rs = "1.0.0"
axum = "0.8"
```

`axum-guard-rs` `1.0.0` depends on `tower-guard-rs` `1.0.0`, the tower
middleware adapter, which itself depends on `guard-core-engine` `4.0.4`, the
published detection engine crate. The version pins stay in lockstep with the
published engine release.

## Verify the installation

A minimal program that wires the guard and serves one route:

```rust
use axum::Router;

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/", axum::routing::get(|| async { "hello" }))
        .layer(axum_guard_rs::with_guard(axum_guard_rs::default_config()));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:8080")
        .await
        .unwrap();
    axum::serve(listener, app).await.unwrap();
}
```

With the server running:

```bash
curl -i http://127.0.0.1:8080/
curl -i 'http://127.0.0.1:8080/?cmd=$(whoami)'
```

The first request answers `200 OK`; the second is blocked by the engine with
`400 Bad Request` and a `Suspicious activity detected` body.

## Building from source

The repository itself consumes the stack as local path dependencies on
sibling checkouts (`tower-guard-rs`, which in turn points at
`guard-core-rs`; see the repository README), so building the repository
workspace locally requires those checkouts to exist. Downstream applications
that depend on the published crate are not affected: crates.io resolves
`tower-guard-rs` and `guard-core-engine` automatically.
