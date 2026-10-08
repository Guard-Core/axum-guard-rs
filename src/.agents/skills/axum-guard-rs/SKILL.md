---
name: axum-guard-rs
description: Use when working in the axum-guard-rs Rust crate (github.com/Guard-Core/axum-guard-rs): changing the with_guard constructor or re-exports, adjusting the axum Router::layer integration with tower-guard-rs, updating the sibling path dependencies or the CI checkout steps, debugging axum body/IntoResponse bound issues with GuardService, or answering questions about what the axum adapter inspects and blocks. Covers CI-verified cargo commands, why security logic must not be duplicated here, and the trait-bound facts about axum::body::Body the integration depends on.
---

# axum-guard-rs

The axum adapter for the Guard ecosystem: `with_guard(config)` returns `tower-guard-rs`'s `GuardLayer` for use with `Router::layer`. Thin surface on purpose; the screening implementation lives in `tower-guard-rs`, the detection in `guard-core-engine`.

## Quick Reference

```bash
# Sibling checkouts at ../tower-guard-rs and ../guard-core-rs are required.
cargo check --all-targets
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings   # pedantic is warn, so this enforces it
cargo test                                  # 12 integration + 2 doctests
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
```

## Public API

- `with_guard(config: DetectConfig) -> GuardLayer`: apply with `Router::layer` (registered routes) or `Router::route_layer`. Chain `.with_body_cap(n)` on the returned layer to change the body cap (default 262 144 bytes).
- Re-exports from `tower-guard-rs`: `GuardLayer`, `GuardService`, `GuardBody`, `DetectConfig`, `DetectVerdict`, `Threat`, `default_config`, `BoxError`, `BLOCKED_MESSAGE`, `OVERSIZE_MESSAGE`, `FAILURE_MESSAGE`.

## Behavior (inherited from tower-guard-rs)

- Views: `url_path` (path, not `/`), `query_param` (query string), `header` (non-excluded names; `host`, `user-agent`, `accept`, `accept-encoding`, `connection`, `origin`, `referer`, and all `sec-*` are excluded), `request_body` (buffered, capped).
- Block `403` + `Suspicious activity detected`; oversize `413`; body read error or engine panic `500` + `Security check failed`. Fail-secure, unlike the TypeScript adapters.
- `Router::layer` does not wrap the fallback: unmatched paths answer `404` without passing the guard. Document this rather than "fixing" it here.

## Trait-Bound Facts (do not regress)

- `GuardService<Route>` satisfies `Router::layer`'s bounds because `Response<GuardBody<axum::body::Body>>` is `IntoResponse` (`GuardBody<Body>: http_body::Body<Data = Bytes, Error = BoxError> + Send + 'static`).
- `axum::body::Body` implements `From<Bytes>` and `http_body::Body`, but NOT `From<Full<Bytes>>`. The guard's rebuild bound is therefore `From<Bytes>`; changing it back breaks the whole integration.
- `Body` is `Unpin`, which the guard's `GuardBody` poll implementation relies on.

## Footguns

- Panic recovery is tested in `tower-guard-rs` via a `#[cfg(test)]` detector seam; it is deliberately not public and not re-tested here.
- Dependencies are path deps (`../tower-guard-rs`, transitively `../guard-core-rs/crates/guard-core-engine`) with a `TODO(engine)` to move to versioned crates. CI checks out `Guard-Core/tower-guard-rs@master` and `Guard-Core/guard-core-rs@master`.
- Payloads in tests must come from the spec 4.0.2 corpus so they are guaranteed threats.
- `axum` uses `default-features = false, features = ["http1", "json", "tokio"]`; adding a feature is a deliberate act.

## Related

- `tower-guard-rs`: the generic implementation; put new behavior there.
- `guard-core-rs`: the engine; put detection changes there.
