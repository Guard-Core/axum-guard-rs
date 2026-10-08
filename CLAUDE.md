# AGENTS.md
Guidance for AI agents (including Claude Code) working in this repository.

## Project Overview

axum-guard-rs is the axum adapter for the Guard ecosystem. It provides `with_guard(config)`, returning the [`GuardLayer`](https://docs.rs/tower/latest/tower/trait.Layer.html) from [tower-guard-rs](https://github.com/Guard-Core/tower-guard-rs), which drops straight into `Router::layer`. Axum middleware is tower middleware, so there is no axum-specific screening code here: this crate is the axum-facing surface (constructor, re-exports, axum-typed tests) over the shared `tower` implementation, backed by the [guard-core-rs](https://github.com/Guard-Core/guard-core-rs) detection engine.

- **Repository**: https://github.com/Guard-Core/axum-guard-rs
- **Language**: Rust, edition 2024, MSRV 1.92
- **License**: MIT OR Apache-2.0
- **Version**: 0.1.0
- **Status**: implemented and tested. Not published to crates.io: dependencies are local paths until the siblings are tagged (see [Sibling Dependencies](#sibling-dependencies)).

## Ecosystem Position

```
guard-core (Python)                  <- Reference implementation, spec owner
├── guard-core-rs                    <- Rust engine crate: guard-core-engine (detect, preprocessor, semantic, compiler)
│   ├── tower-guard-rs               <- Framework-agnostic tower Layer + Service
│   │   └── axum-guard-rs (this)     <- axum surface: with_guard, re-exports, axum-typed tests
│   ├── actix-guard-rs               <- Adapter (scaffold)
│   └── rocket-guard-rs              <- Adapter (scaffold)
└── guard-core-ts                    <- TypeScript port (source of the adapter view mapping)
```

The security behavior lives in `tower-guard-rs` and the engine. This crate owns the axum integration contract: it must keep working against `axum::body::Body` and `Router::layer`.

## Boundary Rules

- **No security logic in this crate**, and no duplicated screening logic either: request inspection belongs in `tower-guard-rs`, detection in the engine.
- **No new middleware implementation.** Do not reimplement body buffering or view scanning against `axum::body::Body`. If an axum-specific need appears (for example `axum::extract::Request` handling), the fix goes in `tower-guard-rs` as a generic mechanism.
- **Keep the dependency set minimal**: `axum` plus `tower-guard-rs` in `[dependencies]`. Test-only crates (tokio, tower `util`, serde_json, http-body-util) stay in `[dev-dependencies]`.
- **Fail-secure is inherited, not re-decided.** Any change that would make a body read error or engine panic pass through must be rejected.

## How the Integration Works

- `with_guard(config) -> GuardLayer` (re-exported from `tower-guard-rs`), applied with `Router::layer` or `Router::route_layer`.
- `GuardService<Route>` satisfies axum's `Router::layer` bounds: `Response = Response<GuardBody<axum::body::Body>>`, which is `IntoResponse` because `GuardBody<Body>: http_body::Body<Data = Bytes, Error = BoxError> + Send + 'static`.
- `axum::body::Body` implements `From<Bytes>` (the rebuild bound the guard relies on) and `http_body::Body<Data = Bytes, Error = BoxError>`. It does **not** implement `From<Full<Bytes>>`; do not add that assumption.
- Extraction is unaffected: `State`, `Json`, and other extractors run in handlers after the guard forwards the request.

## Sibling Dependencies

- `tower-guard-rs = { path = "../tower-guard-rs", version = "0.1.0" }` and, transitively, `guard-core-engine = { path = "../guard-core-rs/crates/guard-core-engine" }`.
- **TODO(engine):** switch both to versioned crates.io dependencies once `tower-guard-rs` and `guard-core-rs` are tagged and published.
- CI checks out `Guard-Core/tower-guard-rs` (`master`, flipped after the engine integration merged) and `Guard-Core/guard-core-rs` (`master`), moving both to the path locations. Moving branches are a deliberate, documented supply-chain tradeoff, mirroring `laravel-guard`/`symfony-guard`.
- When `tower-guard-rs` merges to master, update `.github/workflows/ci.yml` (two `ref:` lines), the README, and this file in the same change.

## Development Commands

CI is the source of truth (`.github/workflows/ci.yml`); there is no Makefile.

```bash
cargo check --all-targets                              # type check
cargo fmt --all -- --check                             # format gate
cargo clippy --all-targets -- -D warnings              # lint gate (pedantic is warn, so -D warnings enforces it)
cargo test                                             # integration + doctests
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps         # rustdoc gate
```

Sibling checkouts at `../tower-guard-rs` and `../guard-core-rs` are required for every command.

## Project Structure

```
axum-guard-rs/
├── src/lib.rs            # crate docs, with_guard, re-exports from tower-guard-rs
├── tests/axum.rs         # Router::layer behavior pinned against axum::body::Body
└── .github/workflows/ci.yml
```

## Testing

- `cargo test` runs 12 integration tests plus 2 doctests. All must pass.
- Coverage must include: benign GET via the router, JSON body round-trip through `Json` extraction, `State` extraction unaffected, XSS body blocked, traversal in path blocked (`url_path`), command injection in query blocked (`query_param`), XSS in a scanned header blocked, benign `Authorization`/`Cookie`/`User-Agent` headers not tripping the guard, oversize body `413`, unmatched route still `404`, 16 concurrent requests screened independently, and `poll_ready` forwarding through the router.
- Panic recovery is tested in `tower-guard-rs` (its `#[cfg(test)]` detector seam is crate-private); this crate relies on that behavior instead of exposing a public injection API.
- Payloads must come from the spec 4.0.2 conformance corpus (`guard-core-rs/conformance/guard-core-spec-4.0.2/cases/`) so they are guaranteed threats. Prefer extending coverage in `tower-guard-rs` when the case is not axum-specific.

## Code Quality Standards

- `[lints]` in `Cargo.toml`: `unsafe_code = "forbid"`, `clippy::all = "deny"`, `clippy::pedantic = "warn"` (enforced as errors by CI's `-D warnings`). `clippy::nursery` is deliberately not enabled: its lints drift between clippy versions.
- No `#[allow(...)]` in `src/`.
- rustdoc warnings are errors in CI.
- `axum` is declared with `default-features = false, features = ["http1", "json", "tokio"]`; add a feature deliberately (and update this file) if a new one is needed.

## Best Practices

1. **Keep this crate thin.** New behavior belongs in `tower-guard-rs` (generic) or the engine (security), not here.
2. **Keep the doctests compiling**: `src/lib.rs` and README examples are part of the test suite.
3. **Run the full local gate before committing**: fmt, clippy, test, doc. CI runs all four.
4. **Conventional commits** (`feat:`, `fix:`, `docs:`, `ci:`), matching history. No AI attribution in commit messages.
5. **Document status honestly.** Nothing here is published; say so rather than implying a crates.io release.
6. **Update the README behavior tables** when the inherited mapping, response shapes, or cap semantics change (and mirror the change in `tower-guard-rs`).

## Related Projects

- [tower-guard-rs](https://github.com/Guard-Core/tower-guard-rs): the generic `tower` implementation this crate composes.
- [guard-core-rs](https://github.com/Guard-Core/guard-core-rs): the Rust detection engine.
- [guard-core-ts](https://github.com/Guard-Core/guard-core-ts): TypeScript port, source of the view mapping this adapter follows.
- [guard-core](https://github.com/Guard-Core/guard-core): Python reference implementation and spec owner.
