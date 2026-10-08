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

## Development Commands

CI is the source of truth (`.github/workflows/ci.yml`); there is no Makefile.

```bash
cargo check --all-targets                              # type check
cargo fmt --all -- --check                             # format gate
cargo clippy --all-targets -- -D warnings              # lint gate (pedantic is warn, so -D warnings enforces it)
cargo test                                             # integration + doctests (workspace: adapter + examples)
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps         # rustdoc gate
cargo deny check                                       # advisories, licenses, bans, sources (deny.toml)
```

Sibling checkouts at `../tower-guard-rs` and `../guard-core-rs` are required for every command.

The example apps under `examples/` build and run like any workspace member:

```bash
docker compose -f examples/simple_app/docker-compose.yml up --build -d --wait    # live smoke stack
SMOKE_PORT=8091 docker compose -f examples/simple_app/docker-compose.yml up ...   # remapped host port
```

The compose stacks also need the sibling checkouts: the Dockerfile receives
their source through compose `additional_contexts` entries named `tower` and
`engine` pointing at `../../../tower-guard-rs` and `../../../guard-core-rs`
(relative to the compose file). The `live-smoke` workflow runs the simple_app
stack and the full curl assertion matrix on every push/PR; `upstream-drift`
runs the suite daily against fresh `tower-guard-rs@master` and
`guard-core-rs@master` checkouts placed at the path dependency locations.
`security.yml` runs `cargo deny check` on push/PR and weekly. `release.yml`
gates `v*` tag pushes with the full suite plus a tag/version consistency
check; crates.io publishing is manual and owner-gated.

## Project Structure

```
axum-guard-rs/
├── Cargo.toml / Cargo.lock          # adapter package + workspace (examples are members)
├── deny.toml                        # cargo-deny: advisories, licenses, bans, sources
├── src/lib.rs            # crate docs, with_guard, re-exports from tower-guard-rs
├── tests/axum.rs         # Router::layer behavior pinned against axum::body::Body
├── examples/
│   ├── simple_app/       # minimal guarded Router: main.rs, Dockerfile, compose, README
│   └── advanced_app/     # env-driven config, route-scoped guards: main.rs, Dockerfile, compose, README
└── .github/
    ├── workflows/ci.yml             # push/PR: fmt, clippy, test, doc, MSRV
    ├── workflows/security.yml       # push/PR + weekly: cargo deny check
    ├── workflows/live-smoke.yml     # push/PR: dockerized simple_app smoke with curl assertions
    ├── workflows/upstream-drift.yml # daily: suite against siblings at master
    ├── workflows/release.yml        # v* tag gate: matrix test + tag/version consistency
    └── workflows/issue-link.yml     # PRs must reference an open issue
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
3. **Run the full local gate before committing**: fmt, clippy, test, doc, cargo deny. CI runs all five.
4. **Example apps are part of the workspace.** `examples/simple_app` and `examples/advanced_app` build with a plain `cargo build` from the repo root; when the adapter surface or response shapes change, update the examples and their READMEs (and re-run the live smoke assertions) in the same change.
5. **Conventional commits** (`feat:`, `fix:`, `docs:`, `ci:`), matching history. No AI attribution in commit messages.
6. **Document status honestly.** Nothing here is published; say so rather than implying a crates.io release. crates.io publishing is manual and owner-gated.
7. **Update the README behavior tables** when the inherited mapping, response shapes, or cap semantics change (and mirror the change in `tower-guard-rs`).
8. **Keep the engine surface claims honest.** guard-core-rs currently ships the CPU-bound detection pipeline only: no Redis, rate limiter, or ban manager. Do not document capabilities the engine does not expose.

## Related Projects

- [tower-guard-rs](https://github.com/Guard-Core/tower-guard-rs): the generic `tower` implementation this crate composes.
- [guard-core-rs](https://github.com/Guard-Core/guard-core-rs): the Rust detection engine.
- [guard-core-ts](https://github.com/Guard-Core/guard-core-ts): TypeScript port, source of the view mapping this adapter follows.
- [guard-core](https://github.com/Guard-Core/guard-core): Python reference implementation and spec owner.
