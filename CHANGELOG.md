# Changelog

All notable changes to this project.

## [Unreleased]

## [1.3.0] - 2026-10-01

### Note

- Trains with the engine: the `tower-guard-rs` floor moves to 1.3.0 (and through it the `guard-core-engine` and `guard-core-rs` floors to 4.3.0, the safety-chain release). The adapter ships no logic changes of its own

### Changed

- Process and CI chores: the community and security process scaffold plus the sync-labels checkout pin and the cargo audit step (#22), the 100% line coverage gate enforced with cargo-llvm-cov (#23), the CDLA-Permissive-2.0 license allowed from the engine sibling's graph (#32), and the routine GitHub Actions dependency bumps with the lockfile tracking the engine master graph (#24-#28, #30, #31)

## [1.2.0] - 2026-09-27

### Note

- Trains with the engine: `guard-core-engine`, `guard-core-rs`, and `tower-guard-rs` floors move to 4.2.0/1.2.0 (the 4.1.0 engine dists were yanked; this release restores registry resolution)

### Added

- The wave engine surfaces are reachable through `with_guard`'s `GuardLayer` (the tower reference implementation's builders, re-exported types included): route/geo rate-limit tiers (`with_route_tiers` + the `RouteRateLimits` request extension, `with_geo_handler`), per-route detection exclusions (`with_detection_exclusions` + the `RouteDetectionExclusions` request extension), the event bus and observability knobs (`with_event_bus`, `with_observability`), `on_block` + custom error bodies (`with_on_block`, `with_custom_error_responses`), the distributed stores (`with_distributed_store` + `with_distributed_ban_store`), and passive mode (`with_passive_mode`). New re-exports: `DetectionExclusionConfig`, `RouteDetectionExclusions`, `GeoIpHandler`, `BanStore`, `SlidingWindowStore`, `RouteRateLimits`, `RateLimitEntry`, `RateLimitTier`, `TierDecision`, `SecurityEventBus`, `ObservabilityConfig`, `RequestObservation`, `StageResponse`, `BlockPayload`, `OnBlockHook`, `CustomErrorResponses`
- axum-specific integration tests pin each surface end to end through a `Router` (`Router::layer` + `oneshot`)

### Changed

- `tower-guard-rs` (and through it the `guard-core-rs` facade and `guard-core-engine` engine) remains the single engine dependency; the axum adapter gains no logic of its own, only the re-export surface and the axum-shaped tests
- Exempt IPs now feed the violation counters (the reference suspicious-activity stage skips a whitelisted IP only; detection still scans and blocks them), so a crossed threshold bans even an exempt attacker - the tower reference's updated contract, pinned by an axum test


### Added

- The stateful stage from `tower-guard-rs` (rate limiting, dynamic bans, auto-ban), exposed for axum with no new code: `with_guard(detect_config).with_rate_limiting(RateLimiter)` answers a sliding-window crossing with `429 Too Many Requests` carrying `Retry-After: <window seconds>`, and `with_ip_banning(IpBanManager, IpBanConfig)` answers a live ban with `403 Forbidden` (`IP address banned`) before the limiter (banned traffic never consumes rate budget), counts every detected threat's categories per client IP, and bans on the spot with `403 Forbidden` (`IP has been banned`) when a `threat_ban_config` entry or the flat `auto_ban_threshold` crosses. With the limiter's `enable_rate_limit_auto_ban` on, every crossing counts one `rate_limit` violation (the response stays 429, the ban bites the next request); with `enable_ip_banning = false` violations count but never ban. Both stages honor the `exempt_ips` contract (whitelisted and exempt IPs are never rate limited, never banned, never counted) and unattributed requests (no `client_ip_layer()`) skip the stage but stay detection-screened
- Re-exports for the stateful surface (`RateLimiter`, `RateLimitConfig`, `RateLimitConfigError`, `RateLimitDecision`, `IpBanManager`, `IpBanConfig`, `IpBanConfigError`, `BanRecord`, `BanError`, `ResolvedBan`, `ThreatBanEntry`, `ViolationCounters`, `Clock`, `BANNED_MESSAGE`, `ACTIVITY_BANNED_MESSAGE`, `RATE_LIMITED_MESSAGE`)
- An axum-level stateful-stage test suite in `tests/axum.rs` (crossing shape with `Retry-After`, exempt IP under load, live ban before detection and the limiter, ban expiry via a fake clock, category-threshold and rate-limit auto-ban, disabled banning, unattributed skip), mirroring the tower reference suite

### Changed

- Detection blocks now answer `400 Bad Request` with `Suspicious activity detected` (the reference suspicious-activity stage's shape) instead of `403 Forbidden`; the shape comes from `tower-guard-rs`, so this is a documentation and test-expectation update here. Live-ban `403 Forbidden` denials are unchanged.

## [1.1.0] - 2026-09-26

### Added

- The global IP gate from `tower-guard-rs`, wired for axum: `with_guard(detect_config).with_ip_gate(IpGateConfig::new(whitelist, blacklist, exempt_ips))` denies a blacklisted client IP (or one a non-empty `whitelist` matches neither directly nor through `exempt_ips`) with `403 Forbidden` before detection, and passes everyone else through with the skip-state decision in the request extensions. `exempt_ips` is noise reduction for known-friendly automation, not immunity: it never adds a deny path, never opens the whitelist gate, and detection still scans exempt IPs. The new `client_ip_layer()` copies axum's `ConnectInfo<SocketAddr>` into the `GuardClientIp` extension the gate reads (apply it after the guard layer); unattributed requests are not gated and still screened. Invalid list entries fail closed at config construction
- Re-exports for the gate surface (`IpGateConfig`, `IpGateDecision`, `IpGateDenial`, `IpGateError`, `IpGateVerdict`, `GuardClientIp`, `FORBIDDEN_MESSAGE`)

### Changed

- `tower-guard-rs` dependency pinned to the published 1.1.0 release (path dep kept for local builds and CI against a sibling checkout), itself pinning `guard-core-engine` 4.1.0 (stateful sliding-window rate limiter and dynamic IP ban engine, tower stage with a reusable `decide()`, and the new detection stages: request size/content, user-agent, headers/auth, cloud provider blocking, geo blocking)
- The `with_guard` example constructs the full `DetectConfig`, which now carries the engine's `detection_binary_min_run_length` knob (default 16) alongside the existing reference defaults; the body view itself gains the engine's content-type body-value extraction (form fields, multipart parts, embedded JSON leaves, mongo operator keys) and the binary-islands reduction for binary-dense uploads through the shared `tower-guard-rs` layer, with no axum-facing API change
- 403/413/500 short-circuit responses now carry the bare message (`Suspicious activity detected`, `Payload too large`, `Security check failed`) as `text/plain; charset=utf-8`, matching the Python family's block-response convention, instead of the JSON `{"detail":"..."}` shape (the bodies come from `tower-guard-rs`, so no code change was needed here)

## [1.0.0] - 2026-09-24

### Added

- First stable release of `axum-guard-rs` 1.0.0: application-layer security middleware for axum 0.8, composing `tower-guard-rs` 1.0.0 (powered by `guard-core-engine` 4.0.4, 17/17 checks parity with guard-core 4.0.4, binary-noise gates)
- Guard layer wiring for axum `Router`s: one engine call per request view (path, query string, headers, buffered body), 403/413/500 fail-secure responses with the ecosystem JSON `detail` shape, configurable body cap (default: engine full-scan cap)
- Example apps: `examples/simple_app` and `examples/advanced_app` with Dockerfiles and docker-compose smoke stacks
- Dockerized live smoke workflow (`.github/workflows/live-smoke.yml`): compose run of `simple_app` with curl assertions of real engine behavior (XSS block, traversal block, 413 body cap, passthrough)
- Upstream drift guard (`.github/workflows/upstream-drift.yml`): daily test suite run against `guard-core-rs@master`
- Security audit workflow (`cargo deny`), release gate (fmt/clippy/test at tag on stable and MSRV 1.92, tag/version consistency), automated crates.io publish on GitHub release via `CARGO_REGISTRY_TOKEN`
- `Makefile` (`install`, `test`, `lint`, `fix`, `bump-version`, `clean`) and `.github/scripts/bump_version.py` (stdlib-only version bump across the crate, example pins, `Cargo.lock`, and a CHANGELOG scaffold)

### Changed

- `tower-guard-rs` dependency pinned to the published 1.0.0 release (path dep kept for local builds and CI against a sibling checkout)
