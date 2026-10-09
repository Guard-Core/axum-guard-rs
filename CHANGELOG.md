# Changelog

All notable changes to this project.

v1.5.0 (2026-10-09)
-------------------

The consumption release: the unified config, the route-config carrier knobs, the response-pass funnels, and the behavioral lanes land, training with the 4.3.2 route-config engine (v1.5.0)
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

### Note

- Trains with the family: the `tower-guard-rs` floor moves to 1.5.0, and with it the `guard-core-engine` (direct) and `guard-core-rs` (dev) floors move to 4.3.2 (the route-config train)

### Added

- The `get_cloud_providers_to_check` route-over-global resolution through the axum idiom (the RC2 axum leg): the lane lands in the tower `GuardLayer`'s pipeline (the tower leg), and the axum twin pins the axum-facing contract end to end through a `Router` - the route's GCP list overriding the global AWS list on its route (the AWS address the global lane blocks passes), the global lane holding off-route
- The carrier's stage knobs through the axum idiom (the RC1 axum leg): the lanes land in the tower `GuardLayer`'s pipeline (the tower leg), and the axum twins pin the axum-facing contract end to end through `Router`s - the route `ip_whitelist` override against the global gate, the `required_headers` and `require_referrer` carriers, and the `enable_suspicious_detection = false` scan toggle, each on a matching route and its off-route silence
- The `security_headers_applied` funnel through the axum idiom (the H6 axum leg, over guard-core-rs#103's composer and #104's accessor): the funnel lands in the tower `GuardLayer`'s response pass (the tower leg), and the axum twins pin the axum-facing contract end to end through a `Router` layered with `with_guard` - the forwarded emission (action `headers_added`, handler `security_headers`, the display-redacted path, `headers_count` over the rendered set, `has_csp`/`has_hsts`), the generated lane applying the headers without firing, and the disabled set rendering nothing and dispatching nothing with the rate-limit crossing as the live-bus control
- The maintenance surface and the full status payload (the GAP-R9 axum leg): the re-exported `GuardLayer`/`GuardService` carry the tower suite's reference maintenance trio - `reset` (the rate-limit windows drop), `refresh_cloud_ip_ranges` + `with_cloud_refresh_scheduler` (one single-flight background refresh through the facade's `CloudRefreshScheduler`, the refreshed ranges landing in the shared table), and `agent_stats` (the reference property's no-agent shape, `AgentStats` re-exported); the status payload's provider rows carry the reference `get_status` shape (`ready`, `last_refreshed`, `entries`) and the geo-ip component renders the `IpInfoManager` health snapshot when the lifecycle manager is wired (`guard-core-rs` joins the dependency set for the manager type)
- The route-config carrier surface (the GAP-R2 axum leg): `RouteConfig` + `RouteConfigResolver` re-exported and `GuardLayer::with_route_configs` reachable from the thin surface - the tower pipeline resolves the route's `RouteConfig` per request ((method, path), an `Arc<RouteConfig>` request extension winning over the resolver) and consumes it with the reference semantics: `bypassed_checks` (+ the `"all"` wildcard) skip the named checks, `require_https` forces the reference `301`, `max_request_size` replaces the route's body cap, `blocked_user_agents` runs additively before the global filter, the rate-limit group becomes the route's tier, and the detection-exclusion group resolves for the route; end-to-end Router twins pin the bypass semantics, the redirect, the tier, the extension precedence, the additive UA list, and the fail-secure invalid tier
- The unified-config consumption (`with_security_config`, the GAP-R1 axum leg): the 129-field `SecurityConfig` (the fieldized reference surface in guard-core-engine) builds the wired pipeline in one call under the axum constructor name - `GuardLayer::from_security_config` re-exported through the thin surface, with `SecurityConfig`, `SecurityConfigError`, `GuardConfigError`, and the `LogLevel`/`LogFormat`/`BufferOverflowPolicy` knob enums re-exported alongside; invalid values fail closed through the typed `GuardConfigError`; the reference `exclude_paths` carve-out and the ip_filter denial behaviors (passive logs-and-forwards, the `on_block` hook with the `ip_security` payload keys, the custom-error body override) ride the same call; end-to-end Router twins pin every consumed group through `oneshot`

### Changed

- The route-config bypass consumption follows the reference's coarse query vocabulary (the tower pipeline's queries: `ip` for the gate, the route IP restrictions, and the country arms; `ip_ban` for the ban arm; `clouds`; `rate_limit`; `penetration` for the scan; the `"all"` wildcard), and the route-config twins carry the corrected names
- The CI coverage gate computes line coverage from the lcov export's per-line DA records instead of llvm-cov's summary table: llvm-cov 22's summary aggregation falsely reports missed lines that no line-level view (show text/html, lcov, cobertura, the JSON segment list) can see on the same profdata, and the divergence persists on the newest available toolchain (cargo-llvm-cov 0.9.1 + rustc 1.99.0). The gate keeps the same fail-closed 100%-lines semantics with nothing hidden or excluded; the summary table stays in the job as an informational printout. Evidence linked in the workflow (#36)

v1.4.0 (2026-10-07)
-------------------

The reference-surface release: the status route and the WebSocket upgrade layer land, training with the 4.3.1 parity-completion engine (v1.4.0)
-----------------------------------------------------------------------------------------------------------------------------------------------

### Note

- Trains with the family: the `tower-guard-rs` floor moves to 1.4.0, and with it the `guard-core-engine` (direct) and `guard-core-rs` (dev) floors move to 4.3.1 (the parity-completion release)

### Added

- The reference status route (fastapi-guard `add_status_route` + `HandlerInitializer.get_initialization_status`): `GuardStatus` + `status_router` mount GET `/_guard/status` serving the cloud-provider readiness table and the geo-ip component from the handles the app already holds (#37)
- The WebSocket upgrade guard (`WebSocketGuard` layer): the reference upgrade sequence (fail-secure unknown address, `is_ip_banned`, the `is_ip_allowed` gate + country arms, the ws rate limit, the path/query/header penetration scan) runs before the axum handshake, rejecting with `403` pre-accept plus the `1008`/`1013` close shapes on dedicated headers; `guard-core-engine` moves to a direct dependency for the upgrade-sequence primitives (#37)

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
