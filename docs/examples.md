# Examples

The repository ships two runnable applications under
[`examples/`](https://github.com/Guard-Core/axum-guard-rs/tree/master/examples).
Both use the real adapter surface (`with_guard` applied to axum routers with
`Router::layer`).

The example crates are workspace members and build against the in-repository
path dependencies, so building them locally requires sibling `tower-guard-rs`
and `guard-core-rs` checkouts (see the repository README).

## simple_app

A minimal guarded axum application
([`examples/simple_app`](https://github.com/Guard-Core/axum-guard-rs/tree/master/examples/simple_app)):

| Route | Guard | Behavior |
|---|---|---|
| `GET /health` | excluded | `200 ok` |
| `GET /` | guarded | `200` greeting |
| `GET /search?q=...` | guarded | `200 search ok`, or `400` when the query trips the engine |
| `POST /echo` | guarded | echoes the body; `400` for a threat, `413` over the body cap |

The excluded path is expressed with axum composition: the guarded routes live
on a router carrying the guard layer, and `Router::merge` combines it with an
unguarded `/health` router.

Run it:

```bash
cargo run -p axum-guard-simple-app
```

## advanced_app

A production-shaped guarded application
([`examples/advanced_app`](https://github.com/Guard-Core/axum-guard-rs/tree/master/examples/advanced_app))
that demonstrates the two knobs a real deployment tunes: environment-driven
engine configuration and route-scoped guard configuration. The `/admin`
sub-router is screened by a second, stricter `GuardLayer` (threat-score
threshold halved by default), while general routes use the default-derived
configuration, and `GET /health` lives on the unguarded router (`nest` plus
`merge` keep the two guard trees and the health route apart).

### Configuration

| Variable | Meaning | Default |
|---|---|---|
| `APP_ADDR` | Listen address | `0.0.0.0:8080` |
| `GUARD_MAX_CONTENT_LENGTH` | Engine `max_content_length` | `10000` |
| `GUARD_MAX_FULL_SCAN_BYTES` | Engine `max_full_scan_bytes` (also the default body cap) | `262144` |
| `GUARD_PRESERVE_ATTACK_PATTERNS` | Engine `preserve_attack_patterns` | `true` |
| `GUARD_SEMANTIC_THRESHOLD` | Engine `semantic_threshold` | `0.7` |
| `GUARD_THREAT_SCORE_THRESHOLD` | Engine `threat_score_threshold` (general routes) | `1.0` |
| `GUARD_BODY_CAP` | Adapter body buffering cap | `GUARD_MAX_FULL_SCAN_BYTES` |
| `GUARD_ADMIN_THREAT_SCORE_THRESHOLD` | Threat-score threshold for the `/admin` guard tree | half the general threshold |

### Routes

| Route | Guard tree | Behavior |
|---|---|---|
| `GET /health` | excluded | `200 ok` |
| `GET /` | general | `200`, greeting text |
| `GET /search?q=...` | general | `200`, or `400` on a threat |
| `POST /echo` | general | echoes the body; `400`/`413` from the guard |
| `GET /admin/stats` | stricter admin guard | screened by a second `GuardLayer` with a lower threat-score threshold |

Run it directly or with the provided Docker setup:

```bash
cargo run -p axum-guard-advanced-app
```

```bash
cd examples/advanced_app
docker compose up
```
