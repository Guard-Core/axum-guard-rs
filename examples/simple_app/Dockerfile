# Build context is the repository root (see docker-compose.yml):
#   docker build -f examples/simple_app/Dockerfile .
#
# The adapter consumes its siblings as path dependencies, so the build needs
# their source too. They are provided through additional build contexts named
# "tower" and "engine" (compose additional_contexts / docker --build-context
# pointing at sibling checkouts); only manifests and source are copied out of
# those contexts.
FROM rust:1.95-slim-bookworm AS build

WORKDIR /build

COPY --from=engine /Cargo.toml ./guard-core-rs/Cargo.toml
COPY --from=engine /Cargo.lock ./guard-core-rs/Cargo.lock
COPY --from=engine /crates/guard-core-engine ./guard-core-rs/crates/guard-core-engine
COPY --from=engine /crates/guard-core-rs ./guard-core-rs/crates/guard-core-rs

COPY --from=tower /Cargo.toml ./tower-guard-rs/Cargo.toml
COPY --from=tower /Cargo.lock ./tower-guard-rs/Cargo.lock
COPY --from=tower /src ./tower-guard-rs/src

COPY Cargo.toml Cargo.lock ./axum-guard-rs/
COPY src ./axum-guard-rs/src
COPY examples ./axum-guard-rs/examples

WORKDIR /build/axum-guard-rs
RUN cargo build --release -p axum-guard-simple-app

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --no-create-home --uid 10001 guard

COPY --from=build /build/axum-guard-rs/target/release/axum-guard-simple-app /usr/local/bin/simple-app

USER guard

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/simple-app"]
