# syntax=docker/dockerfile:1.7
FROM rust:1.98.0-bookworm AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY migrations ./migrations
COPY templates ./templates
COPY static ./static
COPY src ./src
RUN --mount=type=cache,id=configdeck-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=configdeck-release-target,target=/build/target,sharing=locked \
    cargo build --locked --release \
    && cp /build/target/release/configdeck /tmp/configdeck

FROM debian:bookworm-slim AS runtime
LABEL org.opencontainers.image.title="ConfigDeck" \
    org.opencontainers.image.description="Self-hosted environment configuration and change-management platform" \
    org.opencontainers.image.authors="Firman Tarmizi" \
    org.opencontainers.image.licenses="MIT" \
    org.opencontainers.image.source="https://github.com/firmantarmizi/configdeck"
RUN groupadd --system --gid 10001 configdeck \
    && useradd --system --uid 10001 --gid configdeck --home-dir /nonexistent --shell /usr/sbin/nologin configdeck \
    && mkdir -p /data /backup \
    && chown configdeck:configdeck /data /backup
COPY --from=builder /tmp/configdeck /usr/local/bin/configdeck
USER 10001:10001
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/configdeck", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/configdeck"]
CMD ["serve"]
