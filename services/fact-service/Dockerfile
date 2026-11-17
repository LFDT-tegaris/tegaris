FROM docker.io/library/rust:1.98.0-bookworm@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922 AS build
ENV RUSTUP_TOOLCHAIN=1.98.0
WORKDIR /workspace
# Cargo workspace and generated contracts; browser/TypeScript edits do not invalidate Rust.
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/ crates/
COPY generated/ generated/
COPY schemas/ schemas/
COPY services/broker/ services/broker/
COPY services/explorer-adapter/ services/explorer-adapter/
COPY services/fact-service/ services/fact-service/
COPY services/fleet-controller/ services/fleet-controller/
COPY services/indexer-adapter/ services/indexer-adapter/
COPY services/multi-rpc/ services/multi-rpc/
COPY services/openpc-i00-bootstrap-service/ services/openpc-i00-bootstrap-service/
COPY services/pds/ services/pds/
COPY services/policy-compiler/ services/policy-compiler/
COPY services/runtime-agent/ services/runtime-agent/
COPY services/subquery-adapter/ services/subquery-adapter/
COPY services/thegraph-adapter/ services/thegraph-adapter/
ARG OPENPC_CARGO_BUILD_JOBS=1
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/workspace/target \
    case "$OPENPC_CARGO_BUILD_JOBS" in [1-8]) ;; *) exit 64 ;; esac && \
    cargo build --release --locked --jobs "$OPENPC_CARGO_BUILD_JOBS" -p openpc-fact-service --bin local_runtime && \
    cp /workspace/target/release/local_runtime /openpc-fact-local-runtime

FROM docker.io/library/debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171
COPY --from=build /openpc-fact-local-runtime /usr/local/bin/openpc-fact-local-runtime
USER 65532:65532
EXPOSE 8081
ENTRYPOINT ["/usr/local/bin/openpc-fact-local-runtime"]
