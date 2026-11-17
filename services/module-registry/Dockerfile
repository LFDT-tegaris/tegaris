FROM docker.io/library/rust:1.98.0-bookworm@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922 AS rust-build
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
    cargo build --release --locked --jobs "$OPENPC_CARGO_BUILD_JOBS" -p openpc-policy-compiler --bin openpc-policy-evaluator -p openpc-fact-service --bin policy_fact_reader && \
    cp /workspace/target/release/openpc-policy-evaluator /openpc-policy-evaluator && \
    cp /workspace/target/release/policy_fact_reader /policy_fact_reader

FROM docker.io/library/node:24.19.0-bookworm-slim@sha256:a9f5f7c91a432850b2a8a7797adf5eadb6c733ceed61167806cee7ea7fbc29df AS node-build
WORKDIR /workspace
RUN corepack enable && corepack prepare pnpm@11.20.0 --activate
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml .npmrc ./
COPY apps/admin-web/package.json apps/admin-web/
COPY packages/api-client/package.json packages/api-client/
COPY packages/design-system/package.json packages/design-system/
COPY packages/i18n/package.json packages/i18n/
COPY packages/security-kernel/package.json packages/security-kernel/
COPY packages/ui-extensions/package.json packages/ui-extensions/
COPY packages/ui-shell/package.json packages/ui-shell/
COPY services/control-api/package.json services/control-api/
COPY services/identity-service/package.json services/identity-service/
COPY services/module-registry/package.json services/module-registry/
COPY services/participant-service/package.json services/participant-service/
RUN --mount=type=cache,id=openpc-pnpm-store,target=/root/.local/share/pnpm/store,sharing=locked \
    --mount=type=cache,id=openpc-pnpm-cache-v11,target=/root/.cache/pnpm,sharing=locked \
    pnpm install --frozen-lockfile --ignore-scripts --filter @openpc/module-registry... --filter @openpc/control-api...
# Keep all shared TypeScript owners: cross-service imports are bundled transitively.
COPY tsconfig.base.json ./
COPY packages/ packages/
COPY generated/ generated/
COPY schemas/ schemas/
COPY services/control-api/ services/control-api/
COPY services/identity-service/ services/identity-service/
COPY services/module-registry/ services/module-registry/
COPY services/participant-service/ services/participant-service/
RUN pnpm --filter @openpc/module-registry exec esbuild src/local-runtime.ts \
    --bundle --platform=node --format=esm \
    --banner:js='import { createRequire } from "node:module"; const require = createRequire(import.meta.url);' \
    --outfile=/openpc-policy-runtime.mjs

FROM docker.io/library/node:24.19.0-bookworm-slim@sha256:a9f5f7c91a432850b2a8a7797adf5eadb6c733ceed61167806cee7ea7fbc29df
WORKDIR /app
RUN groupadd --system --gid 65532 openpc && useradd --system --gid openpc openpc
COPY --from=node-build --chown=openpc:openpc /openpc-policy-runtime.mjs /app/server.mjs
COPY --from=rust-build --chown=openpc:openpc /openpc-policy-evaluator /usr/local/bin/openpc-policy-evaluator
COPY --from=rust-build --chown=openpc:openpc /policy_fact_reader /usr/local/bin/policy_fact_reader
ENV OPENPC_POLICY_CORE_BIN=/usr/local/bin/openpc-policy-evaluator
ENV OPENPC_POLICY_FACT_READER_BIN=/usr/local/bin/policy_fact_reader
USER openpc
EXPOSE 3002
ENTRYPOINT ["node", "/app/server.mjs"]
