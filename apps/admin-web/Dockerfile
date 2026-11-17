FROM docker.io/library/node:24.19.0-alpine@sha256:2a49bdf71e9fd965a58c1703fd9ddd205b34e5782b692a72dd1d248abb0beb43 AS build
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
    pnpm install --frozen-lockfile --ignore-scripts --filter @openpc/admin-web... --filter @openpc/control-api... --filter @openpc/module-registry... --filter @openpc/identity-service... --filter @openpc/participant-service...
# Keep all shared TypeScript owners: cross-service imports are bundled transitively.
COPY tsconfig.base.json ./
COPY packages/ packages/
COPY generated/ generated/
COPY schemas/ schemas/
COPY services/control-api/ services/control-api/
COPY services/identity-service/ services/identity-service/
COPY services/module-registry/ services/module-registry/
COPY services/participant-service/ services/participant-service/
COPY apps/admin-web/ apps/admin-web/
ARG OPENPC_BUILD_PROFILE=default
RUN case "$OPENPC_BUILD_PROFILE" in \
      default) pnpm --filter @openpc/admin-web build ;; \
      retained-qa-serial) OPENPC_BUILD_PROFILE=retained-qa-serial NODE_OPTIONS=--max-old-space-size=1536 pnpm --filter @openpc/admin-web build ;; \
      *) exit 64 ;; \
    esac

FROM docker.io/library/node:24.19.0-alpine@sha256:2a49bdf71e9fd965a58c1703fd9ddd205b34e5782b692a72dd1d248abb0beb43
WORKDIR /workspace
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1
RUN addgroup -S openpc && adduser -S -G openpc openpc
RUN rm -rf -- /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack && \
    rm -f -- /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack \
    /usr/local/bin/pnpm /usr/local/bin/pnpx /usr/local/bin/yarn /usr/local/bin/yarnpkg \
    /usr/local/bin/tsc /usr/local/bin/tsx
COPY --from=build --chown=openpc:openpc /workspace/apps/admin-web/.next/standalone ./
COPY --from=build --chown=openpc:openpc /workspace/apps/admin-web/.next/static ./apps/admin-web/.next/static
USER openpc
EXPOSE 3000
ENV PORT=3000 HOSTNAME=0.0.0.0
ENTRYPOINT ["node", "apps/admin-web/server.js"]
