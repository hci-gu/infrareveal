FROM --platform=$BUILDPLATFORM node:22-bookworm-slim AS builder

WORKDIR /workspace

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY dashboard/package.json ./dashboard/package.json
COPY debug-dashboard/package.json ./debug-dashboard/package.json
COPY packages/session-state/package.json ./packages/session-state/package.json
RUN corepack enable && corepack prepare pnpm@11.25.0 --activate && pnpm install --frozen-lockfile

COPY packages/session-state ./packages/session-state
COPY testdata ./testdata
COPY debug-dashboard ./debug-dashboard
ENV VITE_POCKETBASE_URL=/
RUN pnpm --filter @infrareveal/debug-dashboard run build

FROM nginx:1.29-alpine

COPY --from=builder /workspace/debug-dashboard/dist /usr/share/nginx/html
COPY debug-dashboard/nginx.conf /etc/nginx/templates/default.conf.template
ENV ADMIN_IP=10.77.0.1

EXPOSE 8081
