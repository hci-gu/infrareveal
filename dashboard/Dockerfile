FROM node:24-alpine AS builder

WORKDIR /workspace

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY dashboard/package.json ./dashboard/package.json
COPY debug-dashboard/package.json ./debug-dashboard/package.json
COPY packages/session-state/package.json ./packages/session-state/package.json
RUN corepack enable && corepack prepare pnpm@11.25.0 --activate && pnpm install --frozen-lockfile

COPY packages/session-state ./packages/session-state
COPY dashboard ./dashboard
RUN pnpm --filter @infrareveal/dashboard run build

FROM nginx:1.29-alpine

COPY --from=builder /workspace/dashboard/dist /usr/share/nginx/html
COPY dashboard/nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
