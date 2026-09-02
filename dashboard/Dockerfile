FROM node:24-alpine AS builder

WORKDIR /workspace

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY dashboard/package.json ./dashboard/package.json
COPY debug-dashboard/package.json ./debug-dashboard/package.json
COPY packages/session-state/package.json ./packages/session-state/package.json
# pnpm 7 otherwise prunes Rolldown's platform binding from a frozen workspace install.
RUN corepack enable && corepack prepare pnpm@7.16.0 --activate && pnpm install --frozen-lockfile --force

COPY packages/session-state ./packages/session-state
COPY dashboard ./dashboard
RUN pnpm --filter @infrareveal/dashboard run build

FROM nginx:1.29-alpine

COPY --from=builder /workspace/dashboard/dist /usr/share/nginx/html
COPY dashboard/nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
