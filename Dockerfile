FROM node:24-bookworm-slim AS dependencies
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends openssl ca-certificates python3 make g++ && rm -rf /var/lib/apt/lists/*
COPY package.json package-lock.json ./
COPY apps/api/package.json apps/api/package.json
COPY apps/web/package.json apps/web/package.json
COPY apps/desktop/package.json apps/desktop/package.json
COPY apps/worker/package.json apps/worker/package.json
COPY packages/contracts/package.json packages/contracts/package.json
COPY packages/crypto-server/package.json packages/crypto-server/package.json
RUN npm ci
COPY . .
RUN npm run db:generate

FROM dependencies AS build
RUN npm run build -w @lk/api && npx tsc && npm run build -w @lk/web

FROM node:24-bookworm-slim AS api
WORKDIR /app
ENV NODE_ENV=production
RUN apt-get update && apt-get install -y --no-install-recommends openssl ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build --chown=node:node /app/node_modules ./node_modules
COPY --from=build --chown=node:node /app/dist ./dist
COPY --from=build --chown=node:node /app/package.json ./package.json
USER node
EXPOSE 4000
HEALTHCHECK --interval=15s --timeout=3s CMD node -e "fetch('http://localhost:4000/api/v1/health/ready').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node","dist/apps/api/src/main.js"]

FROM api AS worker
HEALTHCHECK NONE
CMD ["node","dist/apps/worker/src/main.js"]

FROM dependencies AS migrate
CMD ["npm","run","db:migrate"]

FROM node:24-bookworm-slim AS web
WORKDIR /app
ENV NODE_ENV=production PORT=3000 HOSTNAME=0.0.0.0
COPY --from=build --chown=node:node /app/apps/web/.next/standalone ./
COPY --from=build --chown=node:node /app/apps/web/.next/static ./apps/web/.next/static
USER node
EXPOSE 3000
CMD ["node","apps/web/server.js"]
