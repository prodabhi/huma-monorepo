FROM node:24.22.1-bookworm-slim@sha256:55fb5f5a527ea2c5c4a95f963e48ef90aa38c7b346054fdc8ee9957a2b55d205 AS dependencies
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund

FROM node:24.22.1-bookworm-slim@sha256:55fb5f5a527ea2c5c4a95f963e48ef90aa38c7b346054fdc8ee9957a2b55d205
WORKDIR /app
ENV NODE_ENV=production HUMA_STORAGE_BACKEND=r2 HUMA_REGISTRY_HOST=0.0.0.0 HUMA_REGISTRY_PORT=4318
COPY --from=dependencies /app/node_modules ./node_modules
COPY . .
RUN mkdir -p frontend/data && chown node:node frontend/data
USER node
EXPOSE 4318
CMD ["node", "frontend/registry.mjs"]
