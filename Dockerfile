# syntax=docker/dockerfile:1
FROM node:24-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json tsconfig.build.json ./
COPY tools/build-web.mjs ./tools/build-web.mjs
COPY src ./src
COPY public ./public
RUN npm run build && npm prune --omit=dev

FROM node:24-alpine
WORKDIR /app
ENV NODE_ENV=production CONFIG_FILE=/app/config/verifier.yaml PORT=8374
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY package.json ./
COPY config/verifier.example.yaml ./config/verifier.yaml
COPY config/credential-types.json ./config/credential-types.json
COPY --from=build /app/public ./public
# Writable directory for wallet compatibility results (mount a volume to keep them)
RUN mkdir -p /app/data && chown node:node /app/data
USER node
EXPOSE 8374
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://127.0.0.1:${PORT}/healthz || exit 1
CMD ["node", "dist/server/main.js"]
