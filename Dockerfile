# The Artifact Council relay in a container: `docker compose up -d` (see compose.yaml and README.md).
# The code lives in /app; .env and .local/ live in the mounted /work, never in the image: only the
# files named here are copied (and .dockerignore admits nothing else).
FROM node:22-bookworm-slim
WORKDIR /app
# Hints name docker compose commands, not npm ones (check.mjs `command`).
ENV AC_DOCKER=1
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund && npm cache clean --force
COPY ac-relay.mjs check.mjs docker-entrypoint.sh .env.example holder-exclusions.txt ./
COPY sdk sdk
COPY scripts scripts
ENTRYPOINT ["sh", "/app/docker-entrypoint.sh"]
CMD ["start"]
