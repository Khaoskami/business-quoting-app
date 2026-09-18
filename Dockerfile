FROM oven/bun:1 AS builder
WORKDIR /app

COPY package.json bun.lock* ./
RUN bun install --frozen-lockfile

COPY . .
RUN bun run build

FROM oven/bun:1
WORKDIR /app

RUN apt-get update \
  && apt-get install -y --no-install-recommends chromium fonts-noto-core fonts-noto-extra \
  && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/dist         ./dist
COPY --from=builder /app/server       ./server
COPY --from=builder /app/drizzle.config.ts ./
COPY --from=builder /app/package.json ./

EXPOSE 3000
ENV NODE_ENV=production
ENV CHROMIUM_PATH=/usr/bin/chromium

CMD ["bun", "start"]
