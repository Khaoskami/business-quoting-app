FROM oven/bun:1 AS builder
WORKDIR /app

COPY package.json bun.lock* ./
RUN bun install --frozen-lockfile

COPY . .
RUN bun run build

FROM oven/bun:1
WORKDIR /app

COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/dist         ./dist
COPY --from=builder /app/server       ./server
COPY --from=builder /app/drizzle.config.ts ./
COPY --from=builder /app/package.json ./

EXPOSE 3000
ENV NODE_ENV=production

CMD ["bun", "start"]
