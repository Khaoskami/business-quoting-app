FROM oven/bun:1 AS builder
WORKDIR /app

COPY package.json bun.lock* ./
RUN bun install --frozen-lockfile

COPY . .
RUN DATABASE_URL=postgres://placeholder/db bun run db:generate
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

# NOTE: running db:migrate in the start command assumes a SINGLE replica.
# With multiple replicas, concurrent `drizzle-kit migrate` runs can race —
# move migrations to a dedicated release/pre-deploy step before scaling out.
CMD ["sh", "-c", "bun run db:migrate && bun start"]
