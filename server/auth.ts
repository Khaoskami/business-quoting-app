import { betterAuth } from 'better-auth';
import { drizzleAdapter } from 'better-auth/adapters/drizzle';
import { db } from './db';
import * as schema from './db/schema';

export const auth = betterAuth({
  database: drizzleAdapter(db, {
    provider: 'pg',
    schema: {
      user:         schema.users,
      session:      schema.sessions,
      account:      schema.accounts,
      verification: schema.verifications,
    },
  }),

  emailAndPassword: {
    enabled: true,
    requireEmailVerification: false,
    minPasswordLength: 8,
  },

  session: {
    expiresIn: 60 * 60 * 24 * 30,   // 30 days
    updateAge: 60 * 60 * 24,         // refresh daily
    cookieCache: { enabled: true, maxAge: 60 * 5 },
  },

  // Built-in rate limiting on auth routes. 100 requests per 60s window per IP.
  rateLimit: {
    enabled: true,
    window: 60,
    max: 100,
  },

  trustedOrigins: [
    process.env.CLIENT_URL ?? 'http://localhost:5173',
    process.env.BETTER_AUTH_URL ?? 'http://localhost:3000',
  ],

  databaseHooks: {
    user: {
      create: {
        after: async (user) => {
          // Everyone starts on free; seed the subscription row.
          // NOTE: admin promotion is intentionally NOT done here. Email infra
          // for verification isn't wired up yet, so we avoid auto-admin by
          // email and instead promote explicitly via scripts/make-admin.ts.
          await db.insert(schema.subscriptions).values({ userId: user.id });
        },
      },
    },
  },
});

export type Session = typeof auth.$Infer.Session;
