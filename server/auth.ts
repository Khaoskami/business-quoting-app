import { betterAuth } from 'better-auth';
import { drizzleAdapter } from 'better-auth/adapters/drizzle';
import { db } from './db';
import * as schema from './db/schema';
import { eq } from 'drizzle-orm';

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

  trustedOrigins: [
    process.env.CLIENT_URL ?? 'http://localhost:5173',
    process.env.BETTER_AUTH_URL ?? 'http://localhost:3000',
  ],

  databaseHooks: {
    user: {
      create: {
        after: async (user) => {
          // Everyone starts on free; seed the subscription row.
          await db.insert(schema.subscriptions).values({ userId: user.id });
          // Auto-admin the designated admin email.
          if (user.email === process.env.ADMIN_EMAIL) {
            await db.update(schema.users)
              .set({ isAdmin: true })
              .where(eq(schema.users.id, user.id));
          }
        },
      },
    },
  },
});

export type Session = typeof auth.$Infer.Session;
