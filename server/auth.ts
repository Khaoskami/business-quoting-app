import { betterAuth } from 'better-auth';
import { drizzleAdapter } from 'better-auth/adapters/drizzle';
import { Resend } from 'resend';
import { db } from './db';
import * as schema from './db/schema';

const resend = process.env.RESEND_API_KEY ? new Resend(process.env.RESEND_API_KEY) : null;

if (!process.env.RESET_FROM_EMAIL) {
  console.warn(
    '[email] RESET_FROM_EMAIL is not set — password-reset emails will use a ' +
    'non-deliverable placeholder sender and will likely be rejected. Set ' +
    'RESET_FROM_EMAIL to a sender on a verified Resend domain.'
  );
}

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

  user: {
    additionalFields: {
      isAdmin: {
        type: 'boolean',
        required: false,
        defaultValue: false,
        input: false, // never accept isAdmin from client signup/update payloads
      },
    },
  },

  emailAndPassword: {
    enabled: true,
    requireEmailVerification: false,
    minPasswordLength: 8,
    // Better Auth calls this with ({ user, url, token }, request). We build our
    // own link pointing at the SPA reset page rather than using the default
    // server `url`, then email it via Resend.
    sendResetPassword: async ({ user, token }) => {
      const baseUrl = process.env.BETTER_AUTH_URL ?? 'http://localhost:3000';
      const resetUrl = `${baseUrl}/reset-password?token=${token}`;

      if (!resend) {
        console.error('RESEND_API_KEY is not set; cannot send password reset email.');
        throw new Error('Email service is not configured.');
      }

      await resend.emails.send({
        from: process.env.RESET_FROM_EMAIL ?? 'no-reply@invalid.example',
        to: user.email,
        subject: 'Reset your Business Quotes password',
        html: `
          <p>We received a request to reset your Business Quotes password.</p>
          <p><a href="${resetUrl}">Click here to choose a new password</a>. This link expires in 1 hour.</p>
          <p>If you didn't request this, you can safely ignore this email.</p>
        `,
      });
    },
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
