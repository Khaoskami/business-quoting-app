import { betterAuth } from 'better-auth';
import { drizzleAdapter } from 'better-auth/adapters/drizzle';
import { db } from './db';
import * as schema from './db/schema';
import { sendEmail } from './lib/email-service';

if (!process.env.SMTP_USER || !process.env.SMTP_PASSWORD) {
  console.warn('[email] SMTP_USER/SMTP_PASSWORD are not set. Verification and password-reset emails cannot be delivered.');
}
if (!process.env.EMAIL_FROM && !process.env.RESET_FROM_EMAIL) {
  console.warn('[email] EMAIL_FROM is not set. Set it to the same Gmail address used for SMTP_USER.');
}

const clientOrigin = new URL(process.env.CLIENT_URL ?? 'http://localhost:5173').origin;
const authOrigin = new URL(process.env.BETTER_AUTH_URL ?? 'http://localhost:3000').origin;

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
        input: false,
      },
    },
  },

  emailAndPassword: {
    enabled: true,
    requireEmailVerification: process.env.NODE_ENV === 'production',
    minPasswordLength: 8,
    maxPasswordLength: 128,
    sendResetPassword: async ({ user, url }) => {
      void sendEmail({
        to: user.email,
        subject: 'Reset your Business Quotes password',
        html: `<!doctype html><html><body style="font-family:Arial,sans-serif;color:#1e2430;line-height:1.5;max-width:680px;margin:0 auto;padding:24px">
          <h1 style="font-size:22px">Business Quotes</h1>
          <p>We received a request to reset the password for your Business Quotes account.</p>
          <p><a href="${url}" style="display:inline-block;padding:10px 16px;background:#3b6b8a;color:#fff;text-decoration:none">Choose a new password</a></p>
          <p>This link expires in 1 hour. If you did not request a password reset, you can safely ignore this email.</p>
        </body></html>`,
      }).catch((error) => console.error('[email] password reset send failed', error));
    },
    resetPasswordTokenExpiresIn: 60 * 60,
    revokeSessionsOnPasswordReset: true,
  },

  emailVerification: {
    sendOnSignUp: true,
    sendOnSignIn: process.env.NODE_ENV === 'production',
    autoSignInAfterVerification: true,
    expiresIn: 60 * 60,
    sendVerificationEmail: async ({ user, url }) => {
      void sendEmail({
        to: user.email,
        subject: 'Verify your Business Quotes email',
        html: `<!doctype html><html><body style="font-family:Arial,sans-serif;color:#1e2430;line-height:1.5;max-width:680px;margin:0 auto;padding:24px">
          <h1 style="font-size:22px">Business Quotes</h1>
          <p>Please verify your email address to finish setting up your account.</p>
          <p><a href="${url}" style="display:inline-block;padding:10px 16px;background:#3b6b8a;color:#fff;text-decoration:none">Verify email address</a></p>
          <p>This link expires in 1 hour.</p>
        </body></html>`,
      }).catch((error) => console.error('[email] verification send failed', error));
    },
  },

  session: {
    expiresIn: 60 * 60 * 24 * 30,
    updateAge: 60 * 60 * 24,
    cookieCache: { enabled: true, maxAge: 60 * 5 },
  },

  rateLimit: {
    enabled: true,
    window: 60,
    max: 100,
  },

  trustedOrigins: [clientOrigin, authOrigin],

  databaseHooks: {
    user: {
      create: {
        after: async (user) => {
          await db.insert(schema.subscriptions).values({ userId: user.id, billingAmountMinor: 0 });
        },
      },
    },
  },
});

export type Session = typeof auth.$Infer.Session;
