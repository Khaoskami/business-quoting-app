# Gmail authentication email setup for Railway

This version of Business Quotes sends verification emails, password-reset emails, quote emails, invoice emails, reminders, and direct client emails through Gmail SMTP.

## 1. Google account

Use a dedicated Gmail or Google Workspace mailbox for the application, for example `yourbusiness@gmail.com`.

Turn on 2-Step Verification for that Google account, then create a Google App Password for the application. Do not put the normal Google account password in Railway.

Use the 16-character App Password as `SMTP_PASSWORD`. The application removes spaces automatically if Google displays the password grouped with spaces.

## 2. Railway variables

In Railway, open the service that runs Business Quotes and add:

```text
EMAIL_PROVIDER=gmail
SMTP_HOST=smtp.gmail.com
SMTP_PORT=465
SMTP_SECURE=true
SMTP_USER=yourbusiness@gmail.com
SMTP_PASSWORD=your-16-character-google-app-password
EMAIL_FROM=Business Quotes <yourbusiness@gmail.com>
RESET_FROM_EMAIL=yourbusiness@gmail.com
```

You must also keep the existing production variables:

```text
DATABASE_URL=...
BETTER_AUTH_SECRET=...
BETTER_AUTH_URL=https://app.yourdomain.com
CLIENT_URL=https://app.yourdomain.com
```

The `BETTER_AUTH_URL` and `CLIENT_URL` values must be the public HTTPS URL customers actually use.

## 3. Cloudflare

Cloudflare remains responsible for your website DNS and custom domain. It does not send the application emails.

Point your application hostname at the Railway custom-domain target, then use that same hostname in `BETTER_AUTH_URL` and `CLIENT_URL`.

Example:

```text
app.yourdomain.com
        ↓
Cloudflare DNS
        ↓
Railway custom domain
        ↓
Business Quotes
```

## 4. What happens after deployment

Registration:

```text
Register
  ↓
Better Auth creates the account
  ↓
Verification token is generated
  ↓
Gmail SMTP sends verification email
  ↓
Customer clicks the verification link
  ↓
Account becomes verified
```

Password reset:

```text
Forgot password
  ↓
Better Auth creates a one-hour reset token
  ↓
Gmail SMTP sends reset email
  ↓
Customer clicks the link
  ↓
New password is saved
  ↓
Existing sessions are revoked
```

The existing quote/invoice email queue uses the same Gmail SMTP transport.

## 5. Test checklist

After Railway redeploys:

1. Open `/register`.
2. Create a test account using an email address you can access.
3. Confirm the verification email arrives.
4. Click the verification button.
5. Log out.
6. Open `/forgot-password`.
7. Request a reset for the same account.
8. Confirm the reset email arrives.
9. Click the reset link.
10. Set a new password.
11. Log in with the new password.
12. Send a test quote to another mailbox and confirm it is delivered.

If authentication works but client/quote emails do not, check Railway logs for `[email]` or `SMTP` errors. The same SMTP configuration is used by both systems.

## 6. Important production note

Gmail SMTP is suitable for the initial version and low-volume testing. A multi-tenant SaaS with many customers can eventually outgrow a single Gmail mailbox's sending limits. The email service is kept behind `sendEmail()` so a transactional provider can be introduced later without rebuilding Better Auth or the quote/invoice workflows.

## 7. Existing accounts

Existing accounts are not lost or recreated by enabling verification. Accounts remain in the same database.

If an existing account has not been verified, open `/verify-email`, enter the account email, and request a fresh verification link. The login screen also links to this page.

The production configuration now requires email verification independently of `NODE_ENV`, so Railway and local production-style testing use the same authentication rules. Do not set `REQUIRE_EMAIL_VERIFICATION=false` in the production Railway service.

Verification and password-reset handlers now await the email send. If Gmail SMTP is misconfigured, the authentication request will fail visibly and Railway will log the underlying `[email]`/SMTP error instead of pretending that the message was sent.
