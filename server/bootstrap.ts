/**
 * Railway/runtime environment bootstrap.
 *
 * Railway injects DATABASE_URL and RAILWAY_PUBLIC_DOMAIN automatically.
 * Non-secret mail/auth defaults are supplied here so the app does not depend
 * on a manually copied .env file inside the container.
 *
 * SMTP_USER and SMTP_PASSWORD intentionally remain secrets: Railway must
 * supply those values as service variables. They cannot be safely generated
 * by the application.
 */

const publicDomain = process.env.RAILWAY_PUBLIC_DOMAIN?.trim();
const railwayOrigin = publicDomain ? `https://${publicDomain}` : '';

function setDefault(name: string, value: string | undefined) {
  if ((!process.env[name] || process.env[name]!.trim() === '') && value) {
    process.env[name] = value;
  }
}

setDefault('REQUIRE_EMAIL_VERIFICATION', 'true');
setDefault('EMAIL_PROVIDER', 'gmail');
setDefault('SMTP_HOST', 'smtp.gmail.com');
setDefault('SMTP_PORT', '465');
setDefault('SMTP_SECURE', 'true');

// Railway supplies RAILWAY_PUBLIC_DOMAIN for the generated service domain.
// Explicit BETTER_AUTH_URL / CLIENT_URL values always take precedence, which
// also allows a custom domain to be configured without changing this code.
setDefault('BETTER_AUTH_URL', railwayOrigin);
setDefault('CLIENT_URL', railwayOrigin);

// Gmail sender defaults to the authenticated mailbox when EMAIL_FROM is not
// explicitly supplied. This keeps a single SMTP_USER variable sufficient for
// basic authentication/reset mail configuration.
if (!process.env.EMAIL_FROM?.trim() && process.env.SMTP_USER?.trim()) {
  process.env.EMAIL_FROM = `Business Quotes <${process.env.SMTP_USER.trim()}>`;
}
setDefault('RESET_FROM_EMAIL', process.env.SMTP_USER?.trim());

export {};
