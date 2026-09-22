import '../bootstrap';

export function validateEnvironment() {
  const production = process.env.NODE_ENV === 'production';
  const required = ['DATABASE_URL', 'BETTER_AUTH_SECRET', 'BETTER_AUTH_URL', 'CLIENT_URL'];
  for (const key of required) {
    if (!process.env[key]) throw new Error(`Missing required environment variable: ${key}`);
  }
  if ((process.env.BETTER_AUTH_SECRET ?? '').length < 32) {
    throw new Error('BETTER_AUTH_SECRET must be at least 32 characters.');
  }
  if (production) {
    for (const key of ['BETTER_AUTH_URL', 'CLIENT_URL']) {
      const value = process.env[key]!;
      if (!value.startsWith('https://')) throw new Error(`${key} must use https:// in production.`);
    }
    for (const key of ['SMTP_USER', 'SMTP_PASSWORD', 'EMAIL_FROM']) {
      if (!process.env[key]) throw new Error(`Missing production email setting: ${key}`);
    }
    const provider = (process.env.EMAIL_PROVIDER ?? 'gmail').trim().toLowerCase();
    if (!['gmail', 'smtp'].includes(provider)) throw new Error('EMAIL_PROVIDER must be gmail or smtp.');
    if (provider === 'smtp' && !process.env.SMTP_HOST) throw new Error('SMTP_HOST is required when EMAIL_PROVIDER=smtp.');
    if (process.env.PAYFAST_SANDBOX === 'false') {
      for (const key of ['PAYFAST_MERCHANT_ID', 'PAYFAST_MERCHANT_KEY', 'PAYFAST_PASSPHRASE']) {
        if (!process.env[key]) throw new Error(`Missing PayFast production secret: ${key}`);
      }
    }
  }
}
