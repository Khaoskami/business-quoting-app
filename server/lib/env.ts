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
    for (const key of ['RESEND_API_KEY', 'RESET_FROM_EMAIL']) {
      if (!process.env[key]) throw new Error(`Missing production email setting: ${key}`);
    }
    if (process.env.PAYFAST_SANDBOX === 'false') {
      for (const key of ['PAYFAST_MERCHANT_ID', 'PAYFAST_MERCHANT_KEY', 'PAYFAST_PASSPHRASE']) {
        if (!process.env[key]) throw new Error(`Missing PayFast production secret: ${key}`);
      }
    }
  }
}
