#!/usr/bin/env node
/*
 * License Key Generator — Business Quotes App
 *
 * Usage:
 *   node scripts/generate-license.js pro
 *   node scripts/generate-license.js business
 *
 * Run this locally after receiving payment from a customer. Paste the
 * generated key into the confirmation email you send back. The customer
 * enters it in Settings -> Activate License to unlock the paid tier.
 *
 * Key format:  BQ-{TIER}-{BASE36_TIMESTAMP}-{6_CHAR_CHECKSUM}
 * Example:     BQ-PRO-LK3M8F-A9X2KP
 *
 * Note: This is a structural-checksum key (not cryptographically signed).
 * It is a reasonable deterrent for a zero-backend app, not unforgeable.
 */

const tier = (process.argv[2] || 'PRO').toUpperCase();
if (!['PRO', 'BUSINESS'].includes(tier)) {
  console.error('Tier must be "pro" or "business"');
  process.exit(1);
}

const ts = Date.now().toString(36).toUpperCase();
const body = `BQ${tier}${ts}`;
const sum = body.split('').reduce((a, c) => a + c.charCodeAt(0), 0);
const checksum = sum.toString(36).toUpperCase().slice(-6).padStart(6, '0');

console.log(`BQ-${tier}-${ts}-${checksum}`);
