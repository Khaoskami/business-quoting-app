import { describe, expect, test } from 'bun:test';
import { TIER_LIMITS, quoteLimitReached } from './tier';

describe('TIER_LIMITS', () => {
  test('free tier allows 5 quotes per month', () => {
    expect(TIER_LIMITS.free.quotesPerMonth).toBe(5);
  });

  test('growth tier allows 300 quotes per month', () => {
    expect(TIER_LIMITS.pro.quotesPerMonth).toBe(300);
  });

  test('tier names expose Growth to customers while keeping the pro database key', () => {
    expect(TIER_LIMITS.free.clientEmailsPerMonth).toBe(10);
    expect(TIER_LIMITS.pro.clientEmailsPerMonth).toBe(400);
    expect(TIER_LIMITS.business.clientEmailsPerMonth).toBe(2000);
  });

  test('business tier is unlimited', () => {
    expect(TIER_LIMITS.business.quotesPerMonth).toBe(Infinity);
  });
});

describe('quoteLimitReached', () => {
  test('free user can create up to the cap and is blocked at the cap', () => {
    expect(quoteLimitReached('free', 0)).toBe(false);
    expect(quoteLimitReached('free', 4)).toBe(false); // creating the 5th quote
    expect(quoteLimitReached('free', 5)).toBe(true);  // 6th is blocked
    expect(quoteLimitReached('free', 6)).toBe(true);
  });

  test('pro user can create up to the cap and is blocked at the cap', () => {
    expect(quoteLimitReached('pro', 0)).toBe(false);
    expect(quoteLimitReached('pro', 299)).toBe(false);  // creating the 300th quote
    expect(quoteLimitReached('pro', 300)).toBe(true);  // 301st is blocked
    expect(quoteLimitReached('pro', 301)).toBe(true);
  });

  test('business user is never blocked', () => {
    expect(quoteLimitReached('business', 0)).toBe(false);
    expect(quoteLimitReached('business', 10_000)).toBe(false);
  });
});
