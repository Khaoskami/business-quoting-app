import { describe, expect, test } from 'bun:test';
import { TIER_LIMITS, quoteLimitReached } from './tier';

describe('TIER_LIMITS', () => {
  test('free tier allows 50 quotes per month', () => {
    expect(TIER_LIMITS.free.quotesPerMonth).toBe(50);
  });

  test('pro tier allows 100 quotes per month', () => {
    expect(TIER_LIMITS.pro.quotesPerMonth).toBe(100);
  });

  test('business tier is unlimited', () => {
    expect(TIER_LIMITS.business.quotesPerMonth).toBe(Infinity);
  });
});

describe('quoteLimitReached', () => {
  test('free user can create up to the cap and is blocked at the cap', () => {
    expect(quoteLimitReached('free', 0)).toBe(false);
    expect(quoteLimitReached('free', 49)).toBe(false); // creating the 50th quote
    expect(quoteLimitReached('free', 50)).toBe(true);  // 51st is blocked
    expect(quoteLimitReached('free', 51)).toBe(true);
  });

  test('pro user can create up to the cap and is blocked at the cap', () => {
    expect(quoteLimitReached('pro', 0)).toBe(false);
    expect(quoteLimitReached('pro', 99)).toBe(false);  // creating the 100th quote
    expect(quoteLimitReached('pro', 100)).toBe(true);  // 101st is blocked
    expect(quoteLimitReached('pro', 101)).toBe(true);
  });

  test('business user is never blocked', () => {
    expect(quoteLimitReached('business', 0)).toBe(false);
    expect(quoteLimitReached('business', 10_000)).toBe(false);
  });
});
