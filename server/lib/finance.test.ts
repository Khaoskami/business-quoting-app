import { describe, expect, test } from 'bun:test';
import { calculateTotals, fromMinor, roundMoney, toMinor } from './finance';

describe('finance', () => {
  test('rounds and converts minor units per currency', () => {
    expect(toMinor(123.456, 'ZAR')).toBe(12346);
    expect(toMinor(123.6, 'JPY')).toBe(124);
    expect(fromMinor(124, 'JPY')).toBe(124);
  });

  test('calculates totals in minor-unit-safe currency precision', () => {
    const totals = calculateTotals(
      [{ quantity: 3, unitPrice: 19.99 }, { quantity: 2, unitPrice: 10.01 }],
      15,
      10,
      'ZAR',
    );
    expect(totals.line).toBe(79.99);
    expect(totals.discountAmt).toBe(8);
    expect(totals.sub).toBe(71.99);
    expect(totals.tax).toBe(10.8);
    expect(totals.total).toBe(82.79);
    expect(totals.totalMinor).toBe(8279);
  });

  test('never lets floating point noise change a rounded cent value', () => {
    expect(roundMoney(0.1 + 0.2, 'ZAR')).toBe(0.3);
    expect(toMinor(0.1 + 0.2, 'ZAR')).toBe(30);
  });
});
