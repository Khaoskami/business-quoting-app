export const CURRENCY_DIGITS: Record<string, number> = {
  JPY: 0,
};

export function currencyDigits(currency: string): number {
  return CURRENCY_DIGITS[currency] ?? 2;
}

export function roundMoney(value: number, currency: string): number {
  const factor = 10 ** currencyDigits(currency);
  return Math.round((value + Number.EPSILON) * factor) / factor;
}

export function toMinor(value: number, currency: string): number {
  const factor = 10 ** currencyDigits(currency);
  return Math.round(roundMoney(value, currency) * factor);
}

export function fromMinor(value: number, currency: string): number {
  return value / (10 ** currencyDigits(currency));
}

export function calculateTotals(items: Array<{ quantity: number; unitPrice: number }>, taxPercent: number, discountPercent: number, currency: string) {
  const line = roundMoney(items.reduce((sum, item) => sum + roundMoney(item.quantity * item.unitPrice, currency), 0), currency);
  const discountAmt = roundMoney(line * (discountPercent / 100), currency);
  const sub = roundMoney(line - discountAmt, currency);
  const tax = roundMoney(sub * (taxPercent / 100), currency);
  const total = roundMoney(sub + tax, currency);
  return { line, discountAmt, sub, tax, total, totalMinor: toMinor(total, currency) };
}
