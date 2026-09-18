import { describe, expect, test } from 'bun:test';
import { buildPrintHtml, newQuote, calcTotals } from './quote';

const baseQuote = () => ({
  ...newQuote('ZAR'),
  title: 'Test Quote',
  quoteNumber: 'QT-0001',
  items: [{ id: '1', description: 'Widget', quantity: 2, unitPrice: 100, catalogId: '' }],
});

describe('quote calculations and print hardening', () => {
  test('uses zero decimal precision for JPY totals', () => {
    const q = { ...baseQuote(), currency: 'JPY', items: [{ id: '1', description: 'Widget', quantity: 1, unitPrice: 123.6, catalogId: '' }] };
    expect(calcTotals(q.items, 10, 0, q.currency).total).toBe(136);
  });

  test('escapes a hostile logo so it cannot break out of the src attribute', () => {
    const html = buildPrintHtml(baseQuote(), {
      name: 'Biz',
      logo: 'data:image/png;base64,AAAA" onerror="alert(1)',
    });
    expect(html).not.toContain('" onerror="');
    expect(html).toContain('&quot; onerror=&quot;');
  });

  test('a valid base64 logo passes through esc() unchanged', () => {
    const logo = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUg==';
    const html = buildPrintHtml(baseQuote(), { name: 'Biz', logo });
    expect(html).toContain(`<img src="${logo}"`);
  });

  test('includes a CSP that blocks scripts and network access', () => {
    const html = buildPrintHtml(baseQuote(), { name: 'Biz' });
    expect(html).toContain('http-equiv="Content-Security-Policy"');
    expect(html).toContain("default-src 'none'");
    expect(html).not.toContain("script-src 'unsafe-inline'");
    expect(html).toContain("style-src 'unsafe-inline'");
    expect(html).toContain('img-src data:');
    expect(html).not.toContain('connect-src');
  });

  test('currency cannot terminate the inline converter script', () => {
    const q = { ...baseQuote(), currency: '</script' };
    const html = buildPrintHtml(q, { name: 'Biz' });
    expect(html).not.toContain('var BASE="</script');
  });

  test('non-numeric quantity/percent fields render as numbers, not markup', () => {
    const q = {
      ...baseQuote(),
      taxPercent: '<img src=x onerror=alert(1)>' as any,
      validityDays: '"><script>1</script>' as any,
      items: [{ id: '1', description: 'W', quantity: '<b>9</b>' as any, unitPrice: 10, catalogId: '' }],
    };
    const html = buildPrintHtml(q, { name: 'Biz' });
    expect(html).not.toContain('<img src=x');
    expect(html).not.toContain('<script>1</script>');
    expect(html).not.toContain('<b>9</b>');
  });
});
