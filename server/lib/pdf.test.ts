import { describe, expect, test } from 'bun:test';
import { renderQuotePdf } from './pdf';

const quote = {
  quoteNumber: 'QT-9001',
  title: 'International Web Design',
  clientName: 'Aaliyah Titus',
  clientEmail: 'aaliyah@example.com',
  currency: 'ZAR',
  taxPercent: 0,
  discountPercent: 0,
  validityDays: 30,
  paymentTermsDays: 30,
  createdAt: '2026-09-15T16:25:49.970Z',
  validUntil: '2026-10-15T16:25:49.970Z',
  status: 'accepted',
  items: [{ description: 'Web Design', quantity: 1, unitPrice: 300 }],
};

describe('PDF renderer', () => {
  test('generates real PDFs for symbol-heavy currencies', async () => {
    for (const currency of ['ZAR', 'USD', 'EUR', 'GBP', 'JPY', 'INR', 'NGN', 'AED']) {
      const result = await renderQuotePdf({ ...quote, currency, items: [{ description: 'Design', quantity: 1, unitPrice: 300 }] }, { name: 'Skyboost' });
      expect(result.filename.endsWith('.pdf')).toBe(true);
      expect(result.pdf.length).toBeGreaterThan(1000);
      const header = new TextDecoder().decode(result.pdf.slice(0, 8));
      expect(header).toBe('%PDF-1.7');
    }
  });
});
