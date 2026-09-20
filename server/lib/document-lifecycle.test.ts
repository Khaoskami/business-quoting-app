import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";

const schema = readFileSync(new URL("../db/schema.ts", import.meta.url), "utf8");
const quotes = readFileSync(new URL("../routes/quotes.ts", import.meta.url), "utf8");
const invoices = readFileSync(new URL("../routes/invoices.ts", import.meta.url), "utf8");

describe("document lifecycle contracts", () => {
  test("quotes and invoices have soft-delete timestamps", () => {
    expect(schema).toContain("deletedAt: timestamp('deleted_at')");
  });

  test("quote deletion is an update plus an audit event, not DELETE SQL", () => {
    expect(quotes).toContain("eventType: 'deleted'");
    expect(quotes).toContain("deletedAt: now");
    expect(quotes).not.toContain("db.delete(quotes)");
  });

  test("invoice deletion preserves the record and logs the event", () => {
    expect(invoices).toContain("eventType: 'deleted'");
    expect(invoices).toContain("deletedAt: now");
    expect(invoices).not.toContain("db.delete(invoices)");
  });

  test("payment history is represented separately from invoice lifecycle", () => {
    expect(schema).toContain("export const invoicePayments");
    expect(schema).toContain("export const invoiceEvents");
    expect(invoices).toContain("eventType: 'payment_received'");
  });



  test('quotes expose an owner-scoped direct lookup endpoint for deep links', () => {
    expect(quotes).toContain("quotesRouter.get('/:id'");
    expect(quotes).toContain("eq(quotes.id, id), eq(quotes.userId, userId)");
  });

  test("archived public documents are unavailable", () => {
    expect(quotes).toContain("return c.json({ error: 'This quote is no longer available.' }, 410)");
    expect(invoices).toContain("return c.json({ error: 'This invoice is no longer available.' }, 410)");
  });
});
