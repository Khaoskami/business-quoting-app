import { afterAll, beforeAll, beforeEach, describe, expect, mock, test } from 'bun:test';

// Integration test for the PayFast ITN handler's replay guard and
// currentPeriodEnd bookkeeping. Needs a real Postgres (onConflictDoNothing +
// transactions), so it is skipped when DATABASE_URL is not set.
//
// PayFast signature validation and the server post-back are NOT under test —
// validateItn is mocked to parse the body — the subject is what the handler
// does with an already-validated ITN.
const hasDb = Boolean(process.env.DATABASE_URL);

// Must be registered before the route module (which imports validateItn) loads.
if (hasDb) {
  mock.module('../lib/payfast', () => ({
    validateItn: async (rawBody: string) =>
      Object.fromEntries(new URLSearchParams(rawBody).entries()),
    buildSubscriptionRedirect: () => 'https://example.invalid/redirect',
    cancelSubscription: async () => true,
  }));
}

const itnBody = (fields: Record<string, string>) =>
  new URLSearchParams(fields).toString();

describe.skipIf(!hasDb)('billing ITN handler', () => {
  let app: import('hono').Hono;
  let db: typeof import('../db').db;
  let schema: typeof import('../db/schema');

  const USER_ID = 'itn-test-user';

  beforeAll(async () => {
    db = (await import('../db')).db;
    schema = await import('../db/schema');
    const { migrate } = await import('drizzle-orm/postgres-js/migrator');
    await migrate(db, { migrationsFolder: 'server/db/migrations' });

    const { Hono } = await import('hono');
    const { billingRouter } = await import('./billing');
    app = new Hono();
    app.route('/api/billing', billingRouter);
  });

  afterAll(async () => {
    await (db as any).$client?.end?.({ timeout: 1 });
  });

  beforeEach(async () => {
    const { eq } = await import('drizzle-orm');
    await db.delete(schema.processedItns);
    await db.delete(schema.billingCheckouts);
    await db.delete(schema.subscriptions).where(eq(schema.subscriptions.userId, USER_ID));
    await db.delete(schema.users).where(eq(schema.users.id, USER_ID));
    await db.insert(schema.users).values({
      id: USER_ID, name: 'ITN Test', email: 'itn-test@invalid.example',
      createdAt: new Date(), updatedAt: new Date(),
    });
    await db.insert(schema.subscriptions).values({
      userId: USER_ID, tier: 'pro', status: 'active', failedPayments: 0,
    });
  });

  const getSub = async () => {
    const { eq } = await import('drizzle-orm');
    return db.query.subscriptions.findFirst({ where: eq(schema.subscriptions.userId, USER_ID) });
  };

  const postItn = async (fields: Record<string, string>) => {
    if (fields.m_payment_id) {
      await db.insert(schema.billingCheckouts).values({
        merchantPaymentId: fields.m_payment_id, userId: USER_ID, tier: 'pro',
        amountMinor: 29900, currency: 'ZAR',
      }).onConflictDoNothing();
    }
    return app.request('/api/billing/notify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: itnBody(fields),
    });
  };

  test('replayed FAILED ITN increments failedPayments only once', async () => {
    const failed = {
      payment_status: 'FAILED', custom_str1: USER_ID, custom_str2: 'pro',
      pf_payment_id: 'PF-FAIL-1', m_payment_id: `${USER_ID}:1`,
    };
    expect((await postItn(failed)).status).toBe(200);
    expect((await postItn(failed)).status).toBe(200); // exact re-delivery

    const sub = await getSub();
    expect(sub?.failedPayments).toBe(1);
    expect(sub?.status).toBe('past_due');
    expect(sub?.tier).toBe('pro'); // one real strike must NOT downgrade
  });

  test('two distinct FAILED ITNs still trip the two-strike downgrade', async () => {
    const base = { payment_status: 'FAILED', custom_str1: USER_ID, custom_str2: 'pro' };
    await postItn({ ...base, pf_payment_id: 'PF-FAIL-A' });
    await postItn({ ...base, pf_payment_id: 'PF-FAIL-B' });

    const sub = await getSub();
    expect(sub?.tier).toBe('free');
    expect(sub?.status).toBe('canceled');
    expect(sub?.failedPayments).toBe(0);
  });

  test('COMPLETE ITN activates and writes currentPeriodEnd ~1 month out', async () => {
    const before = new Date();
    const res = await postItn({
      payment_status: 'COMPLETE', custom_str1: USER_ID, custom_str2: 'pro',
      pf_payment_id: 'PF-OK-1', m_payment_id: `${USER_ID}:ok`, amount_gross: '299.00', token: 'tok-123',
    });
    expect(res.status).toBe(200);

    const sub = await getSub();
    expect(sub?.status).toBe('active');
    expect(sub?.tier).toBe('pro');
    expect(sub?.currentPeriodEnd).toBeTruthy();
    const end = sub!.currentPeriodEnd!;
    const days = (end.getTime() - before.getTime()) / 86_400_000;
    expect(days).toBeGreaterThan(27);
    expect(days).toBeLessThan(32);
  });

  test('status transition for the same pf_payment_id is not treated as a replay', async () => {
    // PENDING mutates nothing; the later COMPLETE for the same payment must still land.
    const base = { custom_str1: USER_ID, custom_str2: 'pro', pf_payment_id: 'PF-TRANS-1', m_payment_id: `${USER_ID}:transition` };
    await postItn({ ...base, payment_status: 'PENDING' });
    await postItn({ ...base, payment_status: 'COMPLETE', amount_gross: '299.00', token: 'tok-9' });

    const sub = await getSub();
    expect(sub?.status).toBe('active');
    expect(sub?.currentPeriodEnd).toBeTruthy();
  });

  test('under-amount COMPLETE ITN is ignored and NOT marked processed', async () => {
    const fields = {
      payment_status: 'COMPLETE', custom_str1: USER_ID, custom_str2: 'pro',
      pf_payment_id: 'PF-CHEAP-1', m_payment_id: `${USER_ID}:cheap`, amount_gross: '1.00', token: 'tok-1',
    };
    await postItn(fields);
    let sub = await getSub();
    expect(sub?.currentPeriodEnd).toBeNull();

    // A later legitimate delivery for the same payment id must still process.
    await postItn({ ...fields, amount_gross: '299.00' });
    sub = await getSub();
    expect(sub?.currentPeriodEnd).toBeTruthy();
  });
});
