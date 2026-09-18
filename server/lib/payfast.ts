import { createHash, timingSafeEqual } from 'node:crypto';

const SANDBOX = process.env.PAYFAST_SANDBOX !== 'false';
const HOST = SANDBOX ? 'sandbox.payfast.co.za' : 'www.payfast.co.za';
export const PAYFAST = {
  sandbox: SANDBOX,
  processUrl: `https://${HOST}/eng/process`,
  validateUrl: `https://${HOST}/eng/query/validate`,
  merchantId: process.env.PAYFAST_MERCHANT_ID ?? '',
  merchantKey: process.env.PAYFAST_MERCHANT_KEY ?? '',
  passphrase: process.env.PAYFAST_PASSPHRASE ?? '',
};

function pfEncode(value: string) { return encodeURIComponent(String(value).trim()).replace(/%20/g, '+'); }

export function signParams(pairs: [string, string][], passphrase = PAYFAST.passphrase): string {
  const parts = pairs.filter(([, v]) => v != null && String(v).length > 0).map(([k, v]) => `${k}=${pfEncode(String(v))}`);
  if (passphrase) parts.push(`passphrase=${pfEncode(passphrase)}`);
  return createHash('md5').update(parts.join('&')).digest('hex');
}

const CHECKOUT_ORDER = ['merchant_id','merchant_key','return_url','cancel_url','notify_url','name_first','name_last','email_address','m_payment_id','amount','item_name','item_description','custom_str1','custom_str2','subscription_type','billing_date','recurring_amount','frequency','cycles'] as const;

export function buildSubscriptionRedirect(opts: { amount: string; itemName: string; email: string; mPaymentId: string; userId: string; tier: 'pro' | 'business'; returnUrl: string; cancelUrl: string; notifyUrl: string; }): string {
  const fields: Record<string, string> = {
    merchant_id: PAYFAST.merchantId, merchant_key: PAYFAST.merchantKey, return_url: opts.returnUrl, cancel_url: opts.cancelUrl,
    notify_url: opts.notifyUrl, email_address: opts.email, m_payment_id: opts.mPaymentId, amount: opts.amount,
    item_name: opts.itemName, custom_str1: opts.userId, custom_str2: opts.tier, subscription_type: '1',
    recurring_amount: opts.amount, frequency: '3', cycles: '0',
  };
  const ordered = CHECKOUT_ORDER.filter(k => fields[k] !== undefined && fields[k] !== '').map(k => [k, fields[k]] as [string, string]);
  const signature = signParams(ordered);
  const query = ordered.map(([k, v]) => `${k}=${pfEncode(v)}`).join('&') + `&signature=${signature}`;
  return `${PAYFAST.processUrl}?${query}`;
}

export async function validateItn(rawBody: string): Promise<Record<string, string> | null> {
  const received = new URLSearchParams(rawBody);
  if (received.get('merchant_id') !== PAYFAST.merchantId) return null;
  const pairs: [string, string][] = [];
  let theirSig = '';
  for (const [k, v] of received.entries()) { if (k === 'signature') theirSig = v; else pairs.push([k, v]); }
  const expected = signParams(pairs);
  try {
    const a = Buffer.from(expected); const b = Buffer.from(theirSig);
    if (a.length !== b.length || !timingSafeEqual(a, b)) return null;
  } catch { return null; }
  try {
    const res = await fetch(PAYFAST.validateUrl, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: rawBody });
    if ((await res.text()).trim() !== 'VALID') return null;
  } catch { return null; }
  return Object.fromEntries(received.entries());
}

export async function cancelSubscription(token: string): Promise<boolean> {
  const version = 'v1';
  const timestamp = new Date().toISOString();
  const headerFields = [['merchant-id', PAYFAST.merchantId], ['passphrase', PAYFAST.passphrase], ['timestamp', timestamp], ['version', version]] as [string,string][];
  const sigStr = headerFields.sort((a,b) => a[0].localeCompare(b[0])).map(([k,v]) => `${k}=${pfEncode(v)}`).join('&');
  const signature = createHash('md5').update(sigStr).digest('hex');
  const url = `https://api.payfast.co.za/subscriptions/${encodeURIComponent(token)}/cancel${PAYFAST.sandbox ? '?testing=true' : ''}`;
  try {
    const res = await fetch(url, { method: 'PUT', headers: { 'merchant-id': PAYFAST.merchantId, version, timestamp, signature } });
    return res.ok;
  } catch { return false; }
}
