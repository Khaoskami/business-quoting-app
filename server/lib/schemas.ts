import { z } from 'zod';

const money = z.number().finite().min(0).max(100_000_000);
const currencyCodes = ['ZAR', 'USD', 'EUR', 'GBP', 'AUD', 'CAD', 'JPY', 'INR', 'BRL', 'NGN', 'KES', 'AED', 'CNY', 'CHF', 'NZD', 'MXN', 'SEK', 'SGD'] as const;
const url = z.string().trim().max(2000).refine((value) => {
  if (!value) return true;
  try { const u = new URL(value.includes('://') ? value : `https://${value}`); return ['http:', 'https:'].includes(u.protocol); }
  catch { return false; }
}, 'Must be a valid http(s) URL.');
const email = z.string().trim().email().max(320);

export const quoteItemSchema = z.object({
  id: z.string().uuid().optional(),
  description: z.string().trim().max(2000).default(''),
  quantity: z.number().finite().min(0).max(1_000_000),
  unitPrice: money,
  catalogId: z.string().uuid().optional().or(z.literal('')),
});

export const quoteSchema = z.object({
  title: z.string().trim().max(250).default(''),
  clientId: z.string().uuid().optional().or(z.literal('')),
  clientName: z.string().trim().max(500).default(''),
  clientEmail: z.string().trim().email().max(320).optional().or(z.literal('')),
  clientUrl: url.default(''),
  status: z.enum(['draft', 'sent', 'accepted', 'declined', 'expired']).default('draft'),
  currency: z.enum(currencyCodes).default('ZAR'),
  taxPercent: z.number().finite().min(0).max(100).default(0),
  discountPercent: z.number().finite().min(0).max(100).default(0),
  validityDays: z.number().int().min(1).max(365).default(30),
  paymentTermsDays: z.number().int().min(0).max(365).default(30),
  notes: z.string().max(20_000).default(''),
  items: z.array(quoteItemSchema).min(1).max(100),
  version: z.number().int().min(1).optional(),
  quoteNumber: z.string().optional(),
  createdAt: z.string().datetime().optional(),
  validUntil: z.string().datetime().optional(),
  signature: z.string().max(256).optional(),
  signedAt: z.string().datetime().optional().or(z.literal('')),
}).strip();

export const clientSchema = z.object({
  name: z.string().trim().min(1).max(500),
  company: z.string().trim().max(500).default(''),
  email: email.optional().or(z.literal('')),
  phone: z.string().trim().max(100).default(''),
  address: z.string().trim().max(2000).default(''),
  website: url.default(''),
  notes: z.string().max(20_000).default(''),
}).strip();

export const clientEmailSchema = z.object({
  subject: z.string().trim().min(1).max(200).transform((value) => value.replace(/[\r\n]+/g, ' ')),
  message: z.string().trim().min(1).max(10_000),
}).strip();

export const catalogItemSchema = z.object({
  name: z.string().trim().min(1).max(500),
  category: z.string().trim().max(500).default(''),
  description: z.string().trim().max(2000).default(''),
  unitPrice: money,
  unit: z.string().trim().max(50).default('each'),
}).strip();

export const profileSchema = z.object({
  name: z.string().trim().max(500).optional(),
  email: email.optional(),
  phone: z.string().trim().max(100).optional(),
  taxId: z.string().trim().max(200).optional(),
  address: z.string().trim().max(2000).optional(),
  website: url.optional(),
  defaultCurrency: z.enum(currencyCodes).optional(),
  terms: z.string().max(20_000).optional(),
  paymentInstructions: z.string().max(5_000).optional(),
  logo: z.string().max(1_400_000).regex(/^data:image\/(png|jpeg);base64,[A-Za-z0-9+/]+={0,2}$/).optional(),
  emailSettings: z.object({
    autoReminders: z.boolean().optional(),
    reminderDays: z.array(z.number().int().min(-90).max(90)).max(8).optional(),
  }).optional(),
}).strip();

export const quoteResponseSchema = z.object({
  action: z.enum(['accept', 'decline']),
  name: z.string().trim().min(1).max(250),
  message: z.string().trim().max(5_000).default(''),
  signature: z.string().trim().max(250).default(''),
}).strip();

export const invoicePaymentSchema = z.object({
  amount: z.number().finite().positive().max(100_000_000),
  method: z.enum(['bank_transfer', 'card', 'cash', 'eft', 'other']).default('other'),
  note: z.string().trim().max(1_000).default(''),
  receivedAt: z.string().datetime().optional(),
}).strip();
