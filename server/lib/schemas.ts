import { z } from 'zod';

// Payload validation for write routes. These validate the client-supplied
// `data` blobs that get stored as JSONB. Server-authoritative fields (ids,
// userId, quoteNumber) are never trusted from the client and are stripped or
// overwritten by the route handlers — these schemas only guard shape/size.

const money = z.number().finite().min(0);

export const quoteItemSchema = z.object({
  id:          z.string().optional(),
  description: z.string().max(2000).default(''),
  quantity:    z.number().finite().min(0),
  unitPrice:   money,
  catalogId:   z.string().optional().default(''),
});

export const quoteSchema = z.object({
  // Accepted but ignored by the server — quoteNumber is server-authoritative.
  quoteNumber:     z.string().optional(),
  title:           z.string().max(500).default(''),
  clientId:        z.string().optional().default(''),
  clientName:      z.string().max(500).optional().default(''),
  clientUrl:       z.string().max(2000).optional().default(''),
  status:          z.enum(['draft', 'sent', 'accepted', 'declined', 'expired']).default('draft'),
  currency:        z.string().min(1).max(8).default('ZAR'),
  taxPercent:      z.number().finite().min(0).max(100).default(0),
  discountPercent: z.number().finite().min(0).max(100).default(0),
  validityDays:    z.number().finite().min(1).default(30),
  notes:           z.string().max(20000).optional().default(''),
  createdAt:       z.string().optional(),
  items:           z.array(quoteItemSchema).min(1).max(500),
  signature:       z.string().max(256).optional().default(''),
  signedAt:        z.string().optional().default(''),
}).passthrough();

export const clientSchema = z.object({
  name:    z.string().max(500).default(''),
  company: z.string().max(500).optional().default(''),
  email:   z.string().max(320).optional().default(''),
  phone:   z.string().max(100).optional().default(''),
  address: z.string().max(2000).optional().default(''),
  website: z.string().max(2000).optional().default(''),
  notes:   z.string().max(20000).optional().default(''),
}).passthrough();

export const catalogItemSchema = z.object({
  name:        z.string().max(500).default(''),
  category:    z.string().max(500).optional().default(''),
  description: z.string().max(2000).optional().default(''),
  unitPrice:   money,
  unit:        z.string().max(50).optional().default('each'),
}).passthrough();

export const profileSchema = z.object({
  name:            z.string().max(500).optional(),
  email:           z.string().max(320).optional(),
  phone:           z.string().max(100).optional(),
  address:         z.string().max(2000).optional(),
  website:         z.string().max(2000).optional(),
  defaultCurrency: z.string().max(8).optional(),
  // Logo is injected into an <img src> unescaped on print, so the regex is
  // required (not optional) — reject anything that isn't a png/jpeg data URL.
  logo:            z.string().max(200_000).regex(/^data:image\/(png|jpeg);base64,/).optional(),
}).passthrough();
