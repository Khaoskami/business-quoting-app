export const PRICING = {
  free: {
    name: 'Free',
    price: 0,
    priceLabel: 'R0',
    cadence: 'forever',
    tagline: 'Try the full quote-to-invoice workflow on a small volume.',
  },
  pro: {
    name: 'Growth',
    price: 1099,
    priceLabel: 'R1,099',
    cadence: 'month',
    tagline: 'For businesses that send quotes, invoices, and follow-ups every week.',
  },
  business: {
    name: 'Business',
    price: 1699,
    priceLabel: 'R1,699',
    cadence: 'month',
    tagline: 'For teams that want automation, controls, and higher-volume client communication.',
  },
} as const;

export type PricingTier = keyof typeof PRICING;
