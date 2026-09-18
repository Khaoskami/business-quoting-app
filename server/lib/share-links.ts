import { and, eq } from 'drizzle-orm';
import { shareLinks } from '../db/schema';
import { encryptSecret, hashSecret, newShareToken } from './security';

export async function upsertShareLink(
  tx: any,
  userId: string,
  kind: 'quote' | 'invoice',
  documentId: string,
  expiresAt: Date | null,
): Promise<string> {
  const token = newShareToken();
  const tokenHash = hashSecret(token);
  const tokenCiphertext = encryptSecret(token);
  const where = kind === 'quote'
    ? and(eq(shareLinks.userId, userId), eq(shareLinks.quoteId, documentId))
    : and(eq(shareLinks.userId, userId), eq(shareLinks.invoiceId, documentId));
  const existing = await tx.query.shareLinks.findFirst({ where });
  if (existing) {
    await tx.update(shareLinks).set({ tokenHash, tokenCiphertext, expiresAt, revokedAt: null }).where(eq(shareLinks.id, existing.id));
    return token;
  }
  await tx.insert(shareLinks).values({
    userId,
    ...(kind === 'quote' ? { quoteId: documentId } : { invoiceId: documentId }),
    tokenHash,
    tokenCiphertext,
    expiresAt,
    revokedAt: null,
  });
  return token;
}
