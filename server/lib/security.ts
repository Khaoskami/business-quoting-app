import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';

export function newShareToken() { return randomBytes(32).toString('base64url'); }
export function hashSecret(secret: string) { return createHash('sha256').update(secret).digest('hex'); }

function encryptionKey() {
  return createHash('sha256').update(process.env.BETTER_AUTH_SECRET ?? 'invalid-development-secret').digest();
}

export function encryptSecret(value: string): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', encryptionKey(), iv);
  const ciphertext = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
  return `${iv.toString('base64url')}.${cipher.getAuthTag().toString('base64url')}.${ciphertext.toString('base64url')}`;
}

export function decryptSecret(payload: string): string | null {
  try {
    const [ivText, tagText, cipherText] = payload.split('.');
    if (!ivText || !tagText || !cipherText) return null;
    const decipher = createDecipheriv('aes-256-gcm', encryptionKey(), Buffer.from(ivText, 'base64url'));
    decipher.setAuthTag(Buffer.from(tagText, 'base64url'));
    return Buffer.concat([decipher.update(Buffer.from(cipherText, 'base64url')), decipher.final()]).toString('utf8');
  } catch {
    return null;
  }
}

export function hashRequestIdentifier(value?: string | null) { return hashSecret(value || 'unknown'); }
export function getClientIp(request: Request) { return request.headers.get('cf-connecting-ip') || request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || 'unknown'; }
