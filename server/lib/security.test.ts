import { beforeEach, describe, expect, test } from 'bun:test';
import { decryptSecret, encryptSecret, hashSecret, newShareToken } from './security';

describe('security primitives', () => {
  beforeEach(() => { process.env.BETTER_AUTH_SECRET = 'test-secret-which-is-long-enough-for-aes-key-material'; });

  test('share tokens are high entropy and hash deterministically', () => {
    const token = newShareToken();
    expect(token.length).toBeGreaterThanOrEqual(40);
    expect(hashSecret(token)).toBe(hashSecret(token));
    expect(hashSecret(token)).not.toBe(hashSecret(newShareToken()));
  });

  test('encrypted share tokens round trip and reject tampering', () => {
    const token = newShareToken();
    const encrypted = encryptSecret(token);
    expect(decryptSecret(encrypted)).toBe(token);
    const parts = encrypted.split('.');
    parts[2] = `${parts[2]}x`;
    expect(decryptSecret(parts.join('.'))).toBeNull();
  });
});
