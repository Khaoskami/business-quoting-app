import { describe, expect, test } from 'bun:test';
import { profileSchema } from './schemas';

describe('profileSchema logo validation', () => {
  test('accepts a valid png base64 data URL', () => {
    const r = profileSchema.safeParse({ logo: 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUg==' });
    expect(r.success).toBe(true);
  });

  test('accepts a valid jpeg base64 data URL with single padding char', () => {
    const r = profileSchema.safeParse({ logo: 'data:image/jpeg;base64,/9j/4AAQSkZJRg=' });
    expect(r.success).toBe(true);
  });

  test('rejects attribute-breakout payload after a valid prefix', () => {
    // Passed the old prefix-only regex; must now be rejected.
    const malicious = 'data:image/png;base64,AAAA" onerror="alert(document.cookie)';
    const r = profileSchema.safeParse({ logo: malicious });
    expect(r.success).toBe(false);
  });

  test('rejects non-base64 tail characters', () => {
    expect(profileSchema.safeParse({ logo: 'data:image/png;base64,<script>' }).success).toBe(false);
    expect(profileSchema.safeParse({ logo: 'data:image/png;base64,abc def' }).success).toBe(false);
  });

  test('rejects non-image and wrong-subtype data URLs', () => {
    expect(profileSchema.safeParse({ logo: 'data:text/html;base64,PHNjcmlwdD4=' }).success).toBe(false);
    expect(profileSchema.safeParse({ logo: 'data:image/svg+xml;base64,PHN2Zz4=' }).success).toBe(false);
    expect(profileSchema.safeParse({ logo: 'javascript:alert(1)' }).success).toBe(false);
  });

  test('rejects an empty base64 payload', () => {
    expect(profileSchema.safeParse({ logo: 'data:image/png;base64,' }).success).toBe(false);
  });
});
