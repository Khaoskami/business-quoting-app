/**
 * One-off admin promotion script.
 *
 * Auto-admin-by-email was removed from the Better Auth databaseHook (email
 * verification infra isn't wired up yet), so admins are promoted explicitly.
 *
 * Usage:
 *   bun run scripts/make-admin.ts <email>
 *   # or, if omitted, falls back to ADMIN_EMAIL
 *   ADMIN_EMAIL=you@example.com bun run scripts/make-admin.ts
 */
import { db } from '../server/db';
import { users } from '../server/db/schema';
import { eq } from 'drizzle-orm';

const email = process.argv[2] ?? process.env.ADMIN_EMAIL;

if (!email) {
  console.error('Usage: bun run scripts/make-admin.ts <email>  (or set ADMIN_EMAIL)');
  process.exit(1);
}

const [row] = await db.update(users)
  .set({ isAdmin: true })
  .where(eq(users.email, email))
  .returning({ id: users.id, email: users.email });

if (!row) {
  console.error(`No user found with email: ${email}`);
  process.exit(1);
}

console.log(`Promoted ${row.email} (${row.id}) to admin.`);
process.exit(0);
