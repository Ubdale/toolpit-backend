import { randomBytes, scrypt, timingSafeEqual } from 'node:crypto';

/**
 * Password hashing with scrypt, from Node's own crypto - no dependency.
 *
 * Stored as `scrypt$N$r$p$salt$hash` so the cost can be raised later without
 * breaking existing hashes: verification reads the parameters from the stored
 * value, and a login can re-hash with new ones.
 *
 * N=2^15, r=8, p=1 is OWASP's recommended minimum for scrypt and takes ~50 ms,
 * which is slow enough to make guessing expensive and fast enough for a login.
 */
const N = 32768;
const R = 8;
const P = 1;
const KEY_LENGTH = 64;
// scrypt needs 128 * N * r bytes; Node's default ceiling is exactly that, so
// raise it a little rather than fail at the boundary.
const MAX_MEMORY = 128 * N * R * 2;

function derive(password: string, salt: Buffer, n: number, r: number, p: number): Promise<Buffer> {
  return new Promise((resolve, reject) =>
    scrypt(password.normalize('NFKC'), salt, KEY_LENGTH, { N: n, r, p, maxmem: MAX_MEMORY }, (error, key) =>
      error ? reject(error) : resolve(key),
    ),
  );
}

export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(16);
  const key = await derive(password, salt, N, R, P);
  return `scrypt$${N}$${R}$${P}$${salt.toString('base64url')}$${key.toString('base64url')}`;
}

export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const parts = stored.split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;
  const [, n, r, p, salt, hash] = parts as [string, string, string, string, string, string];
  const expected = Buffer.from(hash, 'base64url');
  const actual = await derive(password, Buffer.from(salt, 'base64url'), Number(n), Number(r), Number(p));
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

/** A hash to compare against when the email is unknown, so timing does not reveal which emails exist. */
export const DECOY_HASH =
  'scrypt$32768$8$1$AAAAAAAAAAAAAAAAAAAAAA$' + Buffer.alloc(KEY_LENGTH).toString('base64url');
