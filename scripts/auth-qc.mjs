/**
 * Password hashing (lib/server/password.ts): the parts a login depends on.
 *
 *   npm run test:auth
 */
import { DECOY_HASH, hashPassword, verifyPassword } from '../src/password.ts';

let problems = 0;
const check = (name, ok, detail) => {
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${name}${ok || !detail ? '' : ` — ${detail}`}`);
  if (!ok) problems += 1;
};

const hash = await hashPassword('correct horse battery');
check('stored as scrypt with its parameters', /^scrypt\$32768\$8\$1\$[\w-]+\$[\w-]+$/.test(hash), hash);
check('never contains the password', !hash.includes('correct horse'));
check('the right password verifies', await verifyPassword('correct horse battery', hash));
check('a wrong password does not', !(await verifyPassword('correct horse batterY', hash)));
check('an empty password does not', !(await verifyPassword('', hash)));
check('the same password hashes differently each time (salted)', hash !== (await hashPassword('correct horse battery')));
check('the decoy used for unknown emails matches nothing', !(await verifyPassword('anything', DECOY_HASH)));
check('a malformed stored value is refused, not thrown', !(await verifyPassword('x', 'not-a-hash')));
const t = Date.now();
await verifyPassword('x', hash);
const ms = Date.now() - t;
check(`hashing is deliberately slow (${ms} ms)`, ms >= 20, String(ms));

console.log(problems === 0 ? '\nall assertions passed\n' : `\n${problems} assertion(s) failed\n`);
process.exit(problems === 0 ? 0 : 1);
