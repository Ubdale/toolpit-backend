/** Explicit opt-in: uses provider-designated test inboxes, never real users. */
import assert from 'node:assert/strict';

if (process.env.DELIVERY_LIVE_ALLOW !== '1') throw new Error('Set DELIVERY_LIVE_ALLOW=1 to test production using Resend test addresses.');
const origin = 'https://api.toolpit.app';
const call = async (path, body) => {
  const response = await fetch(origin + path, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body), signal: AbortSignal.timeout(70000),
  });
  return { status: response.status, body: await response.json() };
};
const suffix = Date.now();
const password = 'Resend-only-test-credential-' + suffix;
const signup = (email) => call('/api/auth/signup', { email, password, verification: 'code', name: 'Delivery QC' });

const nonexistent = await signup(`test@missing-domain-${suffix}.invalid`);
assert.equal(nonexistent.status, 400);
assert.equal(nonexistent.body.code, 'invalid_email');
console.log('PASS: nonexistent domain rejected before any verification email.');

for (const [kind, expected] of [['bounced', 'bounced'], ['delivered', 'delivered']]) {
  const email = `${kind}+toolpit-${suffix}@resend.dev`;
  const started = await signup(email);
  assert.equal(started.status, 202, JSON.stringify(started.body));
  assert.equal(started.body.pending.method, 'code');
  assert.equal(started.body.token, undefined);
  console.log(`PASS: ${kind} test email pending without an account/session.`);
  let result;
  for (let attempt = 0; attempt < 45; attempt++) {
    result = await call('/api/auth/signup/delivery', { handle: started.body.pending.handle });
    if (result.body.delivery === expected) break;
    await new Promise(resolve => setTimeout(resolve, 2000));
  }
  assert.equal(result.body.delivery, expected, JSON.stringify(result.body));
  console.log(`PASS: signed live ${kind} report received by Toolpit.`);
  const login = await call('/api/auth/login', { email, password });
  assert.equal(login.status, 403);
  assert.equal(login.body.code, 'email_unverified');
  console.log(`PASS: ${kind} test inbox cannot sign in without OTP.`);
}
console.log('delivery-live-qc: all checks passed.');
