import assert from 'node:assert/strict';
import { domainCanReceive } from '../src/mailbox.ts';

const failure = (code) => async () => { throw Object.assign(new Error('DNS failure'), { code }); };
const dns = (mx, a = [], aaaa = []) => ({
  resolveMx: Array.isArray(mx) ? async () => mx : failure(mx),
  resolve4: Array.isArray(a) ? async () => a : failure(a),
  resolve6: Array.isArray(aaaa) ? async () => aaaa : failure(aaaa),
});
assert.equal(await domainCanReceive('mail.test', dns([{ exchange: 'mx.mail.test', priority: 10 }])), 'deliverable');
assert.equal(await domainCanReceive('null.test', dns([{ exchange: '', priority: 0 }])), 'undeliverable');
assert.equal(await domainCanReceive('null.test', dns([{ exchange: '.', priority: 0 }])), 'undeliverable');
assert.equal(await domainCanReceive('missing.test', dns('ENOTFOUND')), 'undeliverable');
assert.equal(await domainCanReceive('fallback.test', dns('ENODATA', ['192.0.2.1'])), 'deliverable');
assert.equal(await domainCanReceive('fallback.test', dns('ENODATA', 'ENODATA', ['2001:db8::1'])), 'deliverable');
assert.equal(await domainCanReceive('empty.test', dns('ENODATA', 'ENODATA', 'ENODATA')), 'undeliverable');
assert.equal(await domainCanReceive('outage.test', dns('ETIMEOUT')), 'unknown');
assert.equal(await domainCanReceive('outage.test', dns('ENODATA', 'ETIMEOUT', 'ENODATA')), 'unknown');

console.log('PASS: DNS, null MX, SMTP fallback and temporary outage checks.');
