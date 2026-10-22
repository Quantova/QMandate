// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const qm = require('..');
const F = require('../lib/format');
const native = require('../lib/native');
const { makeChain, client } = require('./chain');
const { PAYEE, bound, grantIssuedEarly } = require('./bind');

const ROOT = path.join(__dirname, '..');
const dirs = [];

test.after(() => {
  for (const d of dirs) fs.rmSync(d, { recursive: true, force: true });
});

function folder() {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'qmandate-totals-'));
  dirs.push(d);
  return d;
}

function setup() {
  const chain = makeChain(ROOT);
  const ep = { network: 'testnet', trustCustomEndpoints: true, clients: [client(chain, 'a'), client(chain, 'b')] };
  const principal = qm.generateKey();
  const agent = qm.generateKey();
  const mandate = qm.grant({
    key: principal,
    agent: qm.describeKey(agent),
    scopes: [{ action: 'payment.send', currency: 'USD', maxPerAction: '500', maxTotal: '800' }],
    validFrom: new Date(Date.now() - 60000).toISOString(),
    validUntil: new Date((chain.time + 3600) * 1000).toISOString(),
  });
  return { chain, ep, principal, agent, mandate };
}

function pay(s, amount, ledger, extra) {
  return qm.act(Object.assign({ key: s.agent, mandate: s.mandate, ledger, action: 'payment.send', currency: 'USD', amount, counterparty: PAYEE }, s.ep, extra || {}));
}

function check(s, action, priorActions, extra) {
  return qm.verify(action, Object.assign({ type: 'action', mandate: s.mandate, principalKeyId: qm.keyId(s.principal), revocations: [], priorActions, requireAnchor: false }, bound(action), s.ep, extra));
}

const failed = (r, name) => r.checks.find((c) => c.name === name && !c.ok);

function memoryLedger(lie) {
  const m = new Map();
  return {
    async read(name) {
      return lie ? lie(m.get(name) || null) : (m.get(name) || null);
    },
    async compareAndSwap(name, expected, next) {
      if (!lie && (m.get(name) || null) !== expected) return false;
      m.set(name, next);
      return true;
    },
  };
}

test('an unbroken record of spending verifies valid with its running total', async () => {
  const s = setup();
  const dir = folder();
  const a1 = await pay(s, '300', dir);
  const a2 = await pay(s, '200', dir);
  const a3 = await pay(s, '250', dir);
  const r = await check(s, a3, [a1, a2]);
  assert.strictEqual(r.status, 'valid', JSON.stringify(r.checks.filter((c) => !c.ok)));
  assert.strictEqual(r.totalProven, true);
  assert.strictEqual(r.spentBefore, '500');
  assert.strictEqual(r.sequence, '3');
  const first = await check(s, a1, []);
  assert.strictEqual(first.status, 'valid');
});

test('a missing earlier action leaves the total unproven', async () => {
  const s = setup();
  const dir = folder();
  const a1 = await pay(s, '300', dir);
  const a2 = await pay(s, '200', dir);
  const a3 = await pay(s, '250', dir);
  const r = await check(s, a3, [a1]);
  assert.strictEqual(r.status, 'indeterminate');
  assert.ok(failed(r, 'sequence'));
  assert.strictEqual(r.totalProven, false);
  const none = await check(s, a2, []);
  assert.strictEqual(none.status, 'indeterminate');
  const r2 = await qm.verify(a2, { type: 'action', mandate: s.mandate, principalKeyId: qm.keyId(s.principal), revocations: [], requireAnchor: false, network: 'testnet', trustCustomEndpoints: true, clients: s.ep.clients });
  assert.strictEqual(r2.status, 'indeterminate');
});

test('two actions with the same number are a fork and verify invalid', async () => {
  const s = setup();
  const own = folder();
  const other = folder();
  const results = [await pay(s, '400', own), await pay(s, '400', other), await pay(s, '400', folder())];
  for (const a of results) assert.strictEqual(a.statement.sequence, '1');
  for (let i = 0; i < 3; i += 1) {
    const r = await check(s, results[i], results.filter((_, j) => j !== i));
    assert.strictEqual(r.status, 'invalid');
    assert.match(failed(r, 'sequence').detail, /numbered 1/);
  }
  const next = await pay(s, '300', own);
  const r = await check(s, next, results);
  assert.strictEqual(r.status, 'invalid');
});

test('a running total that does not add up verifies invalid', async () => {
  const s = setup();
  const lying = memoryLedger((text) => {
    if (!text) return null;
    const st = JSON.parse(text);
    st.total = '0';
    return JSON.stringify(st) + '\n';
  });
  const a1 = await pay(s, '400', lying);
  const a2 = await pay(s, '400', lying);
  const a3 = await pay(s, '400', lying);
  assert.strictEqual(a3.statement.total, '400');
  const r = await check(s, a3, [a1, a2]);
  assert.strictEqual(r.status, 'invalid');
  assert.match(failed(r, 'sequence').detail, /not the total of action 2 plus its amount/);
});

test('a signed running total above the limit verifies invalid even without earlier actions', async () => {
  const s = setup();
  const a = await pay(s, '300', folder(), { spent: '450' });
  const r = await qm.verify(a, { type: 'action', mandate: s.mandate, principalKeyId: qm.keyId(s.principal), revocations: [], requireAnchor: false, network: 'testnet', trustCustomEndpoints: true, clients: s.ep.clients });
  assert.strictEqual(r.status, 'indeterminate');
  const st = Object.assign({}, a.statement, { total: '900' });
  const sig = native.sign(s.agent, F.payload('action', st, F.ACTION_VERSION), crypto.getRandomValues(new Uint8Array(32)));
  const over = Object.assign({}, a, { statement: st, signature: Buffer.from(sig).toString('base64') });
  const r2 = await qm.verify(over, { type: 'action', mandate: s.mandate, principalKeyId: qm.keyId(s.principal), revocations: [], requireAnchor: false, network: 'testnet', trustCustomEndpoints: true, clients: s.ep.clients });
  assert.strictEqual(r2.status, 'invalid');
  assert.match(failed(r2, 'total').detail, /exceeds 800/);
});

test('older format actions verify only when the verifier accepts them and say their total cannot be proven', async () => {
  const s = setup();
  s.mandate = grantIssuedEarly(s.principal, s.agent, s.mandate.statement.scopes, s.mandate.statement.validFrom, s.mandate.statement.validUntil);
  const m = F.parse(s.mandate);
  const st = {
    mandateId: m.statement.mandateId,
    mandateRef: F.refOf(m),
    actionId: '0'.repeat(31) + '1',
    agentKeyId: qm.keyId(s.agent),
    action: 'payment.send',
    currency: 'USD',
    amount: '300',
    counterparty: PAYEE,
    detailsDigest: F.sha3(Buffer.alloc(0)).toString('hex'),
    actedAt: new Date(s.chain.time * 1000).toISOString(),
    note: '',
  };
  const sig = native.sign(s.agent, F.payload('action', st), crypto.getRandomValues(new Uint8Array(32)));
  const pk = qm.publicKey(s.agent);
  const old = { format: F.FORMAT, type: 'action', algorithm: F.ALGORITHM, signer: { id: qm.keyId(s.agent), publicKey: Buffer.from(pk).toString('base64') }, statement: st, signature: Buffer.from(sig).toString('base64') };
  const refused = await check(s, old, []);
  assert.strictEqual(refused.status, 'indeterminate');
  assert.ok(failed(refused, 'total'));
  const r = await check(s, old, [], { acceptLegacyActions: true });
  assert.strictEqual(r.status, 'valid');
  assert.strictEqual(r.format, F.FORMAT);
  assert.strictEqual(r.totalProven, false);
  assert.ok(r.notes.some((n) => /cannot be proven complete/.test(n)));
  const dir = folder();
  const v2 = await pay(s, '400', dir, { spent: '300' });
  const ok = await check(s, v2, [old]);
  assert.strictEqual(ok.status, 'valid', JSON.stringify(ok.checks.filter((c) => !c.ok)));
  const short = await pay(s, '400', folder(), { spent: '100' });
  const bad = await check(s, short, [old]);
  assert.strictEqual(bad.status, 'invalid');
  assert.match(failed(bad, 'sequence').detail, /older format add up to 300/);
});

test('a counterparty can be bound to a key and the verifier says names are self asserted', async () => {
  const s = setup();
  const payee = qm.generateKey();
  const a = await pay(s, '100', folder(), { counterparty: 'key ' + qm.keyId(payee) });
  const r = await qm.verify(a, { type: 'action', mandate: s.mandate, principalKeyId: qm.keyId(s.principal), revocations: [], priorActions: [], requireAnchor: false, network: 'testnet', trustCustomEndpoints: true, clients: s.ep.clients, counterpartyKeyId: qm.keyId(payee), detailsDigest: a.statement.detailsDigest });
  assert.strictEqual(r.status, 'valid');
  assert.strictEqual(r.counterpartyBound, true);
  assert.ok(r.notes.some((n) => /not verified identities/.test(n)));
  const other = await qm.verify(a, { type: 'action', mandate: s.mandate, principalKeyId: qm.keyId(s.principal), revocations: [], priorActions: [], requireAnchor: false, network: 'testnet', trustCustomEndpoints: true, clients: s.ep.clients, counterpartyKeyId: qm.keyId(qm.generateKey()) });
  assert.strictEqual(other.status, 'invalid');
});
