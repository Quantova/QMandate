// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const qm = require('..');
const F = require('../lib/format');
const native = require('../lib/native');
const { makeChain, client } = require('./chain');
const { PAYEE, bound } = require('./bind');

const ROOT = path.join(__dirname, '..');
const dirs = [];

test.after(() => {
  for (const d of dirs) fs.rmSync(d, { recursive: true, force: true });
});

function folder() {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'qmandate-one-ledger-'));
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
    scopes: [{ action: 'payment.send', currency: 'USD', maxPerAction: '500', maxTotal: '1000' }],
    validFrom: new Date(Date.now() - 60000).toISOString(),
    validUntil: new Date((chain.time + 3600) * 1000).toISOString(),
  });
  return { chain, ep, principal, agent, mandate };
}

const pay = (s, amount, ledger) => qm.act(Object.assign({ key: s.agent, mandate: s.mandate, ledger, action: 'payment.send', currency: 'USD', amount, counterparty: PAYEE }, s.ep));
const check = (s, action, priorActions) => qm.verify(action, Object.assign({ type: 'action', mandate: s.mandate, principalKeyId: qm.keyId(s.principal), revocations: [], priorActions, requireAnchor: false }, bound(action), s.ep));
const failed = (r, name) => r.checks.find((c) => c.name === name && !c.ok);

function resign(s, env, change, version) {
  const st = Object.assign({}, env.statement, change);
  const v = version === undefined ? F.ACTION_VERSION : version;
  if (v === F.CHAIN_VERSION) delete st.ledgerId;
  const sig = native.sign(s.agent, F.payload('action', st, v), Uint8Array.from(crypto.randomBytes(32)));
  return Object.assign({}, env, { format: F.formatOf('action', v), statement: st, signature: Buffer.from(sig).toString('base64') });
}

test('every action names the spend ledger that signed it, and the identifier persists in the ledger', async () => {
  const s = setup();
  const dir = folder();
  const a1 = await pay(s, '100', dir);
  const a2 = await pay(s, '100', qm.fileLedger(dir));
  assert.strictEqual(a1.format, 'qmandate/3');
  assert.match(a1.statement.ledgerId, /^[0-9a-f]{32}$/);
  assert.strictEqual(a2.statement.ledgerId, a1.statement.ledgerId);
  const state = JSON.parse(fs.readFileSync(path.join(dir, qm.mandateRef(s.mandate) + '.payment.send.json'), 'utf8'));
  assert.strictEqual(state.ledgerId, a1.statement.ledgerId);
  const r = await check(s, a2, [a1]);
  assert.strictEqual(r.status, 'valid', JSON.stringify(r.checks.filter((c) => !c.ok)));
  assert.strictEqual(r.ledgerId, a1.statement.ledgerId);
  const other = await pay(s, '100', folder());
  assert.notStrictEqual(other.statement.ledgerId, a1.statement.ledgerId);
});

test('actions of one mandate and scope signed from two spend ledgers verify invalid', async () => {
  const s = setup();
  const a = folder();
  const b = folder();
  const a1 = await pay(s, '500', a);
  const a2 = await pay(s, '500', a);
  const b1 = await pay(s, '500', b);
  const b2 = await pay(s, '500', b);
  assert.strictEqual((await check(s, a2, [a1])).status, 'valid');
  for (const [target, priors] of [[b2, [b1, a1]], [b2, [b1, a2]], [a2, [a1, b2]], [b1, [a2]]]) {
    const r = await check(s, target, priors);
    assert.strictEqual(r.status, 'invalid');
    assert.match(failed(r, 'ledger').detail, /2 different spend ledgers/);
  }
});

test('an action that follows a different action than the one supplied at its previous number is a fork', async () => {
  const s = setup();
  const a1 = await pay(s, '300', folder());
  const other = folder();
  const b1 = await pay(s, '300', other);
  const b2 = await pay(s, '300', other);
  const forged = resign(s, b2, { ledgerId: a1.statement.ledgerId });
  const r = await check(s, forged, [a1]);
  assert.strictEqual(r.status, 'invalid');
  assert.match(failed(r, 'sequence').detail, /forks/);
  void b1;
});

test('actions in the format qmandate/2 still verify, and one signed after an action in the newer format is refused', async () => {
  const s = setup();
  const dir = folder();
  const a1 = await pay(s, '100', dir);
  const a2 = await pay(s, '100', dir);
  const old1 = resign(s, a1, {}, F.CHAIN_VERSION);
  const old2 = resign(s, a2, { previousRef: F.refOf(F.parse(old1)) }, F.CHAIN_VERSION);
  assert.strictEqual(old2.format, 'qmandate/2');
  const plain = await check(s, old2, [old1]);
  assert.strictEqual(plain.status, 'valid', JSON.stringify(plain.checks.filter((c) => !c.ok)));
  assert.strictEqual(plain.ledgerId, null);
  const upgraded = resign(s, a2, { previousRef: F.refOf(F.parse(old1)) });
  const mixed = await check(s, upgraded, [old1]);
  assert.strictEqual(mixed.status, 'valid', JSON.stringify(mixed.checks.filter((c) => !c.ok)));
  const back = resign(s, a2, { previousRef: F.refOf(F.parse(a1)) }, F.CHAIN_VERSION);
  const r = await check(s, back, [a1]);
  assert.strictEqual(r.status, 'invalid');
  assert.match(failed(r, 'ledger').detail, /signed outside the spend ledger/);
});
