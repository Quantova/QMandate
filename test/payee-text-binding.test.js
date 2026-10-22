// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const qm = require('..');
const { makeChain, client, SEED } = require('./chain');

const ROOT = path.join(__dirname, '..');
const qstamp = require('@quantovainc/qstamp');
const dirs = [];

test.after(() => {
  for (const d of dirs) fs.rmSync(d, { recursive: true, force: true });
});

function folder() {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'qmandate-payee-'));
  dirs.push(d);
  return d;
}

function proven(t) {
  const had = Object.prototype.hasOwnProperty.call(qstamp, 'isProven');
  const before = qstamp.isProven;
  qstamp.isProven = () => true;
  t.after(() => {
    if (had) qstamp.isProven = before;
    else delete qstamp.isProven;
  });
}

async function world(t) {
  proven(t);
  const chain = makeChain(ROOT);
  const ep = { network: 'testnet', trustCustomEndpoints: true, clients: [client(chain, 'a'), client(chain, 'b')] };
  const principal = qm.generateKey();
  const agent = qm.generateKey();
  const granted = qm.grant({
    key: principal,
    agent: qm.describeKey(agent),
    scopes: [{ action: 'payment.send', currency: 'USD', maxPerAction: '500', maxTotal: '1000' }],
    validFrom: new Date(Date.now() - 60000).toISOString(),
    validUntil: new Date((chain.time + 86400) * 1000).toISOString(),
  });
  const [mandate] = await qm.anchor(granted, Object.assign({ seed: SEED, index: 0 }, ep));
  const dir = folder();
  const details = Buffer.from('pay invoice 1001 to account 12345678');
  const signed = await qm.act(Object.assign({ key: agent, mandate, ledger: dir, action: 'payment.send', currency: 'USD', amount: '400', counterparty: 'ACME Supplies Ltd', details }, ep));
  const [action] = await qm.anchor(signed, Object.assign({ seed: SEED, index: 0, mandate }, ep));
  const opts = Object.assign({ type: 'action', mandate, principalKeyId: qm.keyId(principal), revocations: [], priorActions: [] }, ep);
  return { chain, ep, principal, agent, mandate, dir, details, action, opts };
}

test('a payee named in text binds an action only when the verifier gives that exact text', async (t) => {
  const w = await world(t);
  const unbound = await qm.verify(w.action, Object.assign({ details: w.details }, w.opts));
  assert.strictEqual(unbound.status, 'indeterminate');
  const right = await qm.verify(w.action, Object.assign({ details: w.details, counterparty: 'ACME Supplies Ltd' }, w.opts));
  assert.strictEqual(right.status, 'valid', JSON.stringify(right.checks.filter((c) => !c.ok)));
  assert.strictEqual(right.counterpartyBound, true);
  const other = await qm.verify(w.action, Object.assign({ details: w.details, counterparty: 'EVIL Ltd' }, w.opts));
  assert.strictEqual(other.status, 'invalid');
  const lookalike = await qm.verify(w.action, Object.assign({ details: w.details, counterparty: 'ACME Supplies Ltd ' }, w.opts));
  assert.strictEqual(lookalike.status, 'invalid');
  await assert.rejects(qm.verify(w.action, Object.assign({ details: w.details, counterparty: '' }, w.opts)), /exact payee text/);
});

test('a statement holding a list longer than 4096 items is refused before it is copied', () => {
  const F = require('../lib/format');
  assert.throws(() => F.plainCopy({ scopes: new Array(4097).fill('x') }), /a list is too long/);
  assert.deepStrictEqual(F.plainCopy({ scopes: ['a', 'b'] }), { scopes: ['a', 'b'] });
});
