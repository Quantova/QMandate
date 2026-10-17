// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const qm = require('..');
const { makeChain, client } = require('./chain');

const ROOT = path.join(__dirname, '..');

function setup(from, until) {
  const chain = makeChain(ROOT);
  const ep = { trustCustomEndpoints: true, clients: [client(chain, 'a'), client(chain, 'b')] };
  const principal = qm.generateKey();
  const agent = qm.generateKey();
  const mandate = qm.grant({
    key: principal,
    agent: qm.describeKey(agent),
    scopes: [{ action: 'payment.send', currency: 'USD', maxPerAction: '500', maxTotal: '800' }],
    validFrom: from || new Date(Date.now() - 60000).toISOString(),
    validUntil: until || new Date((chain.time + 3600) * 1000).toISOString(),
  });
  return { chain, ep, agent, mandate };
}

const request = { action: 'payment.send', currency: 'USD', amount: '500' };

test('authorise refuses a caller supplied time away from the time of the chain', async () => {
  const s = setup('2026-01-01T00:00:00.000Z', '2026-02-01T00:00:00.000Z');
  await assert.rejects(qm.authorise(s.mandate, request, Object.assign({ at: '2026-01-15T00:00:00.000Z', spent: '0' }, s.ep)), /within five minutes of the time of the chain/);
  const future = new Date((s.chain.time + 3600) * 1000).toISOString();
  await assert.rejects(qm.authorise(s.mandate, request, Object.assign({ at: future, spent: '0' }, s.ep)), /within five minutes/);
  const r = await qm.authorise(s.mandate, request, Object.assign({ spent: '0' }, s.ep));
  assert.strictEqual(r.allowed, false);
  assert.ok(r.reasons.includes('the mandate has expired'));
  assert.strictEqual(r.atSupplied, false);
  assert.strictEqual(r.at, r.chainTime);
  const near = new Date(Date.parse(r.chainTime) - 60000).toISOString();
  const r2 = await qm.authorise(s.mandate, request, Object.assign({ at: near, spent: '0' }, s.ep));
  assert.strictEqual(r2.atSupplied, true);
  assert.strictEqual(r2.at, near);
});

test('authorise needs the amount already spent or the spend ledger', async () => {
  const s = setup();
  await assert.rejects(qm.authorise(s.mandate, request, s.ep), /spent/);
  const r = await qm.authorise(s.mandate, request, Object.assign({ spent: '400' }, s.ep));
  assert.strictEqual(r.allowed, false);
  assert.strictEqual(r.spent, '400');
});

test('authorise reads the running total from the spend ledger', async () => {
  const s = setup();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qmandate-authorise-'));
  try {
    const empty = await qm.authorise(s.mandate, request, Object.assign({ ledger: dir }, s.ep));
    assert.strictEqual(empty.allowed, true);
    assert.strictEqual(empty.spent, '0');
    await qm.act(Object.assign({ key: s.agent, mandate: s.mandate, ledger: dir, action: 'payment.send', currency: 'USD', amount: '400' }, s.ep));
    const after = await qm.authorise(s.mandate, request, Object.assign({ ledger: dir }, s.ep));
    assert.strictEqual(after.spent, '400');
    assert.strictEqual(after.allowed, false);
    await assert.rejects(qm.authorise(s.mandate, request, Object.assign({ ledger: dir, spent: '0' }, s.ep)), /differs from the 400/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('authorise returns a promise of the decision', async () => {
  const s = setup();
  const pending = qm.authorise(s.mandate, request, Object.assign({ spent: '0' }, s.ep));
  assert.ok(pending instanceof Promise);
  assert.strictEqual(pending.allowed, undefined);
  assert.strictEqual((await pending).allowed, true);
});

test('strict mode refuses the time of a single endpoint', async () => {
  const s = setup();
  const one = { trustCustomEndpoints: true, clients: [s.ep.clients[0]], trustSingleEndpoint: true };
  await assert.rejects(qm.authorise(s.mandate, request, Object.assign({ spent: '0' }, one)), /strict/);
  await assert.rejects(qm.act(Object.assign({ key: s.agent, mandate: s.mandate, ledger: os.tmpdir(), action: 'payment.send', currency: 'USD', amount: '1' }, one)), /strict/);
  const lenient = await qm.authorise(s.mandate, request, Object.assign({ spent: '0', strict: false }, one));
  assert.strictEqual(lenient.allowed, true);
});
