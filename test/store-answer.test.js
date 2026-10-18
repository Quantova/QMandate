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
const Ledger = require('../lib/ledger');
const { makeChain, client } = require('./chain');
const { PAYEE } = require('./bind');

const ROOT = path.join(__dirname, '..');
const dirs = [];

test.after(() => {
  for (const d of dirs) fs.rmSync(d, { recursive: true, force: true });
});

function setup() {
  const chain = makeChain(ROOT);
  const ep = { trustCustomEndpoints: true, clients: [client(chain, 'a'), client(chain, 'b')] };
  const principal = qm.generateKey();
  const agent = qm.generateKey();
  const nowMs = chain.time * 1000;
  const mandate = qm.grant({
    key: principal,
    agent: qm.describeKey(agent),
    scopes: [{ action: 'payment.send', currency: 'USD', maxPerAction: '600', maxTotal: '1000' }],
    validFrom: new Date(nowMs - 60000).toISOString(),
    validUntil: new Date(nowMs + 86400000).toISOString(),
  });
  const pay = (ledger) => qm.act(Object.assign({ key: agent, mandate, ledger, action: 'payment.send', currency: 'USD', amount: '600', counterparty: PAYEE }, ep));
  return { chain, ep, principal, agent, mandate, pay };
}

function driverStore(answer) {
  const docs = new Map();
  const tick = () => new Promise((resolve) => setImmediate(resolve));
  return {
    docs,
    async read(name) {
      await tick();
      return docs.has(name) ? docs.get(name) : null;
    },
    async compareAndSwap(name, expected, next) {
      await tick();
      const matched = (docs.has(name) ? docs.get(name) : null) === expected;
      if (matched) docs.set(name, next);
      return answer(matched);
    },
  };
}

test('act signs only one of two concurrent actions under maxTotal when the store answers a failed swap with an object', async () => {
  const w = setup();
  const store = driverStore((matched) => (matched ? true : { acknowledged: true, matchedCount: 0, modifiedCount: 0 }));
  const res = await Promise.allSettled([0, 1].map(() => w.pay(store)));
  const signed = res.filter((r) => r.status === 'fulfilled');
  const refused = res.filter((r) => r.status === 'rejected');
  assert.strictEqual(signed.length, 1);
  assert.strictEqual(refused.length, 1);
  assert.strictEqual(refused[0].reason.code, 'QMANDATE_STORE');
  assert.strictEqual(signed[0].value.statement.total, '600');
  const state = Ledger.parseState(store.docs.get(Ledger.nameOf(qm.mandateRef(w.mandate), 'payment.send')), qm.mandateRef(w.mandate), 'payment.send');
  assert.strictEqual(state.total, '600');
  assert.strictEqual(state.sequence, '1');
});

test('act refuses every answer of compareAndSwap other than true or false and signs nothing', async () => {
  for (const odd of [{ acknowledged: true, matchedCount: 1, modifiedCount: 1 }, 1, 'true', null, undefined, [], Promise.resolve(true).then(() => 1)]) {
    const w = setup();
    const store = driverStore(() => odd);
    await assert.rejects(w.pay(store), (e) => e.code === 'QMANDATE_STORE', String(odd));
  }
});

test('act retries on false and still keeps concurrent actions within maxTotal', async () => {
  const w = setup();
  const store = driverStore((matched) => matched);
  const res = await Promise.allSettled([0, 1, 2].map(() => w.pay(store)));
  const signed = res.filter((r) => r.status === 'fulfilled');
  assert.strictEqual(signed.length, 1);
  assert.ok(res.filter((r) => r.status === 'rejected').every((r) => r.reason.code === 'QMANDATE_NOT_AUTHORISED'));
});

test('consume refuses a store answer that is not a boolean and never reports the action as recorded', async () => {
  const w = setup();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qmandate-store-'));
  dirs.push(dir);
  const action = await w.pay(dir);
  const swaps = driverStore((matched) => (matched ? { acknowledged: true } : { acknowledged: true, matchedCount: 0 }));
  await assert.rejects(qm.consume(action, swaps), (e) => e.code === 'QMANDATE_STORE');
  const onceObject = { read: async () => null, compareAndSwap: async () => true, createOnce: async () => ({ inserted: 1 }) };
  await assert.rejects(qm.consume(action, onceObject), (e) => e.code === 'QMANDATE_STORE');
  const onceFalse = { read: async () => null, compareAndSwap: async () => true, createOnce: async () => false };
  await assert.rejects(qm.consume(action, onceFalse), (e) => e.code === 'QMANDATE_ALREADY_EXECUTED');
  const strict = driverStore((matched) => matched);
  const race = await Promise.allSettled([0, 1, 2, 3].map(() => qm.consume(action, strict)));
  assert.strictEqual(race.filter((r) => r.status === 'fulfilled').length, 1);
  assert.ok(race.filter((r) => r.status === 'rejected').every((r) => r.reason.code === 'QMANDATE_ALREADY_EXECUTED'));
});

test('executedIn answers from the folder consume writes to and from a store of your own', async () => {
  const w = setup();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qmandate-store-'));
  dirs.push(dir);
  const executed = fs.mkdtempSync(path.join(os.tmpdir(), 'qmandate-executed-'));
  dirs.push(executed);
  const action = await w.pay(dir);
  const ref = F.refOf(F.parse(action));
  const fromFolder = qm.executedIn(executed, action);
  assert.strictEqual(await fromFolder(ref), false);
  await qm.consume(action, executed);
  assert.strictEqual(await fromFolder(ref), true);
  await assert.rejects(fromFolder('0'.repeat(64)), (e) => e.code === 'QMANDATE_INVALID_INPUT');
  const store = driverStore((matched) => matched);
  const fromStore = qm.executedIn(store, action);
  assert.strictEqual(await fromStore(ref), false);
  await qm.consume(action, store);
  assert.strictEqual(await fromStore(ref), true);
  const odd = qm.executedIn({ read: async () => ({ text: 'x' }), compareAndSwap: async () => false }, action);
  await assert.rejects(odd(ref), (e) => e.code === 'QMANDATE_STORE');
  const verdict = await qm.verify(action, Object.assign({ type: 'action', mandate: w.mandate, principalKeyId: qm.keyId(w.principal), revocations: [], priorActions: [], requireAnchor: false, executed: odd }, w.ep));
  assert.ok(verdict.checks.some((c) => c.name === 'once' && !c.ok && c.indeterminate));
  const missing = qm.executedIn(path.join(executed, 'missing'), action);
  await assert.rejects(missing(ref), (e) => e.code === 'QMANDATE_LEDGER');
  assert.throws(() => qm.executedIn(undefined, action), (e) => e.code === 'QMANDATE_INVALID_INPUT');
  assert.throws(() => qm.executedIn({}, action), (e) => e.code === 'QMANDATE_INVALID_INPUT');
});
