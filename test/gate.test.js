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
const { makeChain, client, SEED } = require('./chain');

const ROOT = path.join(__dirname, '..');
const dirs = [];

test.after(() => {
  for (const d of dirs) fs.rmSync(d, { recursive: true, force: true });
});

function folder() {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'qmandate-gate-'));
  dirs.push(d);
  return d;
}

function setup(maxPerAction, maxTotal) {
  const chain = makeChain(ROOT);
  const ep = { trustCustomEndpoints: true, clients: [client(chain, 'a'), client(chain, 'b')] };
  const principal = qm.generateKey();
  const agent = qm.generateKey();
  const mandate = qm.grant({
    key: principal,
    agent: qm.describeKey(agent),
    scopes: [{ action: 'payment.send', currency: 'USD', maxPerAction, maxTotal }],
    validFrom: new Date(Date.now() - 60000).toISOString(),
    validUntil: new Date((chain.time + 86400) * 1000).toISOString(),
  });
  return { chain, ep, principal, agent, mandate };
}

const refOf = (e) => F.refOf(F.parse(e));

test('concurrent tool calls that follow the documented flow never move more than the total limit', async () => {
  for (let round = 0; round < 5; round += 1) {
    const s = setup('600', '1000');
    const ledger = folder();
    const moved = [];
    const tool = async (counterparty) => {
      const request = { action: 'payment.send', currency: 'USD', amount: '600', counterparty };
      await qm.authorise(s.mandate, request, Object.assign({ ledger }, s.ep));
      let action;
      try {
        action = await qm.act(Object.assign({ key: s.agent, mandate: s.mandate, ledger }, request, s.ep));
      } catch (e) {
        assert.strictEqual(e.code, 'QMANDATE_NOT_AUTHORISED');
        return 'refused';
      }
      moved.push(BigInt(action.statement.amount));
      return 'paid';
    };
    const outcomes = await Promise.all(['Supplier A', 'Supplier B', 'Supplier C'].map(tool));
    const total = moved.reduce((a, b) => a + b, 0n);
    assert.ok(total <= 1000n, 'moved ' + total + ' against a limit of 1000');
    assert.deepStrictEqual(outcomes.filter((o) => o === 'paid').length, 1);
    const rec = await qm.ledgerActions(ledger, s.mandate, 'payment.send');
    assert.strictEqual(rec.total, total.toString());
    assert.strictEqual(rec.complete, true);
  }
});

test('authorise allows concurrent requests against the same total, which is why it never gates an action', async () => {
  const s = setup('600', '1000');
  const ledger = folder();
  const request = { action: 'payment.send', currency: 'USD', amount: '600' };
  const advice = await Promise.all([0, 1, 2].map(() => qm.authorise(s.mandate, request, Object.assign({ ledger }, s.ep))));
  assert.ok(advice.every((a) => a.allowed));
  const signed = await Promise.allSettled([0, 1, 2].map(() => qm.act(Object.assign({ key: s.agent, mandate: s.mandate, ledger }, request, s.ep))));
  assert.strictEqual(signed.filter((r) => r.status === 'fulfilled').length, 1);
});

function committingStore() {
  const state = new Map();
  const held = new Map();
  const calls = [];
  const tick = () => new Promise((resolve) => setImmediate(resolve));
  return {
    calls,
    held,
    async journal(name, text) {
      calls.push('journal');
      held.set(name, text);
    },
    async read(name) {
      await tick();
      return state.has(name) ? state.get(name) : null;
    },
    async compareAndSwap(name, expected, next, entry) {
      calls.push('swap');
      await tick();
      const cur = state.has(name) ? state.get(name) : null;
      if (cur !== expected) return false;
      state.set(name, next);
      held.set(entry.name, entry.text);
      return true;
    },
    async readJournal(name) {
      return held.has(name) ? held.get(name) : null;
    },
  };
}

test('a store of your own never holds a signed action that its ledger did not count', async () => {
  const s = setup('500', '100000');
  const [m] = await qm.anchor(s.mandate, Object.assign({ seed: SEED, index: 0 }, s.ep));
  const store = committingStore();
  const pay = (amount, counterparty) => qm.act(Object.assign({ key: s.agent, mandate: m, ledger: store, action: 'payment.send', currency: 'USD', amount, counterparty }, s.ep));
  const returned = [];
  for (let round = 0; round < 10; round += 1) {
    returned.push(...await Promise.all([pay('100', 'ACME'), pay('400', 'Globex'), pay('7', 'Initech')]));
  }
  assert.ok(store.calls.every((c) => c === 'swap'));
  const rec = await qm.ledgerActions(store, m, 'payment.send');
  assert.strictEqual(rec.complete, true);
  assert.strictEqual(rec.sequence, '30');
  const committed = new Set(rec.actions.map(refOf));
  assert.deepStrictEqual([...committed].sort(), returned.map(refOf).sort());
  const held = [...store.held.values()].map((t) => refOf(JSON.parse(t)));
  assert.strictEqual(held.length, 30);
  assert.ok(held.every((r) => committed.has(r)), 'the store holds a signed action that is not on the ledger');
});

test('options are read only from the object given and never from Object.prototype', async () => {
  const s = setup('500', '800');
  const ledger = folder();
  const principalKeyId = qm.keyId(s.principal);
  const a = await qm.act(Object.assign({ key: s.agent, mandate: s.mandate, ledger, action: 'payment.send', currency: 'USD', amount: '100' }, s.ep));
  const mOpts = Object.assign({ type: 'mandate', principalKeyId }, s.ep);
  const aOpts = Object.assign({ type: 'action', mandate: s.mandate, principalKeyId }, s.ep);
  const before = [await qm.verify(s.mandate, mOpts), await qm.verify(a, aOpts)];
  const polluted = { requireAnchor: false, revocations: [], priorActions: [], acceptLegacyActions: true, strict: false, spent: '0', counterparty: 'Mallory', counterparties: ['Mallory'] };
  try {
    for (const [k, v] of Object.entries(polluted)) Object.prototype[k] = v;
    const after = [await qm.verify(s.mandate, mOpts), await qm.verify(a, aOpts)];
    for (const [i, r] of after.entries()) {
      assert.strictEqual(r.status, before[i].status);
      assert.notStrictEqual(r.status, 'valid');
    }
    await assert.rejects(qm.authorise(s.mandate, { action: 'payment.send', currency: 'USD', amount: '100' }, s.ep), /spent/);
    const next = await qm.act(Object.assign({ key: s.agent, mandate: s.mandate, ledger, action: 'payment.send', currency: 'USD', amount: '100' }, s.ep));
    assert.strictEqual(next.statement.counterparty, '');
    assert.strictEqual(next.statement.total, '200');
    const g = qm.grant({ key: s.principal, agent: qm.describeKey(s.agent), scopes: [{ action: 'payment.send', currency: 'USD', maxPerAction: '1', maxTotal: '1' }], validUntil: new Date(Date.now() + 3600000).toISOString() });
    assert.deepStrictEqual(g.statement.counterparties, []);
  } finally {
    for (const k of Object.keys(polluted)) delete Object.prototype[k];
  }
});
