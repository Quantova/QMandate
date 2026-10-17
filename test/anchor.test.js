// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const qm = require('..');
const M = require('../lib/mandate');
const F = require('../lib/format');
const { makeChain, client, SEED, qstampRoot } = require('./chain');

const ROOT = path.join(__dirname, '..');
const qstamp = require(qstampRoot(ROOT));
const dirs = [];

test.after(() => {
  for (const d of dirs) fs.rmSync(d, { recursive: true, force: true });
});

function setup(lifetime) {
  const chain = makeChain(ROOT);
  const ep = { trustCustomEndpoints: true, clients: [client(chain, 'a'), client(chain, 'b')] };
  const principal = qm.generateKey();
  const agent = qm.generateKey();
  const mandate = qm.grant({
    key: principal,
    agent: qm.describeKey(agent),
    scopes: [{ action: 'payment.send', currency: 'USD', maxPerAction: '500', maxTotal: '800' }],
    validFrom: new Date(Date.now() - 60000).toISOString(),
    validUntil: new Date((chain.time + lifetime) * 1000 + 537).toISOString(),
  });
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qmandate-anchor-'));
  dirs.push(dir);
  return { chain, ep, principal, agent, mandate, dir };
}

async function anchoredPair(s) {
  const [m] = await qm.anchor(s.mandate, Object.assign({ seed: SEED, index: 0 }, s.ep));
  const a = await qm.act(Object.assign({ key: s.agent, mandate: m, ledger: s.dir, action: 'payment.send', currency: 'USD', amount: '100' }, s.ep));
  return { m, a };
}

test('the anchor deadline does not reveal a distant mandate expiry', () => {
  const now = 1800000000;
  const a = M.deadlineFor(now + 30 * 86400 + 17, now);
  const b = M.deadlineFor(now + 90 * 86400 + 4242, now);
  assert.strictEqual(a, b);
  assert.strictEqual(a % 3600, 0);
  assert.ok(a >= now + 3600 && a <= now + 7200);
});

test('near expiry the deadline is rounded down and never later than the expiry', () => {
  const now = 1800000000;
  for (const left of [5000, 3000, 1000, 400, 290, 10]) {
    const expiry = now + left;
    const d = M.deadlineFor(expiry, now);
    assert.ok(d <= expiry, 'deadline after expiry for ' + left);
    assert.ok(d >= now + 300 || d === expiry, 'deadline too close for ' + left);
  }
  assert.strictEqual(M.deadlineFor(now + 5000, now) % 3600, 0);
  assert.strictEqual(M.deadlineFor(now + 1000, now) % 600, 0);
  assert.strictEqual(M.deadlineFor(now + 400, now) % 60, 0);
  assert.strictEqual(M.deadlineFor(now + 290, now), now + 290);
});

test('anchored actions carry a coarse deadline that the chain enforces', async () => {
  const s = setup(30 * 86400);
  const { m, a } = await anchoredPair(s);
  const [anchored] = await qm.anchor(a, Object.assign({ seed: SEED, index: 0, mandate: m }, s.ep));
  const expiry = M.untilOf(F.parse(m));
  assert.strictEqual(anchored.anchor.until % 3600, 0);
  assert.ok(anchored.anchor.until < expiry);
  assert.ok(anchored.anchor.until > s.chain.time);
});

test('the chain refuses an action anchor that lands after its deadline', async () => {
  const s = setup(200);
  const { m, a } = await anchoredPair(s);
  s.chain.nextBlockTime = s.chain.time + 400;
  await assert.rejects(qm.anchor(a, Object.assign({ seed: SEED, index: 0, mandate: m, timeoutMs: 1000 }, s.ep)));
});

test('complete accepts a pending stamp with an earlier deadline and refuses a later one', async () => {
  const s = setup(30 * 86400);
  const { m, a } = await anchoredPair(s);
  let pending;
  const [anchored] = await qm.anchor(a, Object.assign({ seed: SEED, index: 0, mandate: m, onPending: (p) => { pending = p; } }, s.ep));
  const done = await qm.complete(a, pending, Object.assign({ mandate: m }, s.ep));
  assert.deepStrictEqual(done[0].anchor, anchored.anchor);
  const later = Object.assign({}, pending, { until: M.untilOf(F.parse(m)) + 1 });
  await assert.rejects(qm.complete(a, later, Object.assign({ mandate: m }, s.ep)), /deadline at or before the expiry/);
});

test('a receipt from endpoints that are not pinned operators never verifies valid', async () => {
  const s = setup(3600);
  const { m, a } = await anchoredPair(s);
  const [anchored] = await qm.anchor(a, Object.assign({ seed: SEED, index: 0, mandate: m }, s.ep));
  const base = { type: 'action', mandate: m, principalKeyId: qm.keyId(s.principal), revocations: [], priorActions: [] };
  const strict = await qm.verify(anchored, Object.assign({}, base, s.ep));
  assert.strictEqual(strict.status, 'unproven');
  assert.strictEqual(strict.valid, false);
  assert.strictEqual(strict.anchoredAt, null);
  assert.ok(strict.checks.some((c) => c.name === 'anchor proof' && !c.ok && c.unproven));
  const lenient = await qm.verify(anchored, Object.assign({ strict: false }, base, s.ep));
  assert.strictEqual(lenient.status, 'unproven');
  assert.notStrictEqual(lenient.anchoredAt, null);
  await assert.rejects(qm.verify(anchored, Object.assign({}, base, { trustCustomEndpoints: true, clients: [s.ep.clients[0]], trustSingleEndpoint: true })), /strict/);
  const single = await qm.verify(anchored, Object.assign({ strict: false }, base, { trustCustomEndpoints: true, clients: [s.ep.clients[0]], trustSingleEndpoint: true }));
  assert.notStrictEqual(single.status, 'valid');
  const mandate = await qm.verify(m, { type: 'mandate', principalKeyId: qm.keyId(s.principal), revocations: [], trustCustomEndpoints: true, clients: s.ep.clients });
  assert.strictEqual(mandate.status, 'unproven');
});

test('a fabricated receipt for an action that was never anchored cannot verify valid', async () => {
  const s = setup(3600);
  const { m, a } = await anchoredPair(s);
  const fake = makeChain(ROOT);
  fake.time = s.chain.time;
  const forged = { trustCustomEndpoints: true, clients: [client(fake, 'c'), client(fake, 'd')] };
  const [onFake] = await qm.anchor(a, Object.assign({ seed: SEED, index: 0, mandate: m }, forged));
  const base = { type: 'action', mandate: m, principalKeyId: qm.keyId(s.principal), revocations: [], priorActions: [] };
  for (const strict of [true, false]) {
    const r = await qm.verify(onFake, Object.assign({ strict }, base, forged));
    assert.notStrictEqual(r.status, 'valid');
    const honest = await qm.verify(onFake, Object.assign({ strict }, base, s.ep));
    assert.notStrictEqual(honest.status, 'valid');
  }
});

test('an anchor proven by pinned operators verifies valid', async (t) => {
  const s = setup(3600);
  const { m, a } = await anchoredPair(s);
  const [anchored] = await qm.anchor(a, Object.assign({ seed: SEED, index: 0, mandate: m }, s.ep));
  const had = Object.prototype.hasOwnProperty.call(qstamp, 'isProven');
  const before = qstamp.isProven;
  qstamp.isProven = () => true;
  t.after(() => {
    if (had) qstamp.isProven = before;
    else delete qstamp.isProven;
  });
  const r = await qm.verify(anchored, Object.assign({ type: 'action', mandate: m, principalKeyId: qm.keyId(s.principal), revocations: [], priorActions: [] }, s.ep));
  assert.strictEqual(r.status, 'valid', JSON.stringify(r.checks.filter((c) => !c.ok)));
  assert.notStrictEqual(r.anchoredAt, null);
});

test('endpoints chosen by the caller need trustCustomEndpoints, loopback needs allowLoopback and the anchor sender is checked', async (t) => {
  const s = setup(3600);
  const { m, a } = await anchoredPair(s);
  const [anchored] = await qm.anchor(a, Object.assign({ seed: SEED, index: 0, mandate: m }, s.ep));
  const base = { type: 'action', mandate: m, principalKeyId: qm.keyId(s.principal), revocations: [], priorActions: [] };
  const untrusted = await qm.verify(anchored, Object.assign({ clients: s.ep.clients, at: new Date().toISOString() }, base));
  assert.notStrictEqual(untrusted.status, 'valid');
  const loop = await qm.verify(anchored, Object.assign({ trustCustomEndpoints: true, rpc: 'http://127.0.0.1:9', at: new Date().toISOString() }, base));
  assert.notStrictEqual(loop.status, 'valid');
  const before = qstamp.isProven;
  qstamp.isProven = () => true;
  t.after(() => {
    qstamp.isProven = before;
  });
  const wrong = await qm.verify(anchored, Object.assign({ expectedSender: s.chain.core.address(new Uint8Array(32).fill(9), 0) }, base, s.ep));
  assert.strictEqual(wrong.status, 'invalid');
  const right = await qm.verify(anchored, Object.assign({ expectedSender: s.chain.core.address(SEED, 0) }, base, s.ep));
  assert.strictEqual(right.status, 'valid', JSON.stringify(right.checks.filter((c) => !c.ok)));
});
