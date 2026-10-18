// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const path = require('path');
const qm = require('..');
const F = require('../lib/format');
const native = require('../lib/native');
const { makeChain, client, SEED, qstampRoot } = require('./chain');

const ROOT = path.join(__dirname, '..');
const qstamp = require(qstampRoot(ROOT));
const iso = (s) => new Date(s * 1000).toISOString();

function proven(t) {
  const had = Object.prototype.hasOwnProperty.call(qstamp, 'isProven');
  const before = qstamp.isProven;
  qstamp.isProven = (r) => !!r && r.status === 'unproven' && r.trust === 'custom-endpoints' && r.checks.every((c) => c.ok || c.name === 'proof');
  t.after(() => {
    if (had) qstamp.isProven = before;
    else delete qstamp.isProven;
  });
}

function issuedAt(env, key, seconds) {
  const p = F.parse(env);
  const statement = Object.assign({}, env.statement, { issuedAt: iso(seconds) });
  const signature = native.sign(key, F.payload(env.type, statement, p.version), new Uint8Array(crypto.randomBytes(32)));
  return Object.assign({}, env, { statement, signature: Buffer.from(signature).toString('base64') });
}

test('a mandate issued more than a day before its anchor, or anchored after the time of verification, is not proven', async (t) => {
  proven(t);
  const now = Math.floor(Date.now() / 1000);
  const chain = makeChain(ROOT, { time: now - 4 * 86400 });
  const ep = { trustCustomEndpoints: true, clients: [client(chain, 'a'), client(chain, 'b')] };
  const principal = qm.generateKey();
  const grant = qm.grant({ key: principal, agent: qm.keyId(qm.generateKey()), scopes: [{ action: 'pay', currency: 'EUR', maxPerAction: '100', maxTotal: '1000' }], validFrom: iso(now - 4 * 86400), validUntil: iso(now + 86400) });
  const anchorAt = async (env, at) => {
    chain.nextBlockTime = at;
    return (await qm.anchor(env, Object.assign({ seed: SEED, index: 0 }, ep)))[0];
  };
  const old = await anchorAt(issuedAt(grant, principal, now - 3 * 86400 - 60), now - 60);
  const fresh = await anchorAt(issuedAt(grant, principal, now - 180), now - 60);
  chain.newBlock();
  const opts = Object.assign({ type: 'mandate', principalKeyId: qm.keyId(principal), revocations: [] }, ep);
  const late = await qm.verify(old, opts);
  assert.strictEqual(late.valid, false);
  assert.ok(late.checks.some((c) => !c.ok && /24 hours/.test(c.detail)));
  assert.strictEqual((await qm.verify(old, Object.assign({ maxAnchorDelay: 4 * 86400 }, opts))).status, 'valid');
  assert.strictEqual((await qm.verify(fresh, opts)).status, 'valid');
  assert.strictEqual((await qm.verify(fresh, Object.assign({ at: iso(now - 1800) }, opts))).valid, false);
});

test('a mandate anchor interrupted before finality keeps its pending stamp and complete finishes it without a second transaction', async (t) => {
  proven(t);
  const chain = makeChain(ROOT);
  let hold = true;
  const holding = { transaction: (c, id) => {
    const tx = c.txs.get(id);
    return tx ? Object.assign({}, tx, hold ? { status: 'pending' } : {}) : null;
  } };
  const ep = { trustCustomEndpoints: true, clients: [client(chain, 'a', holding), client(chain, 'b', holding)] };
  const principal = qm.generateKey();
  const window = { validFrom: new Date(Date.now() - 60000).toISOString(), validUntil: new Date(Date.now() + 86400000).toISOString() };
  const grant = () => qm.grant(Object.assign({ key: principal, agent: qm.keyId(qm.generateKey()), scopes: [{ action: 'pay', currency: 'EUR', maxPerAction: '100', maxTotal: '1000' }] }, window));
  const mandate = grant();
  let seen = null;
  const err = await qm.anchor(mandate, Object.assign({ seed: SEED, index: 0, timeoutMs: 1500, onPending: (p) => { seen = p; } }, ep)).then(() => null, (e) => e);
  assert.ok(err, 'the anchor finished although finality was held back');
  const pending = err.pending || seen;
  assert.ok(pending && pending.records.every((r) => /^[0-9a-f]{64}$/.test(r.salt)));
  hold = false;
  const sent = chain.txs.size;
  const [done] = await qm.complete(mandate, pending, ep);
  assert.strictEqual(chain.txs.size, sent);
  assert.strictEqual(done.anchor.anchor.tx, pending.tx);
  await assert.rejects(qm.complete(grant(), pending, ep));
  chain.newBlock();
  const r = await qm.verify(done, Object.assign({ type: 'mandate', principalKeyId: qm.keyId(principal), revocations: [] }, ep));
  assert.strictEqual(r.status, 'valid', JSON.stringify(r.checks.filter((c) => !c.ok)));
});
