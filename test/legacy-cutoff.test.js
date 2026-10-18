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
const { makeChain, client, SEED, qstampRoot } = require('./chain');
const { PAYEE, bound, grantIssuedEarly } = require('./bind');

const ROOT = path.join(__dirname, '..');
const qstamp = require(qstampRoot(ROOT));
const dirs = [];

test.after(() => {
  for (const d of dirs) fs.rmSync(d, { recursive: true, force: true });
});

function proven(t) {
  const had = Object.prototype.hasOwnProperty.call(qstamp, 'isProven');
  const before = qstamp.isProven;
  qstamp.isProven = () => true;
  t.after(() => {
    if (had) qstamp.isProven = before;
    else delete qstamp.isProven;
  });
}

const SCOPES = [{ action: 'payment.send', currency: 'USD', maxPerAction: '500', maxTotal: '1000' }];

function setup(early) {
  const chain = makeChain(ROOT);
  const ep = { trustCustomEndpoints: true, clients: [client(chain, 'a'), client(chain, 'b')] };
  const principal = qm.generateKey();
  const agent = qm.generateKey();
  const validFrom = new Date(Date.now() - 60000).toISOString();
  const validUntil = new Date((chain.time + 86400) * 1000).toISOString();
  const mandate = early ? grantIssuedEarly(principal, agent, SCOPES, validFrom, validUntil) : qm.grant({ key: principal, agent: qm.describeKey(agent), scopes: SCOPES, validFrom, validUntil });
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qmandate-cutoff-'));
  dirs.push(dir);
  return { chain, ep, principal, agent, mandate, dir };
}

function olderAction(s, m, amount) {
  const mp = F.parse(m);
  const st = {
    mandateId: mp.statement.mandateId,
    mandateRef: F.refOf(mp),
    actionId: crypto.randomBytes(16).toString('hex'),
    agentKeyId: qm.keyId(s.agent),
    action: 'payment.send',
    currency: 'USD',
    amount,
    counterparty: PAYEE,
    detailsDigest: F.sha3(Buffer.alloc(0)).toString('hex'),
    actedAt: new Date(s.chain.time * 1000).toISOString(),
    note: '',
  };
  const pk = qm.publicKey(s.agent);
  const sig = native.sign(s.agent, F.payload('action', st, F.VERSION), Uint8Array.from(crypto.randomBytes(32)));
  return { format: F.FORMAT, type: 'action', algorithm: F.ALGORITHM, signer: { id: qm.keyId(s.agent), publicKey: Buffer.from(pk).toString('base64') }, statement: st, signature: Buffer.from(sig).toString('base64') };
}

const opts = (s, m, env, priorActions) => Object.assign({ type: 'action', mandate: m, principalKeyId: qm.keyId(s.principal), revocations: [], priorActions, acceptLegacyActions: true, maxAnchorDelay: 366 * 86400 }, bound(env), s.ep);

test('the cutoff is the release time of the chained action format', () => {
  assert.strictEqual(F.LEGACY_CUTOFF, '2026-10-17T19:01:44.000Z');
  assert.strictEqual(qm.LEGACY_CUTOFF, F.LEGACY_CUTOFF);
});

test('an action in the format qmandate/1 under a mandate issued after the cutoff is invalid even with acceptLegacyActions', async (t) => {
  proven(t);
  const s = setup(false);
  const [m] = await qm.anchor(s.mandate, Object.assign({ seed: SEED, index: 0 }, s.ep));
  const [old] = await qm.anchor(olderAction(s, m, '400'), Object.assign({ seed: SEED, index: 0, mandate: m }, s.ep));
  const r = await qm.verify(old, opts(s, m, old, []));
  assert.strictEqual(r.status, 'invalid');
  assert.match(r.checks.find((c) => c.name === 'older format' && !c.ok).detail, /issued before 2026-10-17T19:01:44.000Z/);
});

test('under a mandate issued before the cutoff an older action is accepted until the first chained action and refused after it', async (t) => {
  proven(t);
  const s = setup(true);
  const [m] = await qm.anchor(s.mandate, Object.assign({ seed: SEED, index: 0 }, s.ep));
  const [before] = await qm.anchor(olderAction(s, m, '100'), Object.assign({ seed: SEED, index: 0, mandate: m }, s.ep));
  const accepted = await qm.verify(before, opts(s, m, before, []));
  assert.strictEqual(accepted.status, 'valid', JSON.stringify(accepted.checks.filter((c) => !c.ok)));
  const signed = await qm.act(Object.assign({ key: s.agent, mandate: m, ledger: s.dir, action: 'payment.send', currency: 'USD', amount: '500', counterparty: PAYEE, spent: '100' }, s.ep));
  const [first] = await qm.anchor(signed, Object.assign({ seed: SEED, index: 0, mandate: m }, s.ep));
  const still = await qm.verify(before, opts(s, m, before, [first]));
  assert.strictEqual(still.status, 'valid', JSON.stringify(still.checks.filter((c) => !c.ok)));
  const [after] = await qm.anchor(olderAction(s, m, '400'), Object.assign({ seed: SEED, index: 0, mandate: m }, s.ep));
  const refused = await qm.verify(after, opts(s, m, after, [first, before]));
  assert.strictEqual(refused.status, 'invalid');
  assert.match(refused.checks.find((c) => c.name === 'older format' && !c.ok).detail, /anchored after the first action in a newer format/);
  const unanchored = olderAction(s, m, '400');
  const open = await qm.verify(unanchored, Object.assign(opts(s, m, unanchored, [first]), { requireAnchor: false }));
  assert.notStrictEqual(open.status, 'valid');
});
