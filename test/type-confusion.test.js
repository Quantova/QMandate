// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const qm = require('..');
const { makeChain, client } = require('./chain');

const ROOT = path.join(__dirname, '..');

function world(t) {
  const chain = makeChain(ROOT);
  const ep = { network: 'testnet', trustCustomEndpoints: true, clients: [client(chain, 'a'), client(chain, 'b')] };
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qmandate-type-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const principal = qm.generateKey();
  const agent = qm.generateKey();
  const stranger = qm.generateKey();
  const scopes = [{ action: 'pay', currency: 'USD', maxPerAction: '100', maxTotal: '1000' }];
  const window = { validFrom: new Date(Date.now() - 60000).toISOString(), validUntil: new Date(Date.now() + 86400000).toISOString() };
  const mandate = qm.grant(Object.assign({ key: principal, agent: qm.keyId(agent), scopes }, window));
  const foreign = qm.grant(Object.assign({ key: stranger, agent: qm.keyId(agent), scopes }, window));
  return { chain, ep, dir, principal, agent, stranger, mandate, foreign };
}

test('a revocation signed by another key never passes for an action or a revocation of the mandate', async (t) => {
  const w = world(t);
  const forged = qm.revoke({ key: w.stranger, mandate: w.foreign });
  const base = Object.assign({ mandate: w.mandate, principalKeyId: qm.keyId(w.principal), revocations: [], priorActions: [], requireAnchor: false }, w.ep);
  await assert.rejects(qm.verify(forged, base), (e) => e.code === 'QMANDATE_INVALID_INPUT');
  const asAction = await qm.verify(forged, Object.assign({ type: 'action' }, base));
  assert.strictEqual(asAction.status, 'invalid');
  assert.strictEqual(asAction.valid, false);
  const asRevoke = await qm.verify(forged, Object.assign({ type: 'revoke' }, base));
  assert.strictEqual(asRevoke.status, 'invalid');
  assert.ok(asRevoke.checks.some((c) => c.name === 'expected principal' && !c.ok));
  assert.ok(asRevoke.checks.some((c) => c.name === 'mandate binding' && !c.ok));
  await assert.rejects(qm.verify(forged, Object.assign({ type: 'revoke' }, base, { mandate: undefined })), (e) => e.code === 'QMANDATE_INVALID_INPUT');
});

test('the mandate itself is never accepted where an action is expected, and an action never as a mandate', async (t) => {
  const w = world(t);
  const payee = qm.keyId(qm.generateKey());
  const act = await qm.act(Object.assign({ key: w.agent, mandate: w.mandate, ledger: w.dir, action: 'pay', currency: 'USD', amount: '50', counterparty: 'key ' + payee, details: Buffer.from('invoice 1') }, w.ep));
  const base = Object.assign({ details: Buffer.from('invoice 1'), counterpartyKeyId: payee, mandate: w.mandate, principalKeyId: qm.keyId(w.principal), revocations: [], priorActions: [], requireAnchor: false }, w.ep);
  const replay = await qm.verify(w.mandate, Object.assign({ type: 'action' }, base));
  assert.strictEqual(replay.status, 'invalid');
  assert.strictEqual(replay.action, undefined);
  const swapped = await qm.verify(act, Object.assign({ type: 'mandate' }, base));
  assert.strictEqual(swapped.valid, false);
  const honest = await qm.verify(act, Object.assign({ type: 'action' }, base));
  assert.strictEqual(honest.status, 'valid', JSON.stringify(honest.checks.filter((c) => !c.ok)));
});

test('a genuine revocation needs its anchor unless anchors are waived', async (t) => {
  const w = world(t);
  const revocation = qm.revoke({ key: w.principal, mandate: w.mandate });
  const base = Object.assign({ type: 'revoke', mandate: w.mandate, principalKeyId: qm.keyId(w.principal) }, w.ep);
  const strict = await qm.verify(revocation, base);
  assert.strictEqual(strict.valid, false);
  assert.ok(strict.checks.some((c) => c.name === 'anchor' && !c.ok));
  const waived = await qm.verify(revocation, Object.assign({ requireAnchor: false }, base));
  assert.strictEqual(waived.status, 'valid', JSON.stringify(waived.checks.filter((c) => !c.ok)));
});

test('the command line refuses to verify without the expected type and never prints VALID for a revocation by another key', (t) => {
  const w = world(t);
  const forged = qm.revoke({ key: w.stranger, mandate: w.foreign });
  const revFile = path.join(w.dir, 'revoke.json');
  const mandateFile = path.join(w.dir, 'mandate.json');
  fs.writeFileSync(revFile, JSON.stringify(forged));
  fs.writeFileSync(mandateFile, JSON.stringify(w.mandate));
  const run = (extra) => spawnSync(process.execPath, [path.join(ROOT, 'bin', 'qmandate.js'), 'verify', revFile, '--network', 'testnet', '--principal-key-id', qm.keyId(w.principal), '--no-revocations', '--no-prior-actions', '--allow-unanchored', '--at', new Date().toISOString()].concat(extra), { encoding: 'utf8' });
  const untyped = run([]);
  assert.strictEqual(untyped.status, 64);
  assert.match(untyped.stderr, /--type/);
  for (const type of ['action', 'revoke']) {
    const r = run(['--type', type, '--mandate', mandateFile]);
    assert.notStrictEqual(r.status, 0);
    assert.doesNotMatch(r.stdout, /^VALID$/m);
  }
});
