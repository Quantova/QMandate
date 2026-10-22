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
const { makeChain, client } = require('./chain');
const { PAYEE } = require('./bind');

const ROOT = path.join(__dirname, '..');
const dirs = [];

test.after(() => {
  for (const d of dirs) fs.rmSync(d, { recursive: true, force: true });
});

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
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qmandate-restore-'));
  dirs.push(dir);
  const name = qm.mandateRef(mandate) + '.payment.send';
  return { chain, ep, principal, agent, mandate, dir, name, state: path.join(dir, name + '.json') };
}

const pay = (s, amount) => qm.act(Object.assign({ key: s.agent, mandate: s.mandate, ledger: s.dir, action: 'payment.send', currency: 'USD', amount, counterparty: PAYEE }, s.ep));
const refOf = (e) => F.refOf(F.parse(e));

test('a spend ledger state restored from an older copy never signs again until it is rebuilt from the journal', async () => {
  const s = setup();
  await pay(s, '500');
  const backup = fs.readFileSync(s.state, 'utf8');
  const a2 = await pay(s, '500');
  await assert.rejects(pay(s, '500'), (e) => e.code === 'QMANDATE_NOT_AUTHORISED');
  fs.writeFileSync(s.state, backup);
  await assert.rejects(pay(s, '500'), (e) => e.code === 'QMANDATE_LEDGER' && /older than its journal/.test(e.message));
  await assert.rejects(pay(s, '1'), (e) => e.code === 'QMANDATE_LEDGER');
  assert.strictEqual(fs.readFileSync(s.state, 'utf8'), backup);
  const rec = await qm.ledgerActions(s.dir, s.mandate, 'payment.send');
  assert.strictEqual(rec.sequence, '2');
  assert.strictEqual(rec.total, '1000');
  assert.strictEqual(rec.complete, true);
  assert.strictEqual(JSON.parse(fs.readFileSync(s.state, 'utf8')).lastRef, refOf(a2));
  await assert.rejects(pay(s, '1'), (e) => e.code === 'QMANDATE_NOT_AUTHORISED');
});

test('recover rebuilds a deleted or restored state from the highest unbroken chain of the journal', async () => {
  const s = setup();
  await pay(s, '100');
  await pay(s, '200');
  const a3 = await pay(s, '300');
  fs.rmSync(s.state);
  await assert.rejects(pay(s, '50'), (e) => e.code === 'QMANDATE_LEDGER');
  const text = await qm.fileLedger(s.dir).recover(s.name, qm.keyId(s.agent));
  const st = JSON.parse(text);
  assert.strictEqual(st.sequence, '3');
  assert.strictEqual(st.total, '600');
  assert.strictEqual(st.lastRef, refOf(a3));
  assert.strictEqual(st.ledgerId, a3.statement.ledgerId);
  const a4 = await pay(s, '50');
  assert.strictEqual(a4.statement.sequence, '4');
  assert.strictEqual(a4.statement.total, '650');
  assert.strictEqual(a4.statement.previousRef, refOf(a3));
});

test('a journal with a gap is not rebuilt past the gap and the ledger keeps refusing', async () => {
  const s = setup();
  await pay(s, '100');
  const backup = fs.readFileSync(s.state, 'utf8');
  await pay(s, '100');
  await pay(s, '100');
  const second = fs.readdirSync(s.dir).find((f) => f.startsWith(s.name + '.2.') && f.endsWith('.journal'));
  fs.rmSync(path.join(s.dir, second));
  fs.writeFileSync(s.state, backup);
  await assert.rejects(qm.fileLedger(s.dir).recover(s.name, qm.keyId(s.agent)), (e) => e.code === 'QMANDATE_LEDGER' && /missing/.test(e.message));
  await assert.rejects(pay(s, '100'), (e) => e.code === 'QMANDATE_LEDGER');
  assert.strictEqual(fs.readFileSync(s.state, 'utf8'), backup);
});
