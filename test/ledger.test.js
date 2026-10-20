// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');
const qm = require('..');
const { makeChain, client } = require('./chain');

const ROOT = path.join(__dirname, '..');
const dirs = [];

test.after(() => {
  for (const d of dirs) fs.rmSync(d, { recursive: true, force: true });
});

function setup(maxTotal) {
  const chain = makeChain(ROOT);
  const ep = { trustCustomEndpoints: true, clients: [client(chain, 'a'), client(chain, 'b')] };
  const principal = qm.generateKey();
  const agent = qm.generateKey();
  const mandate = qm.grant({
    key: principal,
    agent: qm.describeKey(agent),
    scopes: [{ action: 'payment.send', currency: 'USD', maxPerAction: '500', maxTotal: maxTotal || '800' }],
    validFrom: new Date(Date.now() - 60000).toISOString(),
    validUntil: new Date((chain.time + 3600) * 1000).toISOString(),
  });
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qmandate-ledger-'));
  dirs.push(dir);
  return { chain, ep, principal, agent, mandate, dir };
}

function pay(s, amount, extra) {
  return qm.act(Object.assign({ key: s.agent, mandate: s.mandate, ledger: s.dir, action: 'payment.send', currency: 'USD', amount }, s.ep, extra || {}));
}

test('act refuses to sign without a spend ledger', async () => {
  const s = setup();
  await assert.rejects(qm.act(Object.assign({ key: s.agent, mandate: s.mandate, action: 'payment.send', currency: 'USD', amount: '100', spent: '0' }, s.ep)), /ledger is required/);
});

test('concurrent actions in one process never exceed the total limit', async () => {
  const s = setup();
  const results = await Promise.allSettled([0, 1, 2, 3, 4].map(() => pay(s, '400')));
  const signed = results.filter((r) => r.status === 'fulfilled').map((r) => r.value);
  const refused = results.filter((r) => r.status === 'rejected');
  assert.strictEqual(signed.length, 2);
  assert.strictEqual(refused.length, 3);
  for (const r of refused) assert.strictEqual(r.reason.code, 'QMANDATE_NOT_AUTHORISED');
  const seqs = signed.map((e) => e.statement.sequence).sort();
  assert.deepStrictEqual(seqs, ['1', '2']);
  const totals = signed.map((e) => e.statement.total).sort();
  assert.deepStrictEqual(totals, ['400', '800']);
  assert.ok(signed.every((e) => e.format === qm.ACTION_FORMAT));
});

test('the ledger persists the sequence and total across ledger instances', async () => {
  const s = setup('2000');
  const a1 = await pay(s, '300');
  const a2 = await qm.act(Object.assign({ key: s.agent, mandate: s.mandate, ledger: qm.fileLedger(s.dir), action: 'payment.send', currency: 'USD', amount: '200' }, s.ep));
  assert.strictEqual(a1.statement.sequence, '1');
  assert.strictEqual(a1.statement.previousRef, '');
  assert.strictEqual(a2.statement.sequence, '2');
  assert.strictEqual(a2.statement.total, '500');
  const files = fs.readdirSync(s.dir).filter((f) => f.endsWith('.json'));
  assert.strictEqual(files.length, 1);
  const state = JSON.parse(fs.readFileSync(path.join(s.dir, files[0]), 'utf8'));
  assert.strictEqual(state.sequence, '2');
  assert.strictEqual(state.total, '500');
});

test('a stated spent amount that differs from the ledger is refused', async () => {
  const s = setup('2000');
  await pay(s, '300');
  await assert.rejects(pay(s, '100', { spent: '0' }), /differs from the 300/);
  const a = await pay(s, '100', { spent: '300' });
  assert.strictEqual(a.statement.total, '400');
});

test('an opening amount spent before the ledger existed counts toward the limit', async () => {
  const s = setup();
  const a = await pay(s, '300', { spent: '450' });
  assert.strictEqual(a.statement.total, '750');
  await assert.rejects(pay(s, '100'), (e) => e.code === 'QMANDATE_NOT_AUTHORISED');
});

test('a damaged ledger entry stops signing', async () => {
  const s = setup();
  await pay(s, '100');
  const file = fs.readdirSync(s.dir).find((f) => f.endsWith('.json'));
  fs.writeFileSync(path.join(s.dir, file), '{"format":"qmandate-ledger/1"}\n');
  await assert.rejects(pay(s, '100'), (e) => e.code === 'QMANDATE_LEDGER');
});

const CHILD = `
const qm = require(process.argv[1]);
const fs = require('fs');
const seed = (hex) => Uint8Array.from(Buffer.from(hex, 'hex'));
const now = () => Math.floor(Date.now() / 1000);
const fake = (name) => ({
  base: 'https://' + name + '.example',
  async nodeInfo() { return { chain_id: process.argv[5], genesis_hash: process.argv[6], head_height: 10 }; },
  async block(h) { return { block: 'x', height: h, time: now() }; },
  async transaction() { return null; },
});
const mandate = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
qm.act({ key: seed(process.argv[3]), mandate, ledger: process.argv[4], action: 'payment.send', currency: 'USD', amount: '400', trustCustomEndpoints: true, clients: [fake('a'), fake('b')] })
  .then((e) => { process.stdout.write('signed ' + e.statement.sequence + ' ' + e.statement.total); })
  .catch((e) => { process.stdout.write('refused ' + e.code); });
`;

test('concurrent agent processes sharing a ledger folder never exceed the total limit', async () => {
  const s = setup();
  const net = require('@quantovainc/qstamp').NETWORKS.testnet;
  const mfile = path.join(s.dir, 'mandate.txt');
  fs.writeFileSync(mfile, JSON.stringify(s.mandate));
  const agentHex = Buffer.from(s.agent).toString('hex');
  const runs = [0, 1, 2, 3, 4, 5].map(() => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['-e', CHILD, ROOT, mfile, agentHex, s.dir, net.chainId, net.genesis], { stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    let err = '';
    child.stdout.on('data', (d) => { out += d; });
    child.stderr.on('data', (d) => { err += d; });
    child.on('error', reject);
    child.on('close', () => resolve(out || err));
  }));
  const outs = await Promise.all(runs);
  const signed = outs.filter((o) => o.startsWith('signed ')).sort();
  const refused = outs.filter((o) => o === 'refused QMANDATE_NOT_AUTHORISED');
  assert.deepStrictEqual(signed, ['signed 1 400', 'signed 2 800'], outs.join(' / '));
  assert.strictEqual(refused.length, 4, outs.join(' / '));
});
