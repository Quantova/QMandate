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
const F = require('../lib/format');
const Ledger = require('../lib/ledger');
const native = require('../lib/native');
const { makeChain, client, SEED } = require('./chain');
const { PAYEE, PAYEE_KEY, bound } = require('./bind');

const ROOT = path.join(__dirname, '..');
const qstamp = require('@quantovainc/qstamp');
const dirs = [];

test.after(() => {
  for (const d of dirs) fs.rmSync(d, { recursive: true, force: true });
});

function folder() {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'qmandate-once-'));
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
  const ep = { trustCustomEndpoints: true, clients: [client(chain, 'a'), client(chain, 'b')] };
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
  const signed = await qm.act(Object.assign({ key: agent, mandate, ledger: dir, action: 'payment.send', currency: 'USD', amount: '400', counterparty: PAYEE, details }, ep));
  const [action] = await qm.anchor(signed, Object.assign({ seed: SEED, index: 0, mandate }, ep));
  const opts = Object.assign({ type: 'action', mandate, principalKeyId: qm.keyId(principal), revocations: [], priorActions: [] }, ep);
  return { chain, ep, principal, agent, mandate, dir, details, action, opts };
}

test('verify returns the reference of the action and an executed action fails the once check', async (t) => {
  const w = await world(t);
  const ref = F.refOf(F.parse(w.action));
  const first = await qm.verify(w.action, Object.assign({ details: w.details, counterpartyKeyId: PAYEE_KEY, executed: new Set() }, w.opts));
  assert.strictEqual(first.status, 'valid', JSON.stringify(first.checks.filter((c) => !c.ok)));
  assert.strictEqual(first.actionRef, ref);
  assert.ok(first.checks.some((c) => c.name === 'once' && c.ok));
  const ran = new Set([ref]);
  const again = await qm.verify(JSON.parse(JSON.stringify(w.action)), Object.assign({ details: w.details, counterpartyKeyId: PAYEE_KEY, executed: ran }, w.opts));
  assert.strictEqual(again.status, 'invalid');
  assert.ok(again.checks.some((c) => c.name === 'once' && !c.ok && !c.indeterminate));
  const byFunction = await qm.verify(w.action, Object.assign({ details: w.details, counterpartyKeyId: PAYEE_KEY, executed: async (r) => r === ref }, w.opts));
  assert.strictEqual(byFunction.status, 'invalid');
  const unknown = await qm.verify(w.action, Object.assign({ details: w.details, counterpartyKeyId: PAYEE_KEY, executed: () => 'maybe' }, w.opts));
  assert.strictEqual(unknown.status, 'indeterminate');
  const throws = await qm.verify(w.action, Object.assign({ details: w.details, counterpartyKeyId: PAYEE_KEY, executed: () => { throw new Error('store offline'); } }, w.opts));
  assert.strictEqual(throws.status, 'indeterminate');
  await assert.rejects(qm.verify(w.action, Object.assign({ executed: [ref] }, w.opts)), (e) => e.code === 'QMANDATE_INVALID_INPUT');
});

test('consume records an action once in the ledger folder and refuses a second consume', async (t) => {
  const w = await world(t);
  const ref = F.refOf(F.parse(w.action));
  const done = await qm.consume(w.action, w.dir);
  assert.strictEqual(done.actionRef, ref);
  const name = Ledger.executedName(qm.mandateRef(w.mandate), 'payment.send', F.parse(w.action).statement);
  assert.ok(fs.existsSync(path.join(w.dir, name)));
  assert.strictEqual(fs.statSync(path.join(w.dir, name)).mode & 0o777, 0o600);
  await assert.rejects(qm.consume(w.action, w.dir), (e) => e.code === 'QMANDATE_ALREADY_EXECUTED');
  const copy = Object.assign({}, w.action);
  delete copy.anchor;
  await assert.rejects(qm.consume(copy, qm.fileLedger(w.dir)), (e) => e.code === 'QMANDATE_ALREADY_EXECUTED');
  const results = await Promise.allSettled(Array.from({ length: 8 }, () => qm.consume(w.action, folder())));
  assert.ok(results.every((r) => r.status === 'fulfilled'));
  const shared = folder();
  const race = await Promise.allSettled(Array.from({ length: 8 }, () => qm.consume(w.action, shared)));
  assert.strictEqual(race.filter((r) => r.status === 'fulfilled').length, 1);
  const executed = () => fs.existsSync(path.join(w.dir, Ledger.executedName(qm.mandateRef(w.mandate), 'payment.send', F.parse(w.action).statement)));
  const check = await qm.verify(w.action, Object.assign({ details: w.details, counterpartyKeyId: PAYEE_KEY, executed }, w.opts));
  assert.strictEqual(check.status, 'invalid');
});

test('consume with a store of your own uses its compare and swap and refuses a second consume', async (t) => {
  const w = await world(t);
  const m = new Map();
  const store = {
    async read(name) {
      return m.has(name) ? m.get(name) : null;
    },
    async compareAndSwap(name, expected, next) {
      await new Promise((resolve) => setImmediate(resolve));
      if ((m.has(name) ? m.get(name) : null) !== expected) return false;
      m.set(name, next);
      return true;
    },
  };
  const race = await Promise.allSettled(Array.from({ length: 6 }, () => qm.consume(w.action, store)));
  assert.strictEqual(race.filter((r) => r.status === 'fulfilled').length, 1);
  assert.ok(race.filter((r) => r.status === 'rejected').every((r) => r.reason.code === 'QMANDATE_ALREADY_EXECUTED'));
  const forged = JSON.parse(JSON.stringify(w.action));
  forged.statement.amount = '1';
  await assert.rejects(qm.consume(forged, store), (e) => e.code === 'QMANDATE_INVALID_INPUT');
  await assert.rejects(qm.consume(w.mandate, store), (e) => e.code === 'QMANDATE_INVALID_INPUT');
});

test('in strict mode a metered action is indeterminate unless the verifier binds the details and the payee key', async (t) => {
  const w = await world(t);
  const none = await qm.verify(w.action, w.opts);
  assert.strictEqual(none.status, 'indeterminate');
  assert.ok(none.checks.some((c) => c.name === 'binding' && !c.ok && c.indeterminate));
  const detailsOnly = await qm.verify(w.action, Object.assign({ details: w.details }, w.opts));
  assert.strictEqual(detailsOnly.status, 'indeterminate');
  const keyOnly = await qm.verify(w.action, Object.assign({ counterpartyKeyId: PAYEE_KEY }, w.opts));
  assert.strictEqual(keyOnly.status, 'indeterminate');
  const both = await qm.verify(w.action, Object.assign({}, bound(w.action), w.opts));
  assert.strictEqual(both.status, 'valid', JSON.stringify(both.checks.filter((c) => !c.ok)));
  const otherPayee = await qm.verify(w.action, Object.assign({ details: w.details, counterpartyKeyId: 'e'.repeat(64) }, w.opts));
  assert.strictEqual(otherPayee.status, 'invalid');
  const otherDetails = await qm.verify(w.action, Object.assign({ details: Buffer.from('pay invoice 1001 to account 87654321'), counterpartyKeyId: PAYEE_KEY }, w.opts));
  assert.strictEqual(otherDetails.status, 'invalid');
});

test('an action signed again by the agent is refused by consume and by the executed check', async (t) => {
  const w = await world(t);
  const p = F.parse(w.action);
  const rnd = Uint8Array.from({ length: 32 }, (_, i) => (9 + i) & 255);
  const again = JSON.parse(JSON.stringify(w.action));
  again.signature = Buffer.from(native.sign(w.agent, F.encoded(p), rnd)).toString('base64');
  delete again.anchor;
  assert.notStrictEqual(F.refOf(F.parse(again)), F.refOf(p));
  await qm.consume(w.action, w.dir);
  await assert.rejects(qm.consume(again, w.dir), (e) => e.code === 'QMANDATE_ALREADY_EXECUTED');
  const first = folder();
  await qm.consume(again, first);
  await assert.rejects(qm.consume(w.action, first), (e) => e.code === 'QMANDATE_ALREADY_EXECUTED');
  const once = await qm.verify(again, Object.assign({ details: w.details, counterpartyKeyId: PAYEE_KEY, executed: qm.executedIn(w.dir, again) }, w.opts));
  assert.notStrictEqual(once.status, 'valid');
});

test('a ledger folder given as a symbolic link is refused', async () => {
  const real = folder();
  const link = path.join(folder(), 'linked');
  fs.symlinkSync(real, link);
  await assert.rejects(qm.fileLedger(link).readExecuted('0'.repeat(64) + '.payment.send.executed.seq.1'), (e) => e.code === 'QMANDATE_LEDGER');
});

test('a ledger folder any user can write is refused', async () => {
  const open = folder();
  fs.chmodSync(open, 0o777);
  await assert.rejects(qm.fileLedger(open).readExecuted('0'.repeat(64) + '.payment.send.executed.seq.1'), (e) => e.code === 'QMANDATE_LEDGER' && /every user of this machine/.test(e.message));
});

test('a ledger under a folder any user can change, or with an access control list, is refused', async () => {
  const open = folder();
  fs.chmodSync(open, 0o777);
  const inside = path.join(open, 'ledger');
  fs.mkdirSync(inside, { mode: 0o700 });
  const name = '0'.repeat(64) + '.payment.send.executed.seq.1';
  await assert.rejects(qm.fileLedger(inside).readExecuted(name), (e) => e.code === 'QMANDATE_LEDGER' && /above the ledger can be changed by another user/.test(e.message));
  const listed = folder();
  const acl = process.platform === 'darwin'
    ? spawnSync('chmod', ['+a', 'everyone allow add_file,delete_child', listed])
    : spawnSync('setfacl', ['-m', 'u:nobody:rwx', listed]);
  if (acl.status === 0) await assert.rejects(qm.fileLedger(listed).readExecuted(name), (e) => e.code === 'QMANDATE_LEDGER' && /access control list/.test(e.message));
});

test('a ledger reached through a symbolic link or a parent that another user can change is refused', async () => {
  const CODE = 'QMANDATE_LEDGER';
  const OPEN = (d) => qm.fileLedger(d).readExecuted('0'.repeat(64) + '.payment.send.executed.seq.1');

  const parentAcl = folder();
  const underAcl = path.join(parentAcl, 'ledger');
  fs.mkdirSync(underAcl, { mode: 0o700 });
  const set = process.platform === 'darwin' ? spawnSync('chmod', ['+a', 'everyone allow add_file,delete_child,add_subdirectory', parentAcl]) : spawnSync('setfacl', ['-m', 'u:nobody:rwx', parentAcl]);
  if (set.status === 0) await assert.rejects(OPEN(underAcl), (e) => e.code === CODE && /can be changed by another user/.test(e.message));
  const safeTarget = folder();
  const openHolder = folder();
  fs.chmodSync(openHolder, 0o777);
  const linkInOpen = path.join(openHolder, 'ledger');
  fs.symlinkSync(safeTarget, linkInOpen);
  await assert.rejects(OPEN(linkInOpen), (e) => e.code === CODE && /can be changed by another user|is a symbolic link/.test(e.message));
  const openTop = folder();
  fs.chmodSync(openTop, 0o777);
  const realUp = folder();
  fs.mkdirSync(path.join(realUp, 'ledger'), { mode: 0o700 });
  fs.symlinkSync(realUp, path.join(openTop, 'up'));
  await assert.rejects(OPEN(path.join(openTop, 'up', 'ledger')), (e) => e.code === CODE && /can be changed by another user/.test(e.message));
  const chainOwn = folder();
  const chainOpen = folder();
  fs.chmodSync(chainOpen, 0o777);
  const chainTarget = folder();
  fs.mkdirSync(path.join(chainTarget, 'ledger'), { mode: 0o700 });
  fs.symlinkSync(chainTarget, path.join(chainOpen, 'L2'));
  fs.symlinkSync(path.join(chainOpen, 'L2'), path.join(chainOwn, 'L1'));
  await assert.rejects(OPEN(path.join(chainOwn, 'L1', 'ledger')), (e) => e.code === CODE && /can be changed by another user/.test(e.message));
  const homeLike = folder();
  if (process.platform === 'darwin') spawnSync('chmod', ['+a', 'everyone deny delete', homeLike]);
  const denied = path.join(homeLike, 'ledger');
  fs.mkdirSync(denied, { mode: 0o700 });
  await OPEN(denied);
  if (process.platform === 'darwin') spawnSync('chmod', ['-a', 'everyone deny delete', homeLike]);
});

test('setting the wall clock back does not stretch the wait for a held ledger lock', async () => {
  const dir = folder();
  fs.chmodSync(dir, 0o700);
  const name = '0'.repeat(64) + '.payment.send';
  fs.writeFileSync(path.join(dir, name + '.json.lock'), JSON.stringify({ pid: process.pid, started: 1, host: os.hostname(), nonce: 'ab'.repeat(16) }) + '\n', { mode: 0o600 });
  const real = Date.now;
  let calls = 0;
  let timer;
  const cap = new Promise((resolve) => { timer = setTimeout(() => resolve('still waiting'), Ledger.LOCK_WAIT_MS + 15000); });
  Date.now = () => {
    calls += 1;
    return calls > 1 ? real() - 3600000 : real();
  };
  let out;
  try {
    out = await Promise.race([qm.fileLedger(dir).recover(name).then(() => 'recovered', (e) => e), cap]);
  } finally {
    Date.now = real;
    clearTimeout(timer);
  }
  assert.notStrictEqual(out, 'still waiting');
  assert.ok(out instanceof Error && out.code === 'QMANDATE_LEDGER' && /stayed locked/.test(out.message), String(out && out.message));
});
