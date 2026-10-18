// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawn, spawnSync } = require('child_process');
const qm = require('..');
const F = require('../lib/format');
const Ledger = require('../lib/ledger');
const { makeChain, client } = require('./chain');

const ROOT = path.join(__dirname, '..');
const NET = require(require.resolve('@quantovainc/qstamp', { paths: [ROOT] })).NETWORKS.testnet;
const dirs = [];

test.after(() => {
  for (const d of dirs) fs.rmSync(d, { recursive: true, force: true });
});

function folder() {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'qmandate-journal-'));
  dirs.push(d);
  return d;
}

function setup(maxTotal) {
  const chain = makeChain(ROOT);
  const ep = { trustCustomEndpoints: true, clients: [client(chain, 'a'), client(chain, 'b')] };
  const principal = qm.generateKey();
  const agent = qm.generateKey();
  const mandate = qm.grant({
    key: principal,
    agent: qm.describeKey(agent),
    scopes: [{ action: 'payment.send', currency: 'USD', maxPerAction: '100', maxTotal: maxTotal || '1000' }],
    validFrom: new Date(Date.now() - 60000).toISOString(),
    validUntil: new Date(Date.now() + 86400000).toISOString(),
  });
  return { chain, ep, principal, agent, mandate, dir: folder() };
}

function pay(s, amount, ledger) {
  return qm.act(Object.assign({ key: s.agent, mandate: s.mandate, ledger: ledger || s.dir, action: 'payment.send', currency: 'USD', amount }, s.ep));
}

const refOf = (e) => F.refOf(F.parse(e));
const leftovers = (dir) => fs.readdirSync(dir).filter((f) => !f.endsWith('.json') && !f.endsWith('.journal'));
const stateFile = (s) => path.join(s.dir, Ledger.nameOf(qm.mandateRef(s.mandate), 'payment.send') + '.json');

function backdate(file, seconds) {
  const t = new Date(Date.now() - seconds * 1000);
  fs.utimesSync(file, t, t);
}

function deadPid() {
  return spawnSync(process.execPath, ['-e', '']).pid;
}

function lockFor(pid, host) {
  return JSON.stringify({ pid, started: Date.now() - 5000, host: host || os.hostname(), nonce: crypto.randomBytes(16).toString('hex') }) + '\n';
}

const FAKE = `
const now = () => Math.floor(Date.now() / 1000);
const fake = (name) => ({
  base: 'https://' + name + '.example',
  async nodeInfo() { return { chain_id: ${JSON.stringify(NET.chainId)}, genesis_hash: ${JSON.stringify(NET.genesis)}, head_height: 10 }; },
  async block(h) { return { block: 'x', height: h, time: now() }; },
  async transaction() { return null; },
});
const endpoints = { trustCustomEndpoints: true, clients: [fake('a'), fake('b')] };
`;

function writeMandate(s) {
  const mfile = path.join(folder(), 'mandate.json');
  fs.writeFileSync(mfile, JSON.stringify(s.mandate));
  return mfile;
}

function run(script, args) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['-e', script, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    let err = '';
    child.stdout.on('data', (d) => { out += d; });
    child.stderr.on('data', (d) => { err += d; });
    child.on('error', reject);
    child.on('close', (code, signal) => resolve({ code, signal, out, err, pid: child.pid }));
  });
}

test('an action committed to the ledger but lost by its caller is recovered from the journal and the next action verifies', async () => {
  const s = setup();
  const a1 = await pay(s, '10');
  const a2 = await pay(s, '20');
  const a3 = await pay(s, '30');
  const opts = Object.assign({ type: 'action', mandate: s.mandate, principalKeyId: qm.keyId(s.principal), revocations: [], requireAnchor: false }, s.ep);
  const gap = await qm.verify(a3, Object.assign({ priorActions: [a1] }, opts));
  assert.strictEqual(gap.status, 'indeterminate');
  const rec = await qm.ledgerActions(s.dir, s.mandate, 'payment.send');
  assert.strictEqual(rec.complete, true);
  assert.strictEqual(rec.sequence, '3');
  assert.strictEqual(rec.total, '60');
  assert.deepStrictEqual(rec.actions.map(refOf), [a1, a2, a3].map(refOf));
  const r = await qm.verify(a3, Object.assign({ priorActions: rec.actions.slice(0, 2) }, opts));
  assert.strictEqual(r.status, 'valid', JSON.stringify(r.checks.filter((c) => !c.ok)));
  assert.strictEqual(r.totalProven, true);
  for (const f of fs.readdirSync(s.dir).filter((n) => n.endsWith('.journal'))) assert.strictEqual(fs.statSync(path.join(s.dir, f)).mode & 0o777, 0o600);
  assert.deepStrictEqual(leftovers(s.dir), []);
});

test('a crash between the journal write and the ledger swap leaves a recoverable action', async () => {
  const s = setup();
  const a1 = await pay(s, '10');
  const mfile = writeMandate(s);
  const script = FAKE + `
const fs = require('fs');
const qm = require(process.argv[1]);
const mandate = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const key = Uint8Array.from(Buffer.from(process.argv[3], 'hex'));
const rename = fs.renameSync;
fs.renameSync = function (from, to) {
  if (String(to).endsWith('.json') && fs.readdirSync(require('path').dirname(String(to))).some((f) => f.endsWith('.pending'))) process.kill(process.pid, 'SIGKILL');
  return rename.apply(this, arguments);
};
qm.act(Object.assign({ key, mandate, ledger: process.argv[4], action: 'payment.send', currency: 'USD', amount: '25' }, endpoints)).then(() => process.stdout.write('not killed'));
`;
  const res = await run(script, [ROOT, mfile, Buffer.from(s.agent).toString('hex'), s.dir]);
  assert.strictEqual(res.signal, 'SIGKILL', res.out + res.err);
  assert.strictEqual(JSON.parse(fs.readFileSync(stateFile(s), 'utf8')).sequence, '1');
  const lock = stateFile(s) + '.lock';
  assert.ok(fs.existsSync(lock));
  assert.ok(fs.readdirSync(s.dir).some((f) => f.endsWith('.pending')));
  backdate(lock, 60);
  const rec = await qm.ledgerActions(s.dir, s.mandate, 'payment.send');
  assert.strictEqual(rec.complete, true);
  assert.strictEqual(rec.sequence, '2');
  assert.strictEqual(rec.total, '35');
  assert.strictEqual(refOf(rec.actions[0]), refOf(a1));
  assert.strictEqual(rec.actions[1].statement.amount, '25');
  assert.strictEqual(rec.actions[1].statement.previousRef, refOf(a1));
  assert.deepStrictEqual(leftovers(s.dir), []);
  const a3 = await pay(s, '5');
  assert.strictEqual(a3.statement.sequence, '3');
  assert.strictEqual(a3.statement.previousRef, refOf(rec.actions[1]));
  assert.strictEqual(a3.statement.total, '40');
});

test('a crash after the journal write is rolled forward by the next action', async () => {
  const s = setup('100');
  await pay(s, '10');
  const mfile = writeMandate(s);
  const script = FAKE + `
const fs = require('fs');
const qm = require(process.argv[1]);
const mandate = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const key = Uint8Array.from(Buffer.from(process.argv[3], 'hex'));
const rename = fs.renameSync;
fs.renameSync = function (from, to) {
  if (String(to).endsWith('.json') && fs.readdirSync(require('path').dirname(String(to))).some((f) => f.endsWith('.pending'))) process.kill(process.pid, 'SIGKILL');
  return rename.apply(this, arguments);
};
qm.act(Object.assign({ key, mandate, ledger: process.argv[4], action: 'payment.send', currency: 'USD', amount: '80' }, endpoints));
`;
  const res = await run(script, [ROOT, mfile, Buffer.from(s.agent).toString('hex'), s.dir]);
  assert.strictEqual(res.signal, 'SIGKILL');
  backdate(stateFile(s) + '.lock', 60);
  await assert.rejects(pay(s, '20'), (e) => e.code === 'QMANDATE_NOT_AUTHORISED' && e.spent === '90');
  const a = await pay(s, '10');
  assert.strictEqual(a.statement.sequence, '3');
  assert.strictEqual(a.statement.total, '100');
});

test('a stale lock is broken only when its owner on this host has died', async () => {
  const dir = folder();
  const lock = path.join(dir, 'x.json.lock');
  const place = (text, age) => {
    fs.writeFileSync(lock, text, { mode: 0o600 });
    if (age) backdate(lock, age);
  };
  place(lockFor(deadPid()), 60);
  assert.strictEqual(Ledger.breakStale(lock), true);
  assert.strictEqual(fs.existsSync(lock), false);
  const sleeper = spawn(process.execPath, ['-e', 'setTimeout(() => {}, 60000)'], { stdio: 'ignore' });
  try {
    place(lockFor(sleeper.pid), 600);
    assert.strictEqual(Ledger.breakStale(lock), false);
    assert.strictEqual(fs.existsSync(lock), true);
  } finally {
    sleeper.kill('SIGKILL');
  }
  place(lockFor(process.pid), 600);
  assert.strictEqual(Ledger.breakStale(lock), false);
  place(lockFor(deadPid()), 5);
  assert.strictEqual(Ledger.breakStale(lock), false);
  place(lockFor(deadPid(), 'another-host.example'), 600);
  assert.strictEqual(Ledger.breakStale(lock), false);
  place(String(deadPid()) + '\n', 600);
  assert.strictEqual(Ledger.breakStale(lock), false);
  place('', 600);
  assert.strictEqual(Ledger.breakStale(lock), false);
  assert.strictEqual(fs.existsSync(lock), true);
});

test('act breaks a stale lock left by a dead agent process and signs at once', async () => {
  const s = setup();
  const lock = stateFile(s) + '.lock';
  fs.writeFileSync(lock, lockFor(deadPid()), { mode: 0o600 });
  backdate(lock, 60);
  fs.writeFileSync(path.join(s.dir, '.' + path.basename(stateFile(s)) + '.0123456789ab.tmp'), 'left by an older version');
  fs.writeFileSync(path.join(s.dir, '.' + path.basename(stateFile(s)) + '.tmp'), 'left by a killed writer');
  const started = Date.now();
  const a = await pay(s, '20');
  assert.ok(Date.now() - started < 5000);
  assert.strictEqual(a.statement.sequence, '1');
  assert.deepStrictEqual(leftovers(s.dir), []);
});

test('a journal entry that does not match the ledger stops recovery', async () => {
  const s = setup();
  await pay(s, '10');
  await pay(s, '20');
  const journal = fs.readdirSync(s.dir).filter((f) => f.endsWith('.journal')).map((f) => path.join(s.dir, f));
  assert.strictEqual(journal.length, 2);
  const other = setup();
  await pay(other, '10');
  const foreign = fs.readdirSync(other.dir).find((f) => f.endsWith('.journal'));
  const target = journal.find((f) => fs.readFileSync(f, 'utf8').includes('"sequence":"1"'));
  fs.writeFileSync(target, fs.readFileSync(path.join(other.dir, foreign), 'utf8'));
  await assert.rejects(qm.ledgerActions(s.dir, s.mandate, 'payment.send'), (e) => e.code === 'QMANDATE_LEDGER' && /journal/.test(e.message));
});

test('a store of your own receives each signed action in journal before the swap', async () => {
  const s = setup();
  const state = new Map();
  const journal = new Map();
  const calls = [];
  const store = {
    async read(name) {
      return state.get(name) || null;
    },
    async compareAndSwap(name, expected, next) {
      calls.push('swap');
      if ((state.get(name) || null) !== expected) return false;
      state.set(name, next);
      return true;
    },
    async journal(name, text) {
      calls.push('journal');
      journal.set(name, text);
    },
    async readJournal(name) {
      return journal.get(name) || null;
    },
  };
  const a1 = await pay(s, '10', store);
  const a2 = await pay(s, '20', store);
  assert.deepStrictEqual(calls, ['journal', 'swap', 'journal', 'swap']);
  const rec = await qm.ledgerActions(store, s.mandate, 'payment.send');
  assert.strictEqual(rec.complete, true);
  assert.deepStrictEqual(rec.actions.map(refOf), [a1, a2].map(refOf));
  const plain = { read: store.read, compareAndSwap: store.compareAndSwap };
  await assert.rejects(qm.ledgerActions(plain, s.mandate, 'payment.send'), /keeps no journal/);
});

const WORKER = FAKE + `
const fs = require('fs');
const qm = require(process.argv[1]);
const mandate = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const key = Uint8Array.from(Buffer.from(process.argv[3], 'hex'));
const out = fs.openSync(process.argv[5], 'a');
const one = async () => {
  for (;;) {
    const amount = String(1 + Math.floor(Math.random() * 100));
    try {
      const env = await qm.act(Object.assign({ key, mandate, ledger: process.argv[4], action: 'payment.send', currency: 'USD', amount }, endpoints));
      fs.writeSync(out, JSON.stringify(env) + '\\n');
    } catch (e) {
      if (e.code !== 'QMANDATE_LEDGER') throw e;
    }
  }
};
for (let i = 0; i < 4; i += 1) one();
`;

test('kill -9 of agent processes never loses or duplicates a signed action', async () => {
  const s = setup('100000000');
  const mfile = writeMandate(s);
  const agentHex = Buffer.from(s.agent).toString('hex');
  const outs = folder();
  const state = stateFile(s);
  const lock = state + '.lock';
  const sequence = () => (fs.existsSync(state) ? Number(JSON.parse(fs.readFileSync(state, 'utf8')).sequence) : 0);
  const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
  const ageDeadLock = () => {
    let holder;
    try {
      holder = JSON.parse(fs.readFileSync(lock, 'utf8'));
    } catch (e) {
      return;
    }
    try {
      process.kill(holder.pid, 0);
    } catch (e) {
      if (e.code === 'ESRCH') backdate(lock, 60);
    }
  };
  const target = Number(process.env.QMANDATE_KILL_ACTIONS || 300);
  let round = 0;
  let kills = 0;
  while (sequence() < target && round < 60) {
    round += 1;
    const procs = [0, 1, 2, 3].map((i) => {
      const child = spawn(process.execPath, ['-e', WORKER, ROOT, mfile, agentHex, s.dir, path.join(outs, 'r' + round + 'w' + i + '.jsonl')], { stdio: 'ignore' });
      return { child, done: new Promise((resolve) => child.on('exit', resolve)) };
    });
    await pause(300 + Math.floor(Math.random() * 600));
    const victim = procs[Math.floor(Math.random() * procs.length)];
    victim.child.kill('SIGKILL');
    await victim.done;
    kills += 1;
    ageDeadLock();
    await pause(400 + Math.floor(Math.random() * 400));
    for (const p of procs) p.child.kill('SIGKILL');
    await Promise.all(procs.map((p) => p.done));
    kills += procs.length - 1;
    ageDeadLock();
  }
  const rec = await qm.ledgerActions(s.dir, s.mandate, 'payment.send');
  const delivered = [];
  for (const f of fs.readdirSync(outs)) {
    for (const line of fs.readFileSync(path.join(outs, f), 'utf8').split('\n')) {
      if (line.trim()) delivered.push(JSON.parse(line));
    }
  }
  const recovered = new Set(rec.actions.map(refOf));
  const lost = delivered.filter((e) => !recovered.has(refOf(e)));
  assert.ok(Number(rec.sequence) > 0, 'no action was signed in ' + round + ' rounds');
  assert.ok(kills > 0);
  assert.strictEqual(rec.complete, true);
  assert.strictEqual(rec.actions.length, Number(rec.sequence));
  assert.strictEqual(lost.length, 0);
  assert.strictEqual(new Set(rec.actions.map((e) => e.statement.sequence)).size, rec.actions.length);
  let total = 0n;
  rec.actions.forEach((e, i) => {
    total += BigInt(e.statement.amount);
    assert.strictEqual(e.statement.sequence, String(i + 1));
    assert.strictEqual(e.statement.total, total.toString());
    if (i > 0) assert.strictEqual(e.statement.previousRef, refOf(rec.actions[i - 1]));
  });
  assert.strictEqual(rec.total, total.toString());
  assert.deepStrictEqual(leftovers(s.dir), []);
});
