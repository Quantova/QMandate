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
const native = require('../lib/native');
const { makeChain, client } = require('./chain');
const { PAYEE, bound } = require('./bind');

const ROOT = path.join(__dirname, '..');
const NET = require('@quantovainc/qstamp').NETWORKS.testnet;
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
  return qm.act(Object.assign({ key: s.agent, mandate: s.mandate, ledger: ledger || s.dir, action: 'payment.send', currency: 'USD', amount, counterparty: PAYEE }, s.ep));
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
  const r = await qm.verify(a3, Object.assign({ priorActions: rec.actions.slice(0, 2) }, bound(a3), opts));
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

test('a store of your own receives each signed action only with the swap that commits it', async () => {
  const s = setup();
  const state = new Map();
  const journal = new Map();
  const calls = [];
  const store = {
    async read(name) {
      return state.get(name) || null;
    },
    async compareAndSwap(name, expected, next, entry) {
      calls.push('swap');
      if ((state.get(name) || null) !== expected) return false;
      state.set(name, next);
      journal.set(entry.name, entry.text);
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
  assert.deepStrictEqual(calls, ['swap', 'swap']);
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

function foreignAction(s, signer, prev, amount) {
  const m = F.parse(s.mandate);
  const p = prev ? F.parse(prev) : null;
  const st = {
    mandateId: m.statement.mandateId,
    mandateRef: F.refOf(m),
    actionId: crypto.randomBytes(16).toString('hex'),
    agentKeyId: qm.keyId(signer),
    action: 'payment.send',
    currency: 'USD',
    amount,
    counterparty: 'Mallory',
    detailsDigest: F.sha3(Buffer.alloc(0)).toString('hex'),
    actedAt: new Date().toISOString(),
    sequence: p ? String(Number(p.statement.sequence) + 1) : '1',
    previousRef: p ? F.refOf(p) : '',
    total: String((p ? Number(p.statement.total) : 0) + Number(amount)),
    ledgerId: p && p.statement.ledgerId ? p.statement.ledgerId : crypto.randomBytes(16).toString('hex'),
    note: '',
  };
  const pk = qm.publicKey(signer);
  const sig = native.sign(signer, F.payload('action', st, F.ACTION_VERSION), Uint8Array.from(crypto.randomBytes(32)));
  return { format: F.ACTION_FORMAT, type: 'action', algorithm: F.ALGORITHM, signer: { id: qm.keyId(signer), publicKey: Buffer.from(pk).toString('base64') }, statement: st, signature: Buffer.from(sig).toString('base64') };
}

test('the ledger records the agent of its mandate and refuses an unfinished action signed by another key', async () => {
  const s = setup();
  const a1 = await pay(s, '10');
  const state = JSON.parse(fs.readFileSync(stateFile(s), 'utf8'));
  assert.strictEqual(state.format, 'qmandate-ledger/3');
  assert.strictEqual(state.agentKeyId, qm.keyId(s.agent));
  const pending = stateFile(s).replace(/\.json$/, '.pending');
  fs.writeFileSync(pending, JSON.stringify(foreignAction(s, qm.generateKey(), a1, '5')) + '\n', { mode: 0o600 });
  await assert.rejects(pay(s, '10'), (e) => e.code === 'QMANDATE_LEDGER' && /journal/.test(e.message));
  await assert.rejects(qm.ledgerActions(s.dir, s.mandate, 'payment.send'), (e) => e.code === 'QMANDATE_LEDGER');
  assert.strictEqual(fs.readFileSync(stateFile(s), 'utf8'), Ledger.encodeState(state));
  fs.rmSync(pending);
  const a2 = await pay(s, '10');
  assert.strictEqual(a2.statement.sequence, '2');
  assert.strictEqual(a2.statement.previousRef, refOf(a1));
});

test('an unfinished first action signed by another key is refused before any state exists', async () => {
  const s = setup();
  const name = Ledger.nameOf(qm.mandateRef(s.mandate), 'payment.send');
  fs.writeFileSync(path.join(s.dir, name + '.pending'), JSON.stringify(foreignAction(s, qm.generateKey(), null, '5')) + '\n', { mode: 0o600 });
  await assert.rejects(pay(s, '10'), (e) => e.code === 'QMANDATE_LEDGER');
  await assert.rejects(qm.ledgerActions(s.dir, s.mandate, 'payment.send'), (e) => e.code === 'QMANDATE_LEDGER');
  await assert.rejects(qm.fileLedger(s.dir).recover(name), (e) => e.code === 'QMANDATE_LEDGER');
  assert.strictEqual(fs.existsSync(stateFile(s)), false);
});

test('a ledger written in the first format is read and upgraded, and a state naming another agent stops signing', async () => {
  const s = setup();
  const a1 = await pay(s, '10');
  const v2 = JSON.parse(fs.readFileSync(stateFile(s), 'utf8'));
  const v1 = Ledger.encodeState({ mandateRef: v2.mandateRef, action: v2.action, sequence: v2.sequence, total: v2.total, lastRef: v2.lastRef });
  assert.match(v1, /qmandate-ledger\/1/);
  fs.writeFileSync(stateFile(s), v1);
  const pending = stateFile(s).replace(/\.json$/, '.pending');
  fs.writeFileSync(pending, JSON.stringify(foreignAction(s, qm.generateKey(), a1, '5')) + '\n', { mode: 0o600 });
  await assert.rejects(pay(s, '10'), (e) => e.code === 'QMANDATE_LEDGER');
  assert.strictEqual(fs.readFileSync(stateFile(s), 'utf8'), v1);
  fs.rmSync(pending);
  const a2 = await pay(s, '10');
  assert.strictEqual(a2.statement.total, '20');
  const up = JSON.parse(fs.readFileSync(stateFile(s), 'utf8'));
  assert.strictEqual(up.format, 'qmandate-ledger/3');
  assert.strictEqual(a2.statement.ledgerId, a1.statement.ledgerId);
  assert.strictEqual(up.agentKeyId, qm.keyId(s.agent));
  fs.writeFileSync(stateFile(s), Ledger.encodeState(Object.assign({}, up, { agentKeyId: qm.keyId(qm.generateKey()) })));
  await assert.rejects(pay(s, '10'), (e) => e.code === 'QMANDATE_LEDGER');
});

function keyOf(file) {
  const st = fs.statSync(file);
  const text = fs.readFileSync(file, 'utf8');
  return crypto.createHash('sha256').update(st.dev + ' ' + st.ino + ' ' + st.mtimeMs + ' ' + text).digest('hex').slice(0, 32);
}

test('a claim to break a stale lock left by a dead process is itself broken once it is stale', async () => {
  const dir = folder();
  const lock = path.join(dir, 'x.json.lock');
  const reset = () => {
    for (const f of fs.readdirSync(dir)) fs.rmSync(path.join(dir, f), { force: true });
    fs.writeFileSync(lock, lockFor(deadPid()), { mode: 0o600 });
    backdate(lock, 60);
    return lock + '.' + keyOf(lock) + '.break';
  };
  let claim = reset();
  fs.writeFileSync(claim, lockFor(deadPid()), { mode: 0o600 });
  backdate(claim, 60);
  assert.strictEqual(Ledger.breakStale(lock), true);
  assert.deepStrictEqual(fs.readdirSync(dir), []);

  claim = reset();
  fs.writeFileSync(claim, lockFor(deadPid()), { mode: 0o600 });
  backdate(claim, 5);
  assert.strictEqual(Ledger.breakStale(lock), false);
  assert.ok(fs.existsSync(lock));

  claim = reset();
  const sleeper = spawn(process.execPath, ['-e', 'setTimeout(() => {}, 60000)'], { stdio: 'ignore' });
  try {
    fs.writeFileSync(claim, lockFor(sleeper.pid), { mode: 0o600 });
    backdate(claim, 600);
    assert.strictEqual(Ledger.breakStale(lock), false);
    assert.ok(fs.existsSync(lock));
  } finally {
    sleeper.kill('SIGKILL');
  }

  claim = reset();
  fs.writeFileSync(claim, '', { mode: 0o600 });
  backdate(claim, 600);
  assert.strictEqual(Ledger.breakStale(lock), false);
  assert.ok(fs.existsSync(lock));

  claim = reset();
  fs.writeFileSync(claim, lockFor(deadPid(), 'another-host.example'), { mode: 0o600 });
  backdate(claim, 600);
  assert.strictEqual(Ledger.breakStale(lock), false);
  assert.ok(fs.existsSync(lock));
});

test('act recovers by itself after a process died while breaking a stale lock', async () => {
  const s = setup();
  const lock = stateFile(s) + '.lock';
  fs.writeFileSync(lock, lockFor(deadPid()), { mode: 0o600 });
  backdate(lock, 60);
  const claim = lock + '.' + keyOf(lock) + '.break';
  fs.writeFileSync(claim, lockFor(deadPid()), { mode: 0o600 });
  backdate(claim, 60);
  const started = Date.now();
  const a = await pay(s, '20');
  assert.ok(Date.now() - started < 5000);
  assert.strictEqual(a.statement.sequence, '1');
  assert.deepStrictEqual(leftovers(s.dir), []);
});

test('a lock whose process number now belongs to another process is broken where the start time of a process is known', async (t) => {
  const sleeper = spawn(process.execPath, ['-e', 'setTimeout(() => {}, 60000)'], { stdio: 'ignore' });
  t.after(() => sleeper.kill('SIGKILL'));
  await new Promise((resolve) => setTimeout(resolve, 200));
  const start = Ledger.startOf(sleeper.pid);
  if (start === null) {
    t.diagnostic('this platform does not report when a process started, a reused process number keeps its lock');
    return;
  }
  assert.strictEqual(Ledger.startOf(sleeper.pid), start);
  const dir = folder();
  const lock = path.join(dir, 'x.json.lock');
  const place = (holderStart, age) => {
    const h = JSON.parse(lockFor(sleeper.pid));
    if (holderStart !== undefined) h.start = holderStart;
    fs.writeFileSync(lock, JSON.stringify(h) + '\n', { mode: 0o600 });
    backdate(lock, age);
  };
  place(start, 600);
  assert.strictEqual(Ledger.breakStale(lock), false);
  place(undefined, 600);
  assert.strictEqual(Ledger.breakStale(lock), false);
  place(start.replace(/[0-9]$/, (d) => String((Number(d) + 1) % 10)), 5);
  assert.strictEqual(Ledger.breakStale(lock), false);
  place(start.replace(/[0-9]$/, (d) => String((Number(d) + 1) % 10)), 600);
  assert.strictEqual(Ledger.breakStale(lock), true);
  assert.strictEqual(fs.existsSync(lock), false);
});

test('a lock always records its holder, so a crash while locking never leaves a lock nobody can break', async () => {
  const s = setup();
  await pay(s, '1');
  const lock = stateFile(s) + '.lock';
  const real = fs.writeSync;
  const seen = [];
  fs.writeSync = function (fd, data, ...rest) {
    for (const f of fs.readdirSync(s.dir)) if (f.endsWith('.lock')) seen.push(fs.readFileSync(path.join(s.dir, f), 'utf8'));
    return real.call(fs, fd, data, ...rest);
  };
  try {
    await pay(s, '1');
  } finally {
    fs.writeSync = real;
  }
  assert.ok(seen.length > 0);
  for (const text of seen) assert.strictEqual(JSON.parse(text).pid, process.pid);
  assert.strictEqual(fs.existsSync(lock), false);
  fs.writeFileSync(path.join(s.dir, '.' + path.basename(lock) + '.' + crypto.randomBytes(16).toString('hex') + '.tmp'), '');
  const script = "const fs = require('fs'); require(process.argv[1]).ledgerActions(process.argv[2], JSON.parse(fs.readFileSync(process.argv[3], 'utf8')), 'payment.send').then((r) => process.stdout.write(r.sequence));";
  const res = await run(script, [ROOT, s.dir, writeMandate(s)]);
  assert.strictEqual(res.out, '2', res.err);
  assert.deepStrictEqual(leftovers(s.dir), []);
});
