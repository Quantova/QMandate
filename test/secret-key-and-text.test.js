// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const util = require('util');
const q = require('..');

test('a generated key never shows its bytes when printed or serialised', () => {
  const key = q.generateKey();
  const hex = Buffer.from(key).toString('hex');
  const listed = Array.from(key).join(',');
  const shown = [util.inspect(key), util.inspect({ key }), JSON.stringify({ key }), String(key), `${key}`, util.format('%o', key), util.format('%j', { key }), key.toLocaleString()];
  for (const s of shown) {
    assert.ok(!s.includes(hex), s);
    assert.ok(!s.replace(/\s/g, '').includes(listed.slice(0, 24)), s);
  }
  assert.ok(key instanceof Uint8Array);
  assert.strictEqual(key.length, 32);
  assert.strictEqual(Object.prototype.toString.call(key.slice(0, 4)), '[object Uint8Array]');
  assert.strictEqual(q.keyId(key), q.keyId(Uint8Array.from(key)));
});

test('text with an unassigned code point or a noncharacter is refused', () => {
  const F = require('../lib/format');
  for (const t of ['a\u0378b', 'a\ufffeb', 'a\u{10ffff}b']) assert.ok(F.textProblem(t, 64, 'text'), JSON.stringify(t));
  assert.strictEqual(F.textProblem('plain text', 64, 'text'), null);
});

test('a signing key of too few different byte values or in shared memory is refused', async () => {
  const sign = (key) => q.grant({ key, agent: q.describeKey(q.generateKey()), scopes: [{ action: 'payment.send', currency: 'USD', maxPerAction: '5', maxTotal: '10' }], validFrom: new Date(Date.now() - 60000).toISOString(), validUntil: new Date(Date.now() + 86400000).toISOString() });
  const shared = new Uint8Array(new SharedArrayBuffer(32));
  shared.set(q.generateKey());
  await assert.rejects(Promise.resolve().then(() => sign(new Uint8Array(32))));
  await assert.rejects(Promise.resolve().then(() => sign(new Uint8Array(32).fill(7))), /too few different byte values/);
  await assert.rejects(Promise.resolve().then(() => sign(shared)));
  await Promise.resolve().then(() => sign(q.generateKey()));
});

test('a misspelled or unknown verify option is refused so a check is never skipped silently', async () => {
  await assert.rejects(q.verify({}, { type: 'mandate', expectedSendr: 'Q1' }), /is not an option of verify/);
});

test('a misspelled or unknown option of a signing call is refused and nothing is signed', async () => {
  await assert.rejects(Promise.resolve().then(() => q.grant({ key: q.generateKey(), agent: q.describeKey(q.generateKey()), scopes: [{ action: 'payment.send', currency: 'USD', maxPerAction: '5', maxTotal: '10' }], counterparies: ['x'], validFrom: new Date(Date.now() - 60000).toISOString(), validUntil: new Date(Date.now() + 86400000).toISOString() })), /is not (an option of|used by)/);
  await assert.rejects(Promise.resolve().then(() => q.anchor([], { seed: new Uint8Array(32).fill(5), index: 0, untl: '2030-01-01T00:00:00.000Z' })));
});

test('the folder ledger refuses to run on Windows where folder owners and modes cannot be checked', () => {
  const was = Object.getOwnPropertyDescriptor(process, 'platform');
  Object.defineProperty(process, 'platform', { value: 'win32', configurable: true });
  try {
    assert.throws(() => q.fileLedger(require('os').tmpdir()), /Windows/);
  } finally {
    Object.defineProperty(process, 'platform', was);
  }
});

test('the working copies of the signing key and randomness are wiped after native signing', () => {
  const w = require('../wasm/qmandate_native.js');
  const native = require('../lib/native.js');
  const seen = [];
  const real = { sign: w.sign, publicKey: w.publicKey };
  w.sign = (...a) => { seen.push(...a); return real.sign(...a); };
  w.publicKey = (...a) => { seen.push(...a); return real.publicKey(...a); };
  try {
    const seed = Uint8Array.from({ length: 32 }, (_, i) => (i * 7 + 3) & 255);
    const rnd = Uint8Array.from({ length: 32 }, (_, i) => (i * 11 + 5) & 255);
    native.publicKey(seed);
    native.sign(seed, Buffer.from('m'), rnd);
    const has = (a, n) => Buffer.from(a.buffer, a.byteOffset, a.byteLength).indexOf(Buffer.from(n)) !== -1;
    assert.strictEqual(seen.filter((a) => has(a, seed) || has(a, rnd)).length, 0);
    assert.strictEqual(seed[1], 10);
    assert.strictEqual(rnd[1], 16);
  } finally {
    Object.assign(w, real);
  }
});

test('a ledger refusal never repeats control or direction characters from the folder path', { skip: process.platform === 'win32' }, async () => {
  const fs = require('fs');
  const os = require('os');
  const path = require('path');
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'ledger-'));
  try {
    const dir = path.join(base, 'led\u001b[31mger\u202e\u0007');
    fs.mkdirSync(dir);
    fs.chmodSync(dir, 0o777);
    const make = q.folderLedger || q.fileLedger;
    const msgs = [];
    const hex = 'a'.repeat(64);
    for (const name of ['x' + '.' + hex, hex + '.payment.send', hex + '.x']) {
      try {
        await make(dir).read(name);
      } catch (e) {
        msgs.push(e.message);
      }
    }
    assert.ok(msgs.some((m) => /can be written by every user/.test(m)));
    for (const m of msgs) assert.doesNotMatch(m, /[\u0000-\u001f\u007f-\u009f\u202a-\u202e]/u);
  } finally {
    fs.rmSync(base, { recursive: true, force: true });
  }
});

test('a ledger under a folder another group can change, or whose folder was replaced, is refused', { skip: process.platform === 'win32' }, async () => {
  const fs = require('fs');
  const os = require('os');
  const path = require('path');
  const make = q.folderLedger || q.fileLedger;
  const name = 'a'.repeat(64) + '.payment.send';
  const a = fs.mkdtempSync(path.join(os.tmpdir(), 'ledger-'));
  const b = fs.mkdtempSync(path.join(os.tmpdir(), 'ledger-'));
  try {
    fs.chmodSync(a, 0o770);
    const la = path.join(a, 'ledger');
    fs.mkdirSync(la, { mode: 0o700 });
    await assert.rejects(Promise.resolve().then(() => make(la).read(name)), /above the ledger can be changed by another user/);
    fs.chmodSync(la, 0o770);
    await Promise.resolve().then(() => make(la).read(name));
    const lb = path.join(b, 'ledger');
    fs.mkdirSync(lb, { mode: 0o700 });
    const l = make(lb);
    await Promise.resolve().then(() => l.read(name));
    fs.renameSync(lb, lb + '.old');
    fs.mkdirSync(lb, { mode: 0o700 });
    await assert.rejects(Promise.resolve().then(() => l.read(name)), /moved or replaced/);
  } finally {
    fs.rmSync(a, { recursive: true, force: true });
    fs.rmSync(b, { recursive: true, force: true });
  }
});

test('the envelope, mandate and chain time error codes are produced', async () => {
  const fs = require('fs');
  const os = require('os');
  const path = require('path');
  const iso = (ms) => new Date(ms).toISOString();
  const now = Date.now();
  assert.throws(() => q.mandateRef({}), (e) => e.code === 'QMANDATE_INVALID_ENVELOPE');
  const agent = q.generateKey();
  const mandate = q.grant({ key: q.generateKey(), agent: q.describeKey(agent), scopes: [{ action: 'payment.send', currency: 'USD', maxPerAction: '5', maxTotal: '10' }], validFrom: iso(now - 60000), validUntil: iso(now + 864e5) });
  const forged = JSON.parse(JSON.stringify(mandate));
  forged.statement.note = 'changed';
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'codes-'));
  try {
    const down = (base) => ({ base, nodeInfo: async () => { throw new Error('endpoint down'); }, block: async () => { throw new Error('endpoint down'); } });
    const action = { key: agent, action: 'payment.send', currency: 'USD', amount: '1', counterparty: 'x', details: Buffer.from('d'), ledger: q.fileLedger(dir), trustCustomEndpoints: true, clients: [down('https://a.example'), down('https://b.example')] };
    await assert.rejects(Promise.resolve().then(() => q.act(Object.assign({ mandate: forged }, action))), (e) => e.code === 'QMANDATE_INVALID_MANDATE');
    await assert.rejects(Promise.resolve().then(() => q.act(Object.assign({ mandate }, action))), (e) => e.code === 'QMANDATE_NO_CHAIN_TIME');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('a signing key, salt or secret made of too few different byte values is refused', () => {
  const pattern = (n) => Uint8Array.from({ length: 32 }, (_, i) => 1 + (i % n));
  const weak = [Uint8Array.from(Buffer.from('secretsecretsecretsecretsecretse')), pattern(2), pattern(12)];
  for (const k of weak) assert.throws(() => q.publicKey(k), /too few different byte values/);
  assert.ok(q.publicKey(pattern(13)).length > 0);
  for (let i = 0; i < 200; i += 1) assert.ok(q.publicKey(q.generateKey()).length > 0);
});
