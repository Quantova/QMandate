// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const fs = require('fs');
const path = require('path');
const test = require('node:test');
const assert = require('node:assert');
const { cliCampaign, runCli, tempDir, SAYS_VALID } = require('./fuzz');
const { honest } = require('./honest');
const { PAYEE_KEY } = require('./bind');
const F = require('../lib/format');
const Ledger = require('../lib/ledger');

const BIN = path.join(__dirname, '..', 'bin', 'qmandate.js');
const ENVELOPE_MAX = 1024 * 1024;

let world;
async function setup() {
  if (world) return world;
  const w = await honest();
  const dir = tempDir('qmandate-cli-consume');
  const files = {};
  const texts = { mandate: w.plain.mandate, prior: w.plainPrior, action: w.plain.action };
  for (const [name, value] of Object.entries(texts)) {
    texts[name] = JSON.stringify(value);
    files[name] = path.join(dir, name + '.json');
    fs.writeFileSync(files[name], texts[name]);
  }
  files.details = path.join(dir, 'order.txt');
  fs.writeFileSync(files.details, 'order 200');
  const verify = (executed) => ['verify', files.action, '--type', 'action', '--mandate', files.mandate, '--prior', files.prior,
    '--principal-key-id', w.qm.keyId(w.principal), '--no-revocations', '--allow-unanchored', '--at', w.at,
    '--details-file', files.details, '--counterparty-key-id', PAYEE_KEY].concat(executed === undefined ? [] : ['--executed-dir', executed]);
  const ref = F.refOf(F.parse(w.plain.action));
  const record = (folder) => path.join(folder, Ledger.executedName(w.qm.mandateRef(w.plain.mandate), 'payment.send', ref));
  world = { w, dir, files, texts, verify, ref, record };
  return world;
}

test.after(() => {
  if (!world) return;
  fs.rmSync(world.dir, { recursive: true, force: true });
  world.w.cleanup();
});

function folder() {
  const d = path.join(world.dir, 'executed-' + Math.random().toString(16).slice(2));
  fs.mkdirSync(d);
  return d;
}

test('consume records an action once, a second consume exits 1 with QMANDATE_ALREADY_EXECUTED', async () => {
  const { files, ref, record } = await setup();
  const executed = folder();
  const first = await runCli(BIN, ['consume', files.action, '--ledger', executed]);
  assert.strictEqual(first.code, 0, first.out + first.err);
  assert.match(first.out, /RECORDED/);
  assert.ok(first.out.includes(ref));
  assert.ok(fs.existsSync(record(executed)));
  const second = await runCli(BIN, ['consume', files.action, '--ledger', executed]);
  assert.strictEqual(second.code, 1, second.out + second.err);
  assert.match(second.err, /QMANDATE_ALREADY_EXECUTED/);
  assert.match(second.out, /ALREADY EXECUTED/);
  assert.ok(!/RECORDED/.test(second.out));
  const copy = path.join(world.dir, 'copy-' + Math.random().toString(16).slice(2) + '.json');
  fs.writeFileSync(copy, JSON.stringify(JSON.parse(fs.readFileSync(files.action, 'utf8')), null, 2));
  const reformatted = await runCli(BIN, ['consume', copy, '--ledger', executed]);
  assert.strictEqual(reformatted.code, 1, reformatted.out + reformatted.err);
  assert.match(reformatted.err, /QMANDATE_ALREADY_EXECUTED/);
});

test('concurrent consume commands on one folder record the action exactly once', async () => {
  const { files } = await setup();
  const executed = folder();
  const runs = await Promise.all(Array.from({ length: 6 }, () => runCli(BIN, ['consume', files.action, '--ledger', executed])));
  assert.strictEqual(runs.filter((r) => r.code === 0).length, 1, runs.map((r) => r.code + ' ' + r.err).join('\n'));
  assert.ok(runs.filter((r) => r.code !== 0).every((r) => r.code === 1 && /QMANDATE_ALREADY_EXECUTED/.test(r.err)));
});

test('verify with --executed-dir is valid before consume and invalid after it', async () => {
  const { verify } = await setup();
  const executed = folder();
  const plain = await runCli(BIN, verify());
  assert.strictEqual(plain.code, 0, plain.out + plain.err);
  const before = await runCli(BIN, verify(executed));
  assert.strictEqual(before.code, 0, before.out + before.err);
  assert.ok(SAYS_VALID.test(before.out));
  assert.match(before.out, /ok {4}once/);
  const consumed = await runCli(BIN, ['consume', world.files.action, '--ledger', executed]);
  assert.strictEqual(consumed.code, 0, consumed.out + consumed.err);
  for (let i = 0; i < 2; i += 1) {
    const after = await runCli(BIN, verify(executed));
    assert.strictEqual(after.code, 1, after.out + after.err);
    assert.match(after.out, /FAIL {2}once/);
    assert.match(after.out, /INVALID/);
    const json = await runCli(BIN, verify(executed).concat(['--json']));
    assert.strictEqual(json.code, 1, json.out + json.err);
    const res = JSON.parse(json.out);
    assert.strictEqual(res.status, 'invalid');
    assert.strictEqual(res.actionRef, world.ref);
    assert.ok(res.checks.some((c) => c.name === 'once' && !c.ok && !c.indeterminate));
  }
  const other = await runCli(BIN, verify(folder()));
  assert.strictEqual(other.code, 0, other.out + other.err);
});

test('consume and --executed-dir refuse bad arguments with usage errors and record nothing', async () => {
  const { files, verify, record } = await setup();
  const executed = folder();
  const usage = [
    ['consume', files.action],
    ['consume', '--ledger', executed],
    ['consume', files.action, files.action, '--ledger', executed],
    ['consume', files.action, '--ledger'],
    ['consume', files.action, '--ledger', ''],
    ['consume', files.action, '--ledger', executed, '--ledger', executed],
    ['consume', files.action, '--ledger', executed, '--force'],
    ['consume', files.action, '--ledger', executed, '--json'],
    verify(path.join(world.dir, 'no-such-folder')),
    verify(files.action),
    ['verify', files.mandate, '--type', 'mandate', '--principal-key-id', world.w.qm.keyId(world.w.principal), '--no-revocations', '--allow-unanchored', '--at', world.w.at, '--executed-dir', executed],
  ];
  for (const args of usage) {
    const r = await runCli(BIN, args);
    assert.strictEqual(r.code, 64, args.join(' ') + '\n' + r.out + r.err);
    assert.ok(!SAYS_VALID.test(r.out) && !/RECORDED/.test(r.out), args.join(' '));
  }
  const missing = await runCli(BIN, ['consume', path.join(world.dir, 'no-such-action.json'), '--ledger', executed]);
  assert.strictEqual(missing.code, 64, missing.out + missing.err);
  const noLedger = await runCli(BIN, ['consume', files.action, '--ledger', path.join(world.dir, 'no-such-ledger')]);
  assert.strictEqual(noLedger.code, 1, noLedger.out + noLedger.err);
  assert.ok(!/RECORDED/.test(noLedger.out));
  assert.ok(!fs.existsSync(record(executed)));
});

test('consume refuses envelopes that are not a validly signed action with exit 1 and records nothing', async () => {
  const { files, texts, record } = await setup();
  const executed = folder();
  const write = (name, text) => {
    const f = path.join(world.dir, name + '-' + Math.random().toString(16).slice(2) + '.json');
    fs.writeFileSync(f, text);
    return f;
  };
  const forged = JSON.parse(texts.action);
  forged.statement.amount = '1';
  const firstKey = texts.action.match(/^\{"([^"]+)":/)[1];
  const cases = [
    files.mandate,
    write('forged', JSON.stringify(forged)),
    write('repeated-key', texts.action.replace(/^\{/, '{"' + firstKey + '":"x",')),
    write('not-json', texts.action.slice(0, -1)),
  ];
  for (const f of cases) {
    const r = await runCli(BIN, ['consume', f, '--ledger', executed]);
    assert.strictEqual(r.code, 1, f + '\n' + r.out + r.err);
    assert.ok(!/RECORDED/.test(r.out), f);
  }
  assert.deepStrictEqual(fs.readdirSync(executed), []);
  assert.ok(!fs.existsSync(record(executed)));
});

test('hostile action files make consume exit non zero quickly and record nothing', async (t) => {
  const { texts } = await setup();
  const executed = folder();
  const results = await cliCampaign({ bin: BIN, tag: 'qmandate-cli-consume', cap: ENVELOPE_MAX, validText: texts.action, commands: [(f) => ['consume', f, '--ledger', executed]] });
  t.diagnostic(results.length + ' runs, slowest ' + Math.max(...results.map((r) => r.ms)) + ' ms');
  assert.deepStrictEqual(fs.readdirSync(executed), []);
});
