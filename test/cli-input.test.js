'use strict';

const fs = require('fs');
const path = require('path');
const test = require('node:test');
const assert = require('node:assert');
const { cliCampaign, runCli, tempDir, SAYS_VALID } = require('./fuzz');
const { SEED } = require('./chain');
const { honest } = require('./honest');
const { PAYEE_KEY } = require('./bind');

const BIN = path.join(__dirname, '..', 'bin', 'qmandate.js');
const ENVELOPE_MAX = 1024 * 1024;
const RPC = ['--rpc', 'http://127.0.0.1:9', '--rpc', 'http://127.0.0.2:9'];

let world;
async function setup() {
  if (world) return world;
  const w = await honest();
  let pending;
  await w.qm.anchor(w.plainPrior, Object.assign({ seed: SEED, index: 0, mandate: w.plain.mandate, onPending: (p) => { pending = p; } }, w.ep));
  assert.ok(pending && typeof pending === 'object');
  const dir = tempDir('qmandate-cli-ok');
  const files = {};
  const texts = { mandate: w.plain.mandate, prior: w.plainPrior, action: w.plain.action, revoke: w.plain.revoke, pending };
  for (const [name, value] of Object.entries(texts)) {
    texts[name] = JSON.stringify(value);
    files[name] = path.join(dir, name + '.json');
    fs.writeFileSync(files[name], texts[name]);
  }
  const common = ['--principal-key-id', w.qm.keyId(w.principal), '--no-revocations', '--allow-unanchored', '--at', w.at];
  files.details = path.join(dir, 'order.txt');
  fs.writeFileSync(files.details, 'order 200');
  const binding = ['--details-file', files.details, '--counterparty-key-id', PAYEE_KEY];
  const cmd = {
    mandate: (f) => ['verify', f, '--type', 'mandate'].concat(common),
    action: (f) => ['verify', f, '--type', 'action', '--mandate', files.mandate, '--prior', files.prior].concat(common, binding),
    actionWithMandate: (f) => ['verify', files.action, '--type', 'action', '--mandate', f, '--prior', files.prior].concat(common, binding),
    actionWithPrior: (f) => ['verify', files.action, '--type', 'action', '--mandate', files.mandate, '--prior', f].concat(common, binding),
    revoke: (f) => ['verify', f, '--type', 'revoke', '--mandate', files.mandate].concat(common),
    revokeWithMandate: (f) => ['verify', files.revoke, '--type', 'revoke', '--mandate', f].concat(common),
    check: (f) => ['check', '--mandate', f, '--action', 'payment.send', '--currency', 'USD', '--amount', '1', '--counterparty', 'shop', '--spent', '0', '--trust-custom-endpoints'].concat(RPC),
    complete: (f) => ['complete', f, '--pending', files.pending, '--mandate', files.mandate].concat(RPC),
    completeWithPending: (f) => ['complete', files.prior, '--pending', f, '--mandate', files.mandate].concat(RPC),
    completeWithMandate: (f) => ['complete', files.prior, '--pending', files.pending, '--mandate', f].concat(RPC),
  };
  const json = (c) => (f) => c(f).concat(['--json']);
  world = { w, dir, files, texts, cmd, json };
  return world;
}

test.after(() => {
  if (!world) return;
  fs.rmSync(world.dir, { recursive: true, force: true });
  world.w.cleanup();
});

async function valid(args) {
  const r = await runCli(BIN, args);
  assert.strictEqual(r.code, 0, r.out + r.err);
  assert.ok(SAYS_VALID.test(r.out), r.out);
}

async function hostile(t, validText, commands) {
  const results = await cliCampaign({ bin: BIN, tag: 'qmandate-cli', cap: ENVELOPE_MAX, validText, commands });
  t.diagnostic(results.length + ' runs, slowest ' + Math.max(...results.map((r) => r.ms)) + ' ms');
}

test('hostile mandate files make verify, check and complete exit non zero quickly and never print VALID', async (t) => {
  const { files, texts, cmd, json } = await setup();
  await valid(cmd.mandate(files.mandate));
  await valid(json(cmd.mandate)(files.mandate));
  await valid(cmd.actionWithMandate(files.mandate));
  await valid(cmd.revokeWithMandate(files.mandate));
  const check = await runCli(BIN, cmd.check(files.mandate));
  assert.strictEqual(check.code, 1, check.out + check.err);
  assert.match(check.err, /chain time could not be established/);
  assert.ok(!/ALLOWED/.test(check.out));
  const complete = await runCli(BIN, cmd.completeWithMandate(files.mandate));
  assert.strictEqual(complete.code, 1, complete.out + complete.err);
  assert.match(complete.err, /loopback address/);
  await hostile(t, texts.mandate, [cmd.mandate, json(cmd.mandate), cmd.actionWithMandate, cmd.revokeWithMandate, cmd.check, cmd.completeWithMandate]);
});

test('hostile action files make verify and complete exit non zero quickly and never print VALID', async (t) => {
  const { files, texts, cmd, json } = await setup();
  await valid(cmd.action(files.action));
  await valid(json(cmd.action)(files.action));
  await valid(cmd.actionWithPrior(files.prior));
  const complete = await runCli(BIN, cmd.complete(files.prior));
  assert.strictEqual(complete.code, 1, complete.out + complete.err);
  assert.match(complete.err, /loopback address/);
  await hostile(t, texts.action, [cmd.action]);
  await hostile(t, texts.prior, [cmd.actionWithPrior, cmd.complete]);
});

test('hostile revocation and pending stamp files make verify and complete exit non zero quickly and never print VALID', async (t) => {
  const { files, texts, cmd, json } = await setup();
  await valid(cmd.revoke(files.revoke));
  await valid(json(cmd.revoke)(files.revoke));
  const complete = await runCli(BIN, cmd.completeWithPending(files.pending));
  assert.strictEqual(complete.code, 1, complete.out + complete.err);
  assert.match(complete.err, /loopback address/);
  await hostile(t, texts.revoke, [cmd.revoke]);
  await hostile(t, texts.pending, [cmd.completeWithPending]);
});
