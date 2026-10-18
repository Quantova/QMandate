'use strict';

const test = require('node:test');
const assert = require('node:assert');
const qm = require('..');
const { campaign, mutator, canon } = require('./fuzz');
const { honest, provenByPinnedOperators } = require('./honest');

const CODE = 'QMANDATE_';
const TYPES = ['mandate', 'action', 'revoke'];
const LABEL = { mandate: 'mandate', action: 'action', revoke: 'revocation' };
const A = { mandate: 'a mandate', action: 'an action', revoke: 'a revocation' };
const isValid = (r) => r.status === 'valid' || r.valid === true;

function stringsOf(v, out) {
  if (typeof v === 'string' && v.length < 200) out.push(v);
  else if (v && typeof v === 'object') for (const k of Object.keys(v)) stringsOf(v[k], out);
  return out;
}

let world;
async function setup(t) {
  if (!world) world = await honest();
  t.after(provenByPinnedOperators());
  return world;
}

test.after(() => {
  if (world) world.cleanup();
});

async function honestFirst(w, record, opts) {
  const r = await w.qm.verify(record, opts);
  assert.strictEqual(r.status, 'valid', JSON.stringify(r.checks.filter((c) => !c.ok)));
  assert.strictEqual(r.valid, true);
}

function poolOf(w) {
  return stringsOf([w.records, w.plain, w.prior], []);
}

TYPES.forEach((type, n) => {
  test('a changed anchored ' + LABEL[type] + ' envelope never verifies valid, every refusal carries the ' + CODE + ' code and each check ends within the time bound', async (t) => {
    const w = await setup(t);
    const base = w.records[type];
    const opts = w.options[type];
    await honestFirst(w, base, opts);
    const stats = await campaign({ name: type, seed: 0x4d41 + n, base, pool: poolOf(w), code: CODE, check: (m) => w.qm.verify(m, opts), valid: isValid });
    t.diagnostic(JSON.stringify(stats));
  });

  test('a changed unanchored ' + LABEL[type] + ' envelope never verifies valid when anchors are not required', async (t) => {
    const w = await setup(t);
    const base = w.plain[type];
    const opts = w.plainOptions[type];
    await honestFirst(w, base, opts);
    const stats = await campaign({ name: 'unanchored ' + type, seed: 0x5e11 + n, base, pool: poolOf(w), code: CODE, check: (m) => w.qm.verify(m, opts), valid: isValid });
    t.diagnostic(JSON.stringify(stats));
  });

  test('a changed Qstamp receipt never lets ' + A[type] + ' verify valid', async (t) => {
    const w = await setup(t);
    const base = w.records[type];
    const opts = w.options[type];
    await honestFirst(w, base, opts);
    const pool = stringsOf([w.records.mandate.anchor, w.records.action.anchor, w.records.revoke.anchor, w.prior.anchor], []);
    const stats = await campaign({
      name: type + ' receipt',
      seed: 0xa9c4 + n,
      base: base.anchor,
      pool,
      code: CODE,
      check: (r) => w.qm.verify(Object.assign({}, base, { anchor: r }), opts),
      valid: isValid,
    });
    t.diagnostic(JSON.stringify(stats));
  });
});

test('another anchored receipt of the same batch never lets an action verify valid', async (t) => {
  const w = await setup(t);
  const base = w.records.action;
  const opts = w.options.action;
  await honestFirst(w, base, opts);
  for (const anchor of [w.prior.anchor, w.records.mandate.anchor, w.records.revoke.anchor]) {
    const r = await w.qm.verify(Object.assign({}, base, { anchor }), opts);
    assert.ok(!isValid(r), JSON.stringify(r.checks.filter((c) => !c.ok)));
  }
});

function withoutAnchor(v) {
  if (!v || typeof v !== 'object' || Array.isArray(v)) return v;
  const out = {};
  for (const k of Object.keys(v)) if (k !== 'anchor') Object.defineProperty(out, k, { value: v[k], enumerable: true });
  return out;
}

test('a changed mandate given to verify never lets an action verify valid', async (t) => {
  const w = await setup(t);
  const target = w.records.action;
  const opts = w.options.action;
  await honestFirst(w, target, opts);
  const stats = await campaign({
    name: 'mandate given to action',
    seed: 0x3a7e,
    base: w.records.mandate,
    pool: poolOf(w),
    code: CODE,
    check: (m) => w.qm.verify(target, Object.assign({}, opts, { mandate: m })),
    valid: isValid,
  });
  t.diagnostic(JSON.stringify(stats));
});

test('a mandate changed anywhere outside its receipt never lets a revocation verify valid', async (t) => {
  const w = await setup(t);
  const target = w.records.revoke;
  const opts = Object.assign({}, w.options.revoke, { mandate: w.plain.mandate });
  await honestFirst(w, target, opts);
  const baseForm = canon(withoutAnchor(w.plain.mandate));
  const stats = await campaign({
    name: 'mandate given to revoke',
    seed: 0x3a7f,
    base: w.plain.mandate,
    pool: poolOf(w),
    code: CODE,
    skip: (m) => canon(withoutAnchor(m)) === baseForm,
    check: (m) => w.qm.verify(target, Object.assign({}, opts, { mandate: m })),
    valid: isValid,
  });
  t.diagnostic(JSON.stringify(stats));
});

test('an earlier action changed anywhere outside its receipt never completes the running total of the action that follows it', async (t) => {
  const w = await setup(t);
  const target = w.records.action;
  const opts = Object.assign({}, w.options.action, { priorActions: [w.plainPrior] });
  await honestFirst(w, target, opts);
  const baseForm = canon(withoutAnchor(w.plainPrior));
  const stats = await campaign({
    name: 'earlier action',
    seed: 0x9e1d,
    base: w.plainPrior,
    pool: poolOf(w),
    code: CODE,
    skip: (p) => canon(withoutAnchor(p)) === baseForm,
    check: (p) => w.qm.verify(target, Object.assign({}, opts, { priorActions: [p] })),
    valid: isValid,
  });
  t.diagnostic(JSON.stringify(stats));
});

test('verify refuses an unknown record type with the QMANDATE_INVALID_INPUT code', async (t) => {
  const w = await setup(t);
  for (const type of [undefined, null, '', 'Mandate', 'mandate ', 'receipt', 'checkpoint', ['action'], 'revocation']) {
    await assert.rejects(qm.verify(w.records.mandate, Object.assign({}, w.options.mandate, { type })), (e) => e.code === 'QMANDATE_INVALID_INPUT');
  }
});

test('the mutation stream is the same for the same seed', () => {
  const a = mutator(7);
  const b = mutator(7);
  const base = { format: 'qmandate/2', statement: { a: '00ff', b: 1 }, signature: 'QUJDREVGR0hJSktMTU5PUA==' };
  for (let i = 0; i < 200; i += 1) assert.strictEqual(canon(a.mutate(base, i).value), canon(b.mutate(base, i).value));
});
