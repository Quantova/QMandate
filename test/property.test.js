'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const qm = require('..');
const F = require('../lib/format');
const native = require('../lib/native');
const Ledger = require('../lib/ledger');
const { makeChain, client, SEED } = require('./chain');
const { PAYEE, bound, grantIssuedEarly } = require('./bind');
const { iterations, mulberry32 } = require('./fuzz');
const { provenByPinnedOperators, iso, ROOT } = require('./honest');

const SKEW = 5 * 60 * 1000;
const dirs = [];

test.after(() => {
  for (const d of dirs) fs.rmSync(d, { recursive: true, force: true });
});

function folder() {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'qmandate-property-'));
  dirs.push(d);
  return d;
}

function random(seed) {
  const rnd = mulberry32(seed);
  const int = (n) => Math.floor(rnd() * n);
  const pick = (a) => a[int(a.length)];
  return { rnd, int, pick };
}

function endpoints() {
  const chain = makeChain(ROOT);
  return { chain, ep: { trustCustomEndpoints: true, clients: [client(chain, 'a'), client(chain, 'b')] } };
}

function memoryStore() {
  const m = new Map();
  return {
    m,
    async read(name) {
      return m.get(name) || null;
    },
    async compareAndSwap(name, expected, next) {
      await new Promise((resolve) => setImmediate(resolve));
      if ((m.get(name) || null) !== expected) return false;
      m.set(name, next);
      return true;
    },
  };
}

const refOf = (e) => F.refOf(F.parse(e));

test('over random sequences of concurrent acts the running total of each scope never exceeds its limit in the signed actions or in the ledger', async (t) => {
  const r = random(0x7a11);
  const trials = Math.max(6, Math.round(iterations(1000) / 170));
  const stats = { trials, signed: 0, refused: 0, overLimit: 0, overTotal: 0 };
  for (let trial = 0; trial < trials; trial += 1) {
    const { chain, ep } = endpoints();
    const principal = qm.generateKey();
    const holder = qm.generateKey();
    const scopes = ['payment.send', 'payment.refund'].map((action, i) => {
      const per = 1 + r.int(400);
      return { action, currency: i ? 'EUR' : 'USD', maxPerAction: String(per), maxTotal: String(per + r.int(per * 5 + 1)) };
    });
    const mandate = qm.grant({ key: principal, agent: qm.describeKey(holder), scopes, validFrom: iso(Date.now() - 60000), validUntil: iso((chain.time + 3600) * 1000) });
    const useMemory = trial % 3 === 2;
    const dir = folder();
    const store = useMemory ? memoryStore() : null;
    const ledgerHandle = () => (useMemory ? store : r.int(2) ? dir : qm.fileLedger(dir));
    const signed = new Map(scopes.map((s) => [s.action, []]));
    const rounds = 6 + r.int(6);
    for (let round = 0; round < rounds; round += 1) {
      chain.newBlock();
      const batch = Array.from({ length: 1 + r.int(5) }, () => {
        const scope = r.pick(scopes);
        const per = Number(scope.maxPerAction);
        const amount = String(r.int(4) === 0 ? 0 : r.int(Math.ceil(per * 1.3)) + 1);
        return { scope, amount };
      });
      const results = await Promise.allSettled(batch.map((b) => qm.act(Object.assign({ key: holder, mandate, ledger: ledgerHandle(), action: b.scope.action, currency: b.scope.currency, amount: b.amount, counterparty: PAYEE }, ep))));
      results.forEach((res, i) => {
        const { scope, amount } = batch[i];
        if (res.status === 'fulfilled') {
          signed.get(scope.action).push(res.value);
          stats.signed += 1;
          return;
        }
        stats.refused += 1;
        const e = res.reason;
        assert.strictEqual(e && e.code, 'QMANDATE_NOT_AUTHORISED', String(e && e.message));
        const perAction = BigInt(amount) > BigInt(scope.maxPerAction);
        const total = BigInt(e.spent) + BigInt(amount) > BigInt(scope.maxTotal);
        if (perAction) stats.overLimit += 1;
        if (total) stats.overTotal += 1;
        assert.ok(perAction || total, 'an act of ' + amount + ' was refused with ' + e.spent + ' spent under ' + JSON.stringify(scope));
      });
      for (const scope of scopes) {
        const list = signed.get(scope.action);
        const sum = list.reduce((a, e) => a + BigInt(e.statement.amount), 0n);
        const name = Ledger.nameOf(qm.mandateRef(mandate), scope.action);
        const text = useMemory ? store.m.get(name) || null : fs.existsSync(path.join(dir, name + '.json')) ? fs.readFileSync(path.join(dir, name + '.json'), 'utf8') : null;
        const state = text === null ? { sequence: '0', total: '0' } : JSON.parse(text);
        assert.strictEqual(state.total, sum.toString());
        assert.strictEqual(state.sequence, String(list.length));
        assert.ok(BigInt(state.total) <= BigInt(scope.maxTotal));
      }
    }
    for (const scope of scopes) {
      const list = signed.get(scope.action).slice().sort((a, b) => Number(a.statement.sequence) - Number(b.statement.sequence));
      let total = 0n;
      list.forEach((e, i) => {
        assert.strictEqual(e.format, qm.ACTION_FORMAT);
        assert.strictEqual(e.statement.sequence, String(i + 1));
        assert.strictEqual(e.statement.previousRef, i ? refOf(list[i - 1]) : '');
        assert.ok(BigInt(e.statement.amount) <= BigInt(scope.maxPerAction));
        total += BigInt(e.statement.amount);
        assert.strictEqual(e.statement.total, total.toString());
        assert.ok(total <= BigInt(scope.maxTotal), 'signed running total ' + total + ' above ' + scope.maxTotal);
      });
      if (!useMemory) {
        const rec = await qm.ledgerActions(dir, mandate, scope.action);
        assert.strictEqual(rec.complete, true);
        assert.strictEqual(rec.total, total.toString());
        assert.deepStrictEqual(rec.actions.map(refOf), list.map(refOf));
      }
      if (list.length) {
        const last = list[list.length - 1];
        const v = await qm.verify(last, Object.assign({ type: 'action', mandate, principalKeyId: qm.keyId(principal), revocations: [], priorActions: list.slice(0, -1), requireAnchor: false, at: iso(chain.time * 1000) }, bound(last), ep));
        assert.strictEqual(v.status, 'valid', JSON.stringify(v.checks.filter((c) => !c.ok)));
        assert.strictEqual(v.totalProven, true);
      }
    }
  }
  assert.ok(stats.signed > 0 && stats.overLimit > 0 && stats.overTotal > 0, JSON.stringify(stats));
  t.diagnostic(JSON.stringify(stats));
});

test('authorise never allows a mandate outside its period or one its principal revoked, and allows one clearly in force', async (t) => {
  const r = random(0xa071);
  const n = iterations(400);
  const { chain, ep } = endpoints();
  const principal = qm.generateKey();
  const holder = qm.generateKey();
  const scopes = [{ action: 'payment.send', currency: 'USD', maxPerAction: '500', maxTotal: '800' }];
  const other = qm.grant({ key: principal, agent: qm.describeKey(holder), scopes, validUntil: iso(Date.now() + 86400000) });
  const decoy = qm.revoke({ key: principal, mandate: other });
  const stats = { cases: n, allowed: 0, refused: 0, revoked: 0, threw: 0, early: 0, expired: 0 };
  const request = { action: 'payment.send', currency: 'USD', amount: '10' };
  for (let i = 0; i < n; i += 1) {
    chain.newBlock();
    const chainMs = chain.time * 1000;
    const spread = r.pick([2000, 120000, 7200000]);
    const around = r.int(3) === 0;
    const vf = around ? chainMs - r.int(spread) : chainMs + r.int(2 * spread) - spread;
    const vu = around ? chainMs + 1 + r.int(spread) : vf + 1 + r.int(r.pick([2000, 120000, 7200000]));
    const mandate = qm.grant({ key: principal, agent: qm.describeKey(holder), scopes, validFrom: iso(vf), validUntil: iso(vu) });
    const revoked = r.int(4) === 0;
    const revocations = [];
    if (revoked) revocations.push(qm.revoke({ key: principal, mandate, revokedAt: iso(r.int(2) ? vu + 1000 : vf) }));
    if (r.int(3) === 0) revocations.push(decoy);
    if (r.int(4) === 0) {
      const real = qm.revoke({ key: principal, mandate });
      const sig = Buffer.from(real.signature, 'base64');
      sig[r.int(sig.length)] ^= 1 << r.int(8);
      revocations.push(Object.assign({}, real, { signature: sig.toString('base64') }));
    }
    const atMs = r.int(5) < 2 ? undefined : chainMs + r.int(2 * (SKEW + 60000)) - (SKEW + 60000);
    const opts = Object.assign({ spent: '0', revocations }, ep);
    if (atMs !== undefined) opts.at = iso(atMs);
    const t0 = Date.now();
    let res;
    let error;
    try {
      res = await qm.authorise(mandate, request, opts);
    } catch (e) {
      error = e;
    }
    const t1 = Date.now();
    const lowAt = atMs === undefined ? Infinity : atMs;
    const highAt = atMs === undefined ? -Infinity : atMs;
    if (error) {
      stats.threw += 1;
      assert.strictEqual(error.code, 'QMANDATE_INVALID_INPUT', error.message);
      assert.ok(atMs !== undefined && (atMs < Math.min(chainMs, t1) - SKEW || atMs > Math.max(chainMs, t0) + SKEW), 'refused at ' + iso(atMs) + ' with the chain at ' + iso(chainMs));
      continue;
    }
    if (atMs !== undefined) assert.ok(atMs >= Math.min(chainMs, t0) - SKEW && atMs <= Math.max(chainMs, t1) + SKEW, 'accepted at ' + iso(atMs) + ' with the chain at ' + iso(chainMs));
    assert.strictEqual(res.chainTime, iso(chainMs));
    if (res.allowed) {
      stats.allowed += 1;
      assert.ok(!revoked, 'allowed a revoked mandate');
      assert.ok(vu >= Math.max(chainMs, t0, highAt), 'allowed a mandate that expired at ' + iso(vu) + ' with the chain at ' + iso(chainMs) + ' and at ' + opts.at);
      assert.ok(vf <= Math.min(chainMs, t1, lowAt), 'allowed a mandate not in force until ' + iso(vf) + ' with the chain at ' + iso(chainMs) + ' and at ' + opts.at);
    } else {
      stats.refused += 1;
      if (revoked) stats.revoked += 1;
      if (vu < Math.max(chainMs, t0, highAt)) stats.expired += 1;
      if (vf > Math.min(chainMs, t1, lowAt)) stats.early += 1;
      if (revoked) assert.ok(res.reasons.includes('the principal has revoked this mandate'));
      const clearlyInForce = !revoked && vf <= Math.min(chainMs, t0, lowAt) && vu >= Math.max(chainMs, t1, highAt);
      assert.ok(!clearlyInForce, 'refused a mandate in force from ' + iso(vf) + ' to ' + iso(vu) + ' with the chain at ' + iso(chainMs) + ', ' + res.reasons.join(', '));
    }
  }
  assert.ok(stats.allowed > 0 && stats.revoked > 0 && stats.expired > 0 && stats.early > 0 && stats.threw > 0, JSON.stringify(stats));
  t.diagnostic(JSON.stringify(stats));
});

function legacyAction(s, amount, actedAt, r) {
  const m = F.parse(s.mandate);
  const st = {
    mandateId: m.statement.mandateId,
    mandateRef: F.refOf(m),
    actionId: Array.from({ length: 32 }, () => '0123456789abcdef'[r.int(16)]).join(''),
    agentKeyId: qm.keyId(s.holder),
    action: 'payment.send',
    currency: 'USD',
    amount,
    counterparty: PAYEE,
    detailsDigest: F.sha3(Buffer.alloc(0)).toString('hex'),
    actedAt,
    note: '',
  };
  const sig = native.sign(s.holder, F.payload('action', st), globalThis.crypto.getRandomValues(new Uint8Array(32)));
  return { format: F.FORMAT, type: 'action', algorithm: F.ALGORITHM, signer: { id: qm.keyId(s.holder), publicKey: Buffer.from(qm.publicKey(s.holder)).toString('base64') }, statement: st, signature: Buffer.from(sig).toString('base64') };
}

test('an older format metered action never verifies valid unless the verifier sets acceptLegacyActions to true', async (t) => {
  t.after(provenByPinnedOperators());
  const r = random(0x1e9a);
  const { chain, ep } = endpoints();
  const s = { principal: qm.generateKey(), holder: qm.generateKey() };
  const maxTotal = 900;
  s.mandate = grantIssuedEarly(s.principal, s.holder, [{ action: 'payment.send', currency: 'USD', maxPerAction: '500', maxTotal: String(maxTotal) }], iso(Date.now() - 60000), iso((chain.time + 86400) * 1000));
  const actedAt = iso(chain.time * 1000);
  const legacy = Array.from({ length: 8 }, () => legacyAction(s, String(r.int(501)), actedAt, r));
  const [anchored] = await qm.anchor(legacyAction(s, String(r.int(501)), actedAt, r), Object.assign({ seed: SEED, index: 0, mandate: s.mandate }, ep));
  const current = await qm.act(Object.assign({ key: s.holder, mandate: s.mandate, ledger: folder(), action: 'payment.send', currency: 'USD', amount: '1', counterparty: PAYEE }, ep));
  const flags = [undefined, false, 0, 1, 'true', 'yes', {}, [], [true], null, { valueOf: () => true }];
  const n = iterations(300);
  const stats = { cases: n, refused: 0, accepted: 0, overTotal: 0 };
  for (let i = 0; i < n; i += 1) {
    const isAnchored = r.int(6) === 0;
    const target = isAnchored ? anchored : r.pick(legacy);
    const pool = legacy.filter((e) => e !== target).concat(r.int(4) === 0 ? [current] : []);
    const priors = r.int(10) === 0 ? undefined : pool.filter(() => r.int(3) === 0);
    const opts = Object.assign({ type: 'action', mandate: s.mandate, principalKeyId: qm.keyId(s.principal), revocations: [], requireAnchor: false, at: iso(chain.time * 1000 + 1000) }, bound(target), ep);
    if (priors !== undefined) opts.priorActions = priors;
    const strict = r.pick([undefined, true, false]);
    if (strict !== undefined) opts.strict = strict;
    const flag = r.int(3) === 0 ? true : r.pick(flags);
    if (flag !== undefined) opts.acceptLegacyActions = flag;
    const res = await qm.verify(target, opts);
    assert.strictEqual(res.format, F.FORMAT);
    if (flag !== true) {
      stats.refused += 1;
      assert.notStrictEqual(res.status, 'valid', 'an older format action verified valid with acceptLegacyActions ' + String(flag));
      assert.strictEqual(res.valid, false);
      continue;
    }
    if (priors === undefined || isAnchored) {
      if (priors === undefined) assert.notStrictEqual(res.status, 'valid');
      continue;
    }
    if (priors.includes(current)) {
      assert.notStrictEqual(res.status, 'valid', 'an older format action verified valid beside an unordered action in the newer format');
      continue;
    }
    const total = priors.reduce((a, e) => a + Number(e.statement.amount), 0) + Number(target.statement.amount);
    if (total > maxTotal) {
      stats.overTotal += 1;
      assert.strictEqual(res.status, 'invalid');
    } else {
      stats.accepted += 1;
      assert.strictEqual(res.status, 'valid', JSON.stringify(res.checks.filter((c) => !c.ok)));
      assert.strictEqual(res.totalProven, false);
    }
  }
  assert.ok(stats.accepted > 0 && stats.overTotal > 0, JSON.stringify(stats));
  t.diagnostic(JSON.stringify(stats));
});
