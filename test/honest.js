'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const qm = require('..');
const { makeChain, client, SEED, qstampRoot } = require('./chain');

const ROOT = path.join(__dirname, '..');
const qstamp = require(qstampRoot(ROOT));

function provenByPinnedOperators() {
  const had = Object.prototype.hasOwnProperty.call(qstamp, 'isProven');
  const before = qstamp.isProven;
  qstamp.isProven = (r) => !!r && r.status === 'unproven' && Array.isArray(r.checks) && r.checks.every((c) => c.ok || c.name === 'proof');
  return () => {
    if (had) qstamp.isProven = before;
    else delete qstamp.isProven;
  };
}

function iso(ms) {
  return new Date(ms).toISOString();
}

async function honest() {
  const chain = makeChain(ROOT);
  const ep = { trustCustomEndpoints: true, clients: [client(chain, 'a'), client(chain, 'b')] };
  const principal = qm.generateKey();
  const holder = qm.generateKey();
  const mandate = qm.grant({
    key: principal,
    agent: qm.describeKey(holder),
    agentLabel: 'buyer',
    counterparties: ['shop', 'depot'],
    scopes: [
      { action: 'payment.send', currency: 'USD', maxPerAction: '500', maxTotal: '800' },
      { action: 'data.read', currency: '', maxPerAction: '0', maxTotal: '0' },
    ],
    validFrom: iso(chain.time * 1000 - 60000),
    validUntil: iso((chain.time + 30 * 86400) * 1000 + 537),
    note: 'weekly supplies',
  });
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qmandate-honest-'));
  const [m] = await qm.anchor(mandate, Object.assign({ seed: SEED, index: 0 }, ep));
  const pay = (amount) => qm.act(Object.assign({ key: holder, mandate: m, ledger: dir, action: 'payment.send', currency: 'USD', amount, counterparty: 'shop', details: Buffer.from('order ' + amount) }, ep));
  const a1 = await pay('100');
  const a2 = await pay('200');
  const [x1, x2] = await qm.anchor([a1, a2], Object.assign({ seed: SEED, index: 0, mandate: m }, ep));
  const revocation = qm.revoke({ key: principal, mandate: m, note: 'closed' });
  const [rv] = await qm.anchor(revocation, Object.assign({ seed: SEED, index: 0 }, ep));
  const at = iso((chain.time + 1) * 1000);
  const principalKeyId = qm.keyId(principal);
  const options = {
    mandate: Object.assign({ type: 'mandate', principalKeyId, revocations: [], at }, ep),
    action: Object.assign({ type: 'action', mandate: m, principalKeyId, revocations: [], priorActions: [x1], at }, ep),
    revoke: Object.assign({ type: 'revoke', mandate: m, principalKeyId, at }, ep),
  };
  const records = { mandate: m, action: x2, revoke: rv };
  const cleanup = () => fs.rmSync(dir, { recursive: true, force: true });
  const plain = { mandate, action: a2, revoke: revocation };
  const plainOptions = {
    mandate: Object.assign({}, options.mandate, { requireAnchor: false }),
    action: Object.assign({}, options.action, { mandate, priorActions: [a1], requireAnchor: false }),
    revoke: Object.assign({}, options.revoke, { mandate, requireAnchor: false }),
  };
  return { qm, chain, ep, dir, principal, holder, records, prior: x1, plainPrior: a1, options, plain, plainOptions, at, cleanup };
}

module.exports = { honest, provenByPinnedOperators, iso, ROOT };
