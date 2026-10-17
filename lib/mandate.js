// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const qstamp = require('@quantovainc/qstamp');
const native = require('./native');
const F = require('./format');

function requireSeed(key) {
  if (!(key instanceof Uint8Array) || key.length !== 32) {
    F.reject('a signing key is a 32 byte Uint8Array seed, kept by its holder and wiped with fill(0) after use');
  }
  return key;
}

function randomHex(n) {
  const b = new Uint8Array(n);
  globalThis.crypto.getRandomValues(b);
  return Buffer.from(b).toString('hex');
}

function generateKey() {
  const seed = new Uint8Array(32);
  globalThis.crypto.getRandomValues(seed);
  if (seed.every((b) => b === 0)) throw new Error('the secure random source returned only zeros');
  return seed;
}

function publicKey(key) {
  return native.publicKey(requireSeed(key));
}

function keyId(key) {
  return F.keyIdOf(publicKey(key));
}

function describeKey(key) {
  const pk = publicKey(key);
  return { format: 'qmandate-key/1', algorithm: F.ALGORITHM, id: F.keyIdOf(pk), publicKey: Buffer.from(pk).toString('base64') };
}

function agentKeyIdOf(agent) {
  if (typeof agent === 'string' && /^[0-9a-f]{64}$/.test(agent)) return agent;
  if (agent instanceof Uint8Array) return F.keyIdOf(agent);
  if (agent && typeof agent === 'object' && agent.format === 'qmandate-key/1' && typeof agent.publicKey === 'string') {
    const raw = Buffer.from(agent.publicKey, 'base64');
    if (raw.toString('base64') !== agent.publicKey) F.reject('the agent public key is not canonical base64');
    const id = F.keyIdOf(raw);
    if (agent.id !== id) F.reject('the agent key description names an id that does not match its public key');
    return id;
  }
  F.reject('agent is a qmandate-key/1 description, a public key or a 64 character key id');
}

function nowIso() {
  return new Date().toISOString();
}

function seal(type, key, statement) {
  const pk = publicKey(key);
  const id = F.keyIdOf(pk);
  let plain;
  try {
    plain = F.plainCopy(statement);
  } catch (e) {
    F.reject('the statement is not plain data');
  }
  const problem = F.statementProblem(type, plain);
  if (problem) F.reject(problem);
  statement = plain;
  const message = F.payload(type, statement);
  const rnd = new Uint8Array(32);
  globalThis.crypto.getRandomValues(rnd);
  let signature;
  try {
    signature = native.sign(key, message, rnd);
  } finally {
    rnd.fill(0);
  }
  if (!native.verify(pk, message, signature)) throw new Error('the new signature did not verify, nothing was produced');
  return {
    format: F.FORMAT,
    type,
    algorithm: F.ALGORITHM,
    signer: { id, publicKey: Buffer.from(pk).toString('base64') },
    statement: JSON.parse(JSON.stringify(statement)),
    signature: Buffer.from(signature).toString('base64'),
  };
}

function grant(options) {
  if (!options || typeof options !== 'object') F.reject('grant needs options');
  requireSeed(options.key);
  if (options.validUntil === undefined) F.reject('validUntil is required, a mandate never lasts indefinitely');
  const statement = {
    mandateId: randomHex(16),
    principalKeyId: keyId(options.key),
    agentKeyId: agentKeyIdOf(options.agent),
    agentLabel: options.agentLabel === undefined ? '' : options.agentLabel,
    scopes: options.scopes,
    counterparties: options.counterparties === undefined ? [] : options.counterparties,
    validFrom: options.validFrom === undefined ? nowIso() : options.validFrom,
    validUntil: options.validUntil,
    issuedAt: nowIso(),
    note: options.note === undefined ? '' : options.note,
  };
  return seal('mandate', options.key, statement);
}

function badMandate(message) {
  const e = new Error(message);
  e.code = 'QMANDATE_INVALID_MANDATE';
  throw e;
}

function mandateOf(envelope) {
  const p = F.parse(envelope);
  if (p.type !== 'mandate') badMandate('the envelope is not a mandate');
  if (p.signerId !== F.keyIdOf(p.publicKey) || p.signerId !== p.statement.principalKeyId) badMandate('the mandate is not signed by the principal it names');
  if (!native.verify(p.publicKey, F.payload('mandate', p.statement), p.signature)) badMandate('the mandate signature does not verify');
  return p;
}

function revokedBy(m, revocations) {
  if (revocations === undefined) return false;
  if (!Array.isArray(revocations) || revocations.length > 500) F.reject('revocations is a list of at most 500 envelopes');
  for (const env of revocations) {
    let r;
    try {
      r = F.parse(env);
    } catch (e) {
      continue;
    }
    if (r.type !== 'revoke' || r.statement.mandateId !== m.statement.mandateId || r.statement.principalKeyId !== m.statement.principalKeyId) continue;
    if (r.signerId !== m.statement.principalKeyId || r.signerId !== F.keyIdOf(r.publicKey)) continue;
    if (native.verify(r.publicKey, F.payload('revoke', r.statement), r.signature)) return true;
  }
  return false;
}

function amountOf(value, what) {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]{0,29})$/.test(value)) F.reject(what + ' is a whole number of minor units written as text');
  return BigInt(value);
}

function decide(m, request, at, spent) {
  const reasons = [];
  const st = m.statement;
  const scope = st.scopes.find((s) => s.action === request.action);
  const atMs = Date.parse(at);
  if (!scope) {
    reasons.push('the mandate does not permit the action ' + String(request.action).slice(0, 64));
  } else {
    if (request.currency !== scope.currency) reasons.push('the mandate permits this action only in ' + (scope.currency || 'no currency'));
    const amount = BigInt(request.amount);
    if (amount > BigInt(scope.maxPerAction)) reasons.push('the amount exceeds the limit of ' + scope.maxPerAction + ' per action');
    if (spent + amount > BigInt(scope.maxTotal)) reasons.push('the amount would take the total for this action beyond ' + scope.maxTotal);
  }
  if (st.counterparties.length > 0 && !st.counterparties.includes(request.counterparty)) reasons.push('the counterparty is not permitted by the mandate');
  if (atMs < Date.parse(st.validFrom)) reasons.push('the mandate is not yet in force');
  if (atMs > Date.parse(st.validUntil)) reasons.push('the mandate has expired');
  return { allowed: reasons.length === 0, reasons, scope: scope ? Object.assign({}, scope) : null };
}

function normaliseRequest(request) {
  if (!request || typeof request !== 'object') F.reject('the request is an object');
  const r = {
    action: request.action,
    currency: request.currency === undefined ? '' : request.currency,
    amount: request.amount === undefined ? '0' : request.amount,
    counterparty: request.counterparty === undefined ? '' : request.counterparty,
  };
  if (typeof r.action !== 'string' || !/^[a-z][a-z0-9_.]{0,63}$/.test(r.action)) F.reject('action is a lowercase name such as payment.send');
  if (typeof r.currency !== 'string' || !/^([A-Z]{3})?$/.test(r.currency)) F.reject('currency is a three letter ISO 4217 code or empty');
  amountOf(r.amount, 'amount');
  const p = F.textProblem(r.counterparty, F.LABEL_MAX, 'counterparty');
  if (p) F.reject(p);
  return r;
}

function authorise(mandate, request, options) {
  const opts = options || {};
  const m = mandateOf(mandate);
  const r = normaliseRequest(request);
  const at = opts.at === undefined ? nowIso() : opts.at;
  const tp = F.timeProblem(at, 'at');
  if (tp) F.reject(tp);
  const spent = opts.spent === undefined ? 0n : amountOf(opts.spent, 'spent');
  const out = decide(m, r, at, spent);
  if (revokedBy(m, opts.revocations)) {
    out.allowed = false;
    out.reasons.push('the principal has revoked this mandate');
  }
  if (opts.agentKeyId !== undefined && opts.agentKeyId !== m.statement.agentKeyId) {
    out.allowed = false;
    out.reasons.push('the mandate was granted to a different agent key');
  }
  if (opts.principalKeyId !== undefined && opts.principalKeyId !== m.statement.principalKeyId) {
    out.allowed = false;
    out.reasons.push('the mandate was granted by a different principal');
  }
  return Object.assign(out, { mandateId: m.statement.mandateId, mandateRef: F.refOf(m), at });
}

function act(options) {
  if (!options || typeof options !== 'object') F.reject('act needs options');
  requireSeed(options.key);
  const m = mandateOf(options.mandate);
  const r = normaliseRequest(options);
  const actedAt = options.actedAt === undefined ? nowIso() : options.actedAt;
  const agentKeyId = keyId(options.key);
  if (agentKeyId !== m.statement.agentKeyId) F.reject('this key is not the agent named in the mandate');
  if (options.spent === undefined) F.reject('spent is required, the amount already spent under this mandate for this action, or 0');
  const decision = authorise(options.mandate, r, { at: actedAt, spent: options.spent, agentKeyId, revocations: options.revocations });
  if (!decision.allowed) {
    const e = new Error('the action is outside the mandate, ' + decision.reasons.join(', '));
    e.code = 'QMANDATE_NOT_AUTHORISED';
    e.reasons = decision.reasons;
    throw e;
  }
  let detailsDigest;
  if (options.details !== undefined && options.detailsDigest !== undefined) F.reject('give details or detailsDigest, not both');
  if (options.details !== undefined) {
    if (!(options.details instanceof Uint8Array)) F.reject('details is a Uint8Array');
    detailsDigest = F.sha3(options.details).toString('hex');
  } else if (options.detailsDigest !== undefined) {
    if (typeof options.detailsDigest !== 'string' || !/^[0-9a-f]{64}$/.test(options.detailsDigest)) F.reject('detailsDigest is 64 lowercase hex characters');
    detailsDigest = options.detailsDigest;
  } else {
    detailsDigest = F.sha3(Buffer.alloc(0)).toString('hex');
  }
  return seal('action', options.key, {
    mandateId: m.statement.mandateId,
    mandateRef: F.refOf(m),
    actionId: randomHex(16),
    agentKeyId,
    action: r.action,
    currency: r.currency,
    amount: r.amount,
    counterparty: r.counterparty,
    detailsDigest,
    actedAt,
    note: options.note === undefined ? '' : options.note,
  });
}

function revoke(options) {
  if (!options || typeof options !== 'object') F.reject('revoke needs options');
  requireSeed(options.key);
  const m = mandateOf(options.mandate);
  const principalKeyId = keyId(options.key);
  if (principalKeyId !== m.statement.principalKeyId) F.reject('only the principal that granted the mandate can revoke it');
  return seal('revoke', options.key, {
    mandateId: m.statement.mandateId,
    mandateRef: F.refOf(m),
    principalKeyId,
    revokedAt: options.revokedAt === undefined ? nowIso() : options.revokedAt,
    note: options.note === undefined ? '' : options.note,
  });
}

function kindFor(type) {
  return type === 'action' ? 'ai_agent_action' : 'record';
}

function anchorBatch(envelopes) {
  const list = Array.isArray(envelopes) ? envelopes : [envelopes];
  if (list.length === 0) F.reject('anchor needs at least one envelope');
  const parsed = list.map((e) => {
    const p = F.parse(e);
    if (p.anchor !== undefined) F.reject('an envelope is already anchored');
    if (p.signerId !== F.keyIdOf(p.publicKey)) F.reject('an envelope names a signer id that does not match its public key');
    if (!native.verify(p.publicKey, F.payload(p.type, p.statement), p.signature)) F.reject('an envelope carries a signature that does not verify');
    return p;
  });
  const kinds = new Set(parsed.map((p) => kindFor(p.type)));
  if (kinds.size !== 1) F.reject('anchor agent actions separately from mandates and revocations');
  return { list, parsed, kind: [...kinds][0] };
}

function attach(list, receipts) {
  if (!Array.isArray(receipts) || receipts.length !== list.length) throw new Error('the anchoring returned an unexpected number of receipts');
  return list.map((e, i) => Object.assign({}, e, { anchor: receipts[i] }));
}

async function anchor(envelopes, options) {
  const { list, parsed, kind } = anchorBatch(envelopes);
  if (!options || typeof options !== 'object') F.reject('anchor needs the stamping options of a funded Quantova account');
  const records = parsed.map((p) => ({ alg: 'sha3-256', digest: F.anchorDigest(p) }));
  return attach(list, await qstamp.stamp(Object.assign({}, options, { records, kind })));
}

async function complete(envelopes, pending, options) {
  const plain = (Array.isArray(envelopes) ? envelopes : [envelopes]).map((e) => {
    let c;
    try {
      c = F.plainCopy(e);
    } catch (err) {
      return F.reject('an envelope is not plain data');
    }
    if (c && typeof c === 'object' && !Array.isArray(c)) delete c.anchor;
    return c;
  });
  const { list, parsed, kind } = anchorBatch(plain);
  let p;
  try {
    p = F.plainCopy(pending);
  } catch (e) {
    F.reject('the pending stamp is not plain data');
  }
  if (!p || typeof p !== 'object' || !Array.isArray(p.records) || p.records.length !== parsed.length || String(p.kind) !== String(qstamp.KINDS[kind])) {
    F.reject('the pending stamp does not belong to these envelopes');
  }
  parsed.forEach((c, i) => {
    const r = p.records[i];
    if (!r || r.alg !== 'sha3-256' || r.digest !== F.anchorDigest(c).toString('hex')) F.reject('the pending stamp does not belong to these envelopes, or they are in another order');
  });
  return attach(list, await qstamp.complete(p, options || {}));
}

module.exports = { generateKey, publicKey, keyId, describeKey, grant, authorise, act, revoke, anchor, complete, kindFor, mandateOf, amountOf };
