// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const fs = require('fs');
const path = require('path');
const qstamp = require('@quantovainc/qstamp');
const native = require('./native');
const F = require('./format');
const Ledger = require('./ledger');

function requireProvingQstamp() {
  const dir = path.dirname(require.resolve('@quantovainc/qstamp/package.json'));
  const [major, minor] = String(require(path.join(dir, 'package.json')).version).split('.').map((n) => parseInt(n, 10));
  const released = major > 0 || (major === 0 && minor >= 3);
  const staged = fs.existsSync(path.join(dir, 'lib', 'deadline.js')) && fs.existsSync(path.join(dir, 'lib', 'finality.js'));
  if (typeof qstamp.isProven !== 'function' || !(released || staged)) {
    throw new Error('the installed Qstamp is older than 0.3.0 and cannot prove anchors');
  }
}
requireProvingQstamp();

function own(value) {
  return Object.assign(Object.create(null), value);
}

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

function seal(type, key, statement, version) {
  const v = version === undefined ? F.VERSION : version;
  const pk = publicKey(key);
  const id = F.keyIdOf(pk);
  let plain;
  try {
    plain = F.plainCopy(statement);
  } catch (e) {
    F.reject('the statement is not plain data');
  }
  const problem = F.statementProblem(type, plain, v);
  if (problem) F.reject(problem);
  statement = plain;
  const message = F.payload(type, statement, v);
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
    format: F.formatOf(type, v),
    type,
    algorithm: F.ALGORITHM,
    signer: { id, publicKey: Buffer.from(pk).toString('base64') },
    statement: JSON.parse(JSON.stringify(statement)),
    signature: Buffer.from(signature).toString('base64'),
  };
}

function grant(options) {
  if (!options || typeof options !== 'object') F.reject('grant needs options');
  options = own(options);
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
  if (!native.verify(p.publicKey, F.encoded(p), p.signature)) badMandate('the mandate signature does not verify');
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
    if (native.verify(r.publicKey, F.encoded(r), r.signature)) return true;
  }
  return false;
}

function amountOf(value, what) {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]{0,29})$/.test(value)) F.reject(what + ' is a whole number of minor units written as text');
  return BigInt(value);
}

const CLOCK_SKEW_MS = 5 * 60 * 1000;
const ENDPOINT_OPTIONS = ['network', 'rpc', 'client', 'clients', 'trustSingleEndpoint', 'trustCustomEndpoints', 'allowLoopback', 'endpointAllowList', 'clockSlackMs'];
const SWAP_TRIES = 64;
const DEADLINE_HORIZON_S = 3600;
const DEADLINE_STEPS_S = [3600, 600, 60];
const DEADLINE_MARGIN_S = 300;

function strictOf(opts) {
  if (opts.strict === undefined) return true;
  if (typeof opts.strict !== 'boolean') F.reject('strict is true or false');
  return opts.strict;
}

function endpointOptions(opts) {
  const out = Object.create(null);
  for (const k of ENDPOINT_OPTIONS) if (opts[k] !== undefined) out[k] = opts[k];
  return out;
}

async function chainClock(opts, strict) {
  if (strict !== false && strictOf(opts) && opts.trustSingleEndpoint === true) {
    F.reject('strict mode takes the time of the chain only from at least two independent endpoints and refuses trustSingleEndpoint, set strict to false to rely on one endpoint');
  }
  try {
    return await qstamp.chainTime(endpointOptions(opts));
  } catch (e) {
    const err = new Error('the chain time could not be established, so no decision was made, ' + ((e && e.message) || 'unknown error'));
    err.code = 'QMANDATE_NO_CHAIN_TIME';
    throw err;
  }
}

function decide(m, request, when, spent) {
  const reasons = [];
  const st = m.statement;
  const scope = st.scopes.find((s) => s.action === request.action);
  if (!scope) {
    reasons.push('the mandate does not permit the action ' + String(request.action).slice(0, 64));
  } else {
    if (request.currency !== scope.currency) reasons.push('the mandate permits this action only in ' + (scope.currency || 'no currency'));
    const amount = BigInt(request.amount);
    if (amount > BigInt(scope.maxPerAction)) reasons.push('the amount exceeds the limit of ' + scope.maxPerAction + ' per action');
    if (spent + amount > BigInt(scope.maxTotal)) reasons.push('the amount would take the total for this action beyond ' + scope.maxTotal);
  }
  if (st.counterparties.length > 0 && !st.counterparties.includes(request.counterparty)) reasons.push('the counterparty is not permitted by the mandate');
  if (Math.min(when.early, when.claimed) < Date.parse(st.validFrom)) reasons.push('the mandate is not yet in force');
  if (Math.max(when.late, when.claimed) > Date.parse(st.validUntil)) reasons.push('the mandate has expired');
  return { allowed: reasons.length === 0, reasons, scope: scope ? Object.assign({}, scope) : null };
}

function normaliseRequest(request) {
  if (!request || typeof request !== 'object') F.reject('the request is an object');
  request = own(request);
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

async function authorise(mandate, request, options) {
  const opts = own(options);
  const m = mandateOf(mandate);
  const r = normaliseRequest(request);
  if (opts.at !== undefined) {
    const tp = F.timeProblem(opts.at, 'at');
    if (tp) F.reject(tp);
  }
  const clock = await chainClock(opts);
  let at = new Date(clock.chainMs).toISOString();
  let when = { early: clock.early, late: clock.late, claimed: clock.chainMs };
  if (opts.at !== undefined) {
    const ms = Date.parse(opts.at);
    if (ms < clock.early - CLOCK_SKEW_MS || ms > clock.late + CLOCK_SKEW_MS) {
      F.reject('at must be within five minutes of the time of the chain, ' + at + ', a decision is never made for another time');
    }
    at = opts.at;
    when = { early: Math.min(clock.early, ms), late: Math.max(clock.late, ms), claimed: ms };
  }
  const spent = await spentOf(m, r.action, opts);
  const out = decide(m, r, when, spent);
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
  return Object.assign(out, { mandateId: m.statement.mandateId, mandateRef: F.refOf(m), at, atSupplied: opts.at !== undefined, chainTime: new Date(clock.chainMs).toISOString(), spent: spent.toString() });
}

async function spentOf(m, action, opts) {
  const given = opts.spent === undefined ? null : amountOf(opts.spent, 'spent');
  if (opts.ledger === undefined) {
    if (given === null) F.reject('give the spend ledger, or spent, the amount already spent under this mandate for this action, so a decision is never made on a total of 0 by default');
    return given;
  }
  const ref = F.refOf(m);
  const state = Ledger.parseState(await Ledger.ledgerOf(opts.ledger).read(Ledger.nameOf(ref, action)), ref, action, m.statement.agentKeyId);
  if (state === null) return given === null ? 0n : given;
  if (given !== null && given !== BigInt(state.total)) F.reject('spent ' + given + ' differs from the ' + state.total + ' the spend ledger holds for this mandate and action');
  return BigInt(state.total);
}

function deadlineFor(expiry, nowS) {
  const grid = Math.ceil((nowS + DEADLINE_HORIZON_S) / DEADLINE_HORIZON_S) * DEADLINE_HORIZON_S;
  if (grid <= expiry) return grid;
  for (const step of DEADLINE_STEPS_S) {
    const d = Math.floor(expiry / step) * step;
    if (d >= nowS + DEADLINE_MARGIN_S) return d;
  }
  return expiry;
}

async function act(options) {
  if (!options || typeof options !== 'object') F.reject('act needs options');
  options = own(options);
  requireSeed(options.key);
  const m = mandateOf(options.mandate);
  const r = normaliseRequest(options);
  const agentKeyId = keyId(options.key);
  if (agentKeyId !== m.statement.agentKeyId) F.reject('this key is not the agent named in the mandate');
  if (options.ledger === undefined) F.reject('ledger is required, the folder or store of the spend ledger that numbers the actions of each scope and keeps their running total, so concurrent actions can never exceed the total limit');
  const store = Ledger.ledgerOf(options.ledger);
  const opening = options.spent === undefined ? null : amountOf(options.spent, 'spent');
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
  if (options.actedAt !== undefined) {
    const tp = F.timeProblem(options.actedAt, 'actedAt');
    if (tp) F.reject(tp);
  }
  const note = options.note === undefined ? '' : options.note;
  const revoked = revokedBy(m, options.revocations);
  const clock = await chainClock(options);
  const actedAt = options.actedAt === undefined ? new Date(clock.chainMs).toISOString() : options.actedAt;
  const claimed = Date.parse(actedAt);
  if (Math.abs(claimed - clock.chainMs) > CLOCK_SKEW_MS) F.reject('actedAt must be within five minutes of the time of the chain, ' + new Date(clock.chainMs).toISOString());
  const ref = F.refOf(m);
  const name = Ledger.nameOf(ref, r.action);
  for (let attempt = 0; attempt < SWAP_TRIES; attempt += 1) {
    const text = await store.read(name);
    const prev = Ledger.parseState(text, ref, r.action, agentKeyId);
    if (prev && opening !== null && opening !== BigInt(prev.total)) {
      F.reject('spent ' + opening + ' differs from the ' + prev.total + ' the spend ledger holds for this mandate and action');
    }
    const spent = prev ? BigInt(prev.total) : (opening === null ? 0n : opening);
    const decision = decide(m, r, { early: clock.early, late: clock.late, claimed }, spent);
    if (revoked) {
      decision.allowed = false;
      decision.reasons.push('the principal has revoked this mandate');
    }
    if (!decision.allowed) {
      const e = new Error('the action is outside the mandate, ' + decision.reasons.join(', '));
      e.code = 'QMANDATE_NOT_AUTHORISED';
      e.reasons = decision.reasons;
      e.spent = spent.toString();
      throw e;
    }
    const sequence = prev ? (BigInt(prev.sequence) + 1n).toString() : '1';
    const total = (spent + BigInt(r.amount)).toString();
    const env = seal('action', options.key, {
      mandateId: m.statement.mandateId,
      mandateRef: ref,
      actionId: randomHex(16),
      agentKeyId,
      action: r.action,
      currency: r.currency,
      amount: r.amount,
      counterparty: r.counterparty,
      detailsDigest,
      actedAt,
      sequence,
      previousRef: prev ? prev.lastRef : '',
      total,
      note,
    }, F.ACTION_VERSION);
    const lastRef = F.refOf(F.parse(env));
    const next = Ledger.encodeState({ mandateRef: ref, action: r.action, agentKeyId, sequence, total, lastRef });
    const entry = { name: Ledger.journalName(ref, r.action, sequence, lastRef), text: JSON.stringify(env) + '\n' };
    if (await store.compareAndSwap(name, text, next, entry)) return env;
  }
  const e = new Error('the spend ledger kept changing under concurrent actions, nothing was signed, try again');
  e.code = 'QMANDATE_LEDGER';
  throw e;
}

async function ledgerActions(ledger, mandate, action) {
  const m = mandateOf(mandate);
  if (typeof action !== 'string' || !/^[a-z][a-z0-9_.]{0,63}$/.test(action)) F.reject('action is a lowercase name such as payment.send');
  const store = Ledger.ledgerOf(ledger);
  if (typeof store.readJournal !== 'function') F.reject('this spend ledger store keeps no journal of signed actions, keep the entry given to compareAndSwap in the same transaction as the new state and give it readJournal so that actions can be recovered');
  const ref = F.refOf(m);
  const name = Ledger.nameOf(ref, action);
  const agentKeyId = m.statement.agentKeyId;
  const state = Ledger.parseState(typeof store.recover === 'function' ? await store.recover(name, agentKeyId) : await store.read(name), ref, action, agentKeyId);
  if (state === null) return { mandateRef: ref, action, sequence: '0', total: '0', actions: [], complete: true };
  const actions = [];
  let want = state.lastRef;
  for (let seq = BigInt(state.sequence); seq >= 1n; seq -= 1n) {
    const text = await store.readJournal(Ledger.journalName(ref, action, seq.toString(), want));
    if (text === null || text === undefined) break;
    const entry = Ledger.entryOf(text, ref, action);
    const st = entry.parsed.statement;
    if (entry.ref !== want || entry.sequence !== seq.toString() || st.mandateId !== m.statement.mandateId || entry.parsed.signerId !== m.statement.agentKeyId) throw Ledger.journalDamaged(ref, action);
    if (actions.length === 0 && entry.total !== state.total) throw Ledger.journalDamaged(ref, action);
    actions.push(entry.envelope);
    want = entry.previousRef;
  }
  actions.reverse();
  return { mandateRef: ref, action, sequence: state.sequence, total: state.total, actions, complete: String(actions.length) === state.sequence };
}

function revoke(options) {
  if (!options || typeof options !== 'object') F.reject('revoke needs options');
  options = own(options);
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

function untilOf(m) {
  return Math.floor(Date.parse(m.statement.validUntil) / 1000);
}

function anchorBatch(envelopes, mandate) {
  const list = Array.isArray(envelopes) ? envelopes : [envelopes];
  if (list.length === 0) F.reject('anchor needs at least one envelope');
  const parsed = list.map((e) => {
    const p = F.parse(e);
    if (p.anchor !== undefined) F.reject('an envelope is already anchored');
    if (p.signerId !== F.keyIdOf(p.publicKey)) F.reject('an envelope names a signer id that does not match its public key');
    if (!native.verify(p.publicKey, F.encoded(p), p.signature)) F.reject('an envelope carries a signature that does not verify');
    return p;
  });
  const kinds = new Set(parsed.map((p) => kindFor(p.type)));
  if (kinds.size !== 1) F.reject('anchor agent actions separately from mandates and revocations');
  const kind = [...kinds][0];
  let until;
  if (kind === kindFor('action')) {
    if (mandate === undefined) F.reject('anchoring agent actions needs the mandate they rely on, so the chain refuses the anchor once the mandate has expired');
    const m = mandateOf(mandate);
    const ref = F.refOf(m);
    for (const p of parsed) {
      if (p.statement.mandateRef !== ref || p.statement.mandateId !== m.statement.mandateId || p.statement.agentKeyId !== m.statement.agentKeyId) {
        F.reject('every action in one anchor must rely on the mandate given');
      }
    }
    until = untilOf(m);
  }
  return { list, parsed, kind, until };
}

function attach(list, receipts) {
  if (!Array.isArray(receipts) || receipts.length !== list.length) throw new Error('the anchoring returned an unexpected number of receipts');
  return list.map((e, i) => Object.assign({}, e, { anchor: receipts[i] }));
}

async function anchor(envelopes, options) {
  if (!options || typeof options !== 'object') F.reject('anchor needs the stamping options of a funded Quantova account');
  options = own(options);
  const { list, parsed, kind, until } = anchorBatch(envelopes, options.mandate);
  const records = parsed.map((p) => ({ alg: 'sha3-256', digest: F.anchorDigest(p) }));
  const stampOptions = Object.assign(own(options), { records, kind });
  delete stampOptions.mandate;
  delete stampOptions.strict;
  if (until !== undefined) {
    const clock = await chainClock(options, false);
    stampOptions.until = deadlineFor(until, Math.ceil(clock.late / 1000));
  } else {
    delete stampOptions.until;
  }
  return attach(list, await qstamp.stamp(stampOptions));
}

async function complete(envelopes, pending, options) {
  const opts = own(options);
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
  const { list, parsed, kind, until } = anchorBatch(plain, opts.mandate);
  let p;
  try {
    p = F.plainCopy(pending);
  } catch (e) {
    F.reject('the pending stamp is not plain data');
  }
  if (!p || typeof p !== 'object' || !Array.isArray(p.records) || p.records.length !== parsed.length || String(p.kind) !== String(qstamp.KINDS[kind])) {
    F.reject('the pending stamp does not belong to these envelopes');
  }
  if (until === undefined ? p.until !== undefined : (!Number.isSafeInteger(p.until) || p.until > until)) {
    F.reject('the pending stamp does not carry a deadline at or before the expiry of the mandate these actions rely on');
  }
  parsed.forEach((c, i) => {
    const r = p.records[i];
    if (!r || r.alg !== 'sha3-256' || r.digest !== F.anchorDigest(c).toString('hex')) F.reject('the pending stamp does not belong to these envelopes, or they are in another order');
  });
  const completeOptions = own(opts);
  delete completeOptions.mandate;
  delete completeOptions.strict;
  return attach(list, await qstamp.complete(p, completeOptions));
}

module.exports = { own, generateKey, publicKey, keyId, describeKey, grant, authorise, act, ledgerActions, revoke, anchor, complete, kindFor, mandateOf, amountOf, untilOf, chainClock, endpointOptions, strictOf, deadlineFor };
