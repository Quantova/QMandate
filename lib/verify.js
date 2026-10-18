// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const qstamp = require('@quantovainc/qstamp');
const native = require('./native');
const F = require('./format');
const { kindFor, untilOf, chainClock, strictOf } = require('./mandate');

const CLOCK_SKEW_MS = 5 * 60 * 1000;
const LIST_MAX = 500;
const PASS = ['rpc', 'client', 'clients', 'contract', 'trustCustomContract', 'trustSingleEndpoint', 'trustCustomEndpoints', 'allowLoopback', 'endpointAllowList', 'expectedSender'];
const CLAIMED_TIME = { mandate: 'issuedAt', action: 'actedAt', revoke: 'revokedAt' };

function plain(text) {
  return String(text).replace(/:\s+/g, ', ').replace(/;\s*/g, ', ').slice(0, 300);
}

function statusOf(checks) {
  const open = checks.filter((c) => !c.ok);
  if (open.some((c) => !c.transport && !c.indeterminate && !c.unproven)) return 'invalid';
  if (open.some((c) => c.transport || c.indeterminate)) return 'indeterminate';
  if (open.length) return 'unproven';
  return 'valid';
}

function recorder() {
  const checks = [];
  const add = (name, ok, detail, transport, indeterminate, unproven) => checks.push({ name, ok: !!ok, detail: plain(detail), transport: !!transport, indeterminate: !!indeterminate, unproven: !!unproven });
  return { checks, add };
}

const SELF_ASSERTED = 'the agent label and the counterparty are text written by the principal and the agent, they are not verified identities, bind a counterparty to a key with counterpartyKeyId';
const LEGACY_TOTAL = 'this action uses the older format ' + F.FORMAT + ', which carries no sequence or signed running total, so its running total is checked only against the earlier actions supplied and cannot be proven complete';

function provenOf(result) {
  if (!result || (result.status !== 'valid' && result.status !== 'unproven')) return false;
  return typeof qstamp.isProven === 'function' && qstamp.isProven(result) === true;
}

function finish(checks, extra) {
  const status = statusOf(checks);
  return Object.assign({ valid: status === 'valid', status }, extra, { checks: checks.map((c) => Object.assign({}, c)) });
}

function anchorOptions(opts) {
  const out = {};
  for (const k of PASS) if (opts[k] !== undefined) out[k] = opts[k];
  return out;
}

function signatureOk(p) {
  return p.signerId === F.keyIdOf(p.publicKey) && native.verify(p.publicKey, F.encoded(p), p.signature);
}

function identity(p) {
  return F.anchorDigest(p).toString('hex');
}

function strictlyAfter(a, b) {
  if (a.chain === b.chain) {
    if (a.height !== b.height) return a.height > b.height;
    return a.tx === b.tx && a.index > b.index;
  }
  return a.ms > b.ms;
}

function earlier(a, b) {
  if (!a) return b;
  if (!b) return a;
  return strictlyAfter(a, b) ? b : a;
}

function iso(pos) {
  return new Date(pos.ms).toISOString();
}

const NET = Symbol('endpoints');
const DEFAULT_ANCHOR_DELAY_S = 24 * 60 * 60;
const ANCHOR_DELAY_MAX_S = 366 * 24 * 60 * 60;

function delayOf(opts) {
  if (opts.maxAnchorDelay === undefined) return DEFAULT_ANCHOR_DELAY_S * 1000;
  const v = opts.maxAnchorDelay;
  if (typeof v !== 'number' || !Number.isSafeInteger(v) || v < 60 || v > ANCHOR_DELAY_MAX_S) F.reject('maxAnchorDelay is a whole number of seconds from 60 to ' + ANCHOR_DELAY_MAX_S);
  return v * 1000;
}

function noteEndpoints(opts, result) {
  const net = opts[NET];
  if (!net || !(result.endpoints || []).length) return;
  for (const e of result.endpoints) net.endpoints.add(e);
  net.official = net.official !== false && result.officialEndpoints === true;
}

async function checkAnchor(p, opts, add, label, until) {
  const receipt = p.anchor;
  if (receipt === undefined) return null;
  try {
    if (receipt === null || typeof receipt !== 'object' || Array.isArray(receipt)) {
      add(label, false, 'the anchor is not a Qstamp receipt');
      return null;
    }
    if (until !== undefined && (!Number.isSafeInteger(receipt.until) || receipt.until > until)) {
      add(label, false, 'the action was not anchored through the stamp entry that makes the chain refuse it after the mandate expires');
      return null;
    }
    if (receipt.kind !== String(qstamp.KINDS[kindFor(p.type)])) {
      add(label, false, 'the anchor was not recorded under the kind for ' + (p.type === 'action' ? 'an action' : 'a ' + p.type));
      return null;
    }
    const result = await qstamp.verify(receipt, Object.assign(anchorOptions(opts), { digest: F.anchorDigest(p) }));
    noteEndpoints(opts, result);
    const confirmed = result.status === 'valid' || result.status === 'unproven';
    const proven = provenOf(result);
    for (const c of result.checks) {
      if (proven && !c.ok) continue;
      add(label + ' ' + c.name, c.ok, c.detail, confirmed ? false : c.transport, false, confirmed && !c.ok);
    }
    if (!confirmed) return null;
    if (!proven) {
      const strict = strictOf(opts);
      if (!result.checks.some((c) => !c.ok)) add(label + ' proof', false, 'the anchor was confirmed only by endpoints that are not pinned independent operators of the network, so it is not proven' + (strict ? ' and is treated as not anchored' : ''), false, false, true);
      if (strict) return null;
    }
    const position = {
      ms: receipt.anchor.time * 1000,
      height: receipt.anchor.height,
      tx: receipt.anchor.tx,
      index: receipt.proof.index,
      chain: receipt.chain.id + '/' + receipt.chain.genesis,
    };
    const claimed = Date.parse(p.statement[CLAIMED_TIME[p.type]]);
    if (claimed > position.ms + CLOCK_SKEW_MS) {
      add(label + ' time', false, 'the claimed time is later than the anchor time ' + iso(position));
      return null;
    }
    const delayMs = delayOf(opts);
    if (position.ms - claimed > delayMs) {
      add(label + ' time', false, 'anchored at ' + iso(position) + ', more than ' + Math.round(delayMs / 3600000) + ' hours after its claimed time, so the claimed time is not proven', false, true);
      return position;
    }
    if (opts.at !== undefined && position.ms > Date.parse(opts.at)) {
      add(label + ' time', false, 'anchored at ' + iso(position) + ', after the time given for verification, so it was not proven at that time', false, true);
      return position;
    }
    add(label + ' time', true, 'recorded by ' + iso(position));
    return position;
  } catch (e) {
    add(label, false, 'the anchor could not be checked, ' + ((e && e.message) || 'unknown error'));
    return null;
  }
}

async function earliestOf(copies, opts, until) {
  let best = null;
  let problem = null;
  for (const c of copies) {
    if (c.anchor === undefined) continue;
    const sub = recorder();
    const pos = await checkAnchor(c, opts, sub.add, 'copy', until);
    if (pos) best = earlier(best, pos);
    else problem = problem || sub.checks.find((x) => !x.ok) || { detail: 'an anchor could not be confirmed', transport: false };
  }
  return { position: best, problem };
}

function groupByIdentity(list) {
  const groups = new Map();
  for (const p of list) {
    const id = identity(p);
    if (!groups.has(id)) groups.set(id, []);
    groups.get(id).push(p);
  }
  return groups;
}

function expectedPrincipal(opts) {
  if (opts.principalKeyId !== undefined && opts.principalPublicKey !== undefined) F.reject('give principalKeyId or principalPublicKey, not both');
  if (opts.principalKeyId !== undefined) {
    if (typeof opts.principalKeyId !== 'string' || !/^[0-9a-f]{64}$/.test(opts.principalKeyId)) F.reject('principalKeyId is 64 lowercase hex characters');
    return opts.principalKeyId;
  }
  if (opts.principalPublicKey !== undefined) {
    let pk = opts.principalPublicKey;
    if (typeof pk === 'string') {
      const raw = Buffer.from(pk, 'base64');
      if (raw.toString('base64') !== pk) F.reject('principalPublicKey is canonical base64');
      pk = raw;
    }
    return F.keyIdOf(pk);
  }
  F.reject('the expected principal is required, give principalKeyId or principalPublicKey so an attacker cannot substitute a mandate of its own');
}

function listOption(opts, name) {
  const list = opts[name];
  if (list === undefined) return undefined;
  if (!Array.isArray(list) || list.length > LIST_MAX) F.reject(name + ' is a list of at most ' + LIST_MAX + ' envelopes');
  return list;
}

async function mandateCore(envelope, opts, add, prefix) {
  let m;
  try {
    m = F.parse(envelope);
  } catch (e) {
    add(prefix + 'format', false, e.message);
    return null;
  }
  if (m.type !== 'mandate') {
    add(prefix + 'format', false, (m.type === 'action' ? 'an action' : 'a ' + m.type) + ' envelope was given where a mandate was expected');
    return null;
  }
  add(prefix + 'format', true, 'a well formed mandate');
  const sigOk = signatureOk(m);
  add(prefix + 'signature', sigOk, sigOk ? 'the ML-DSA-65 signature of the principal is valid' : 'the mandate signature does not verify');
  const bound = m.signerId === m.statement.principalKeyId;
  add(prefix + 'principal', bound, bound ? 'signed by the principal it names' : 'signed by a key other than the principal it names');
  const expected = expectedPrincipal(opts);
  const trusted = expected === m.statement.principalKeyId;
  add(prefix + 'expected principal', trusted, trusted ? 'granted by the expected principal' : 'granted by a different principal than expected');
  if (!sigOk || !bound) return { m, ok: false, trusted, position: null, ref: null };
  const position = await checkAnchor(m, opts, add, prefix + 'anchor');
  return { m, ok: true, trusted, position, ref: F.refOf(m) };
}

async function revocationOf(core, opts, add, prefix) {
  const list = listOption(opts, 'revocations');
  if (list === undefined) {
    add(prefix + 'revocations', false, 'no revocation list was supplied, so it is unknown whether the mandate was withdrawn', false, true);
    return { earliest: null, unproven: false, checked: false };
  }
  const valid = [];
  for (const [i, env] of list.entries()) {
    const name = prefix + 'revocation ' + (i + 1);
    let r;
    try {
      r = F.parse(env);
    } catch (e) {
      add(name, true, 'ignored, it is not a well formed envelope');
      continue;
    }
    if (r.type !== 'revoke' || r.statement.mandateId !== core.m.statement.mandateId || r.statement.principalKeyId !== core.m.statement.principalKeyId) {
      add(name, true, 'ignored, it concerns another mandate');
      continue;
    }
    if (!signatureOk(r) || r.signerId !== core.m.statement.principalKeyId) {
      add(name, true, 'ignored, it is not signed by the principal of this mandate');
      continue;
    }
    valid.push(r);
  }
  let earliest = null;
  let unproven = false;
  for (const copies of groupByIdentity(valid).values()) {
    const { position } = await earliestOf(copies, opts);
    if (position) earliest = earlier(earliest, position);
    else unproven = true;
  }
  if (valid.length) add(prefix + 'revocations', true, earliest ? 'the principal revoked this mandate at ' + iso(earliest) : 'the principal revoked this mandate, the revocation time is not yet proven');
  else add(prefix + 'revocations', true, 'no revocation of this mandate was supplied');
  return { earliest, unproven, checked: true };
}

async function verifyMandate(envelope, opts) {
  const { checks, add } = recorder();
  const core = await mandateCore(envelope, opts, add, '');
  if (!core) return finish(checks, { type: null });
  const requireAnchor = opts.requireAnchor !== false;
  if (core.ok && core.m.anchor === undefined) {
    if (requireAnchor) add('anchor', false, 'the mandate is not anchored, so its time is only the claim of the principal', false, true);
    else add('anchor', true, 'not anchored');
  }
  let rev = { earliest: null, unproven: false, checked: false };
  if (core.ok) {
    rev = await revocationOf(core, opts, add, '');
    if (rev.earliest) add('in force', false, 'the mandate was revoked');
    else if (rev.unproven) add('in force', false, 'a revocation exists whose time is not yet proven', false, true);
    if (opts.at !== undefined) {
      const tp = F.timeProblem(opts.at, 'at');
      if (tp) F.reject(tp);
    }
    let early = null;
    let late = null;
    if (opts.at !== undefined) {
      early = Date.parse(opts.at);
      late = early;
    } else {
      try {
        const clock = await chainClock(opts);
        early = clock.early;
        late = clock.late;
      } catch (e) {
        add('in force', false, 'the current time could not be confirmed by the chain, so it is unknown whether the mandate is in force, ' + ((e && e.message) || 'unknown error'), true);
      }
    }
    if (early !== null && early < Date.parse(core.m.statement.validFrom)) add('in force', false, 'the mandate is not in force until ' + core.m.statement.validFrom);
    if (late !== null && late > Date.parse(core.m.statement.validUntil)) add('in force', false, 'the mandate expired at ' + core.m.statement.validUntil);
  }
  return finish(checks, {
    type: 'mandate',
    mandateId: core.m.statement.mandateId,
    mandateRef: core.ref,
    principalKeyId: core.m.statement.principalKeyId,
    agentKeyId: core.m.statement.agentKeyId,
    agentLabel: core.m.statement.agentLabel,
    scopes: core.m.statement.scopes,
    counterparties: core.m.statement.counterparties,
    validFrom: core.m.statement.validFrom,
    validUntil: core.m.statement.validUntil,
    anchoredAt: core.position ? iso(core.position) : null,
    revokedAt: rev.earliest ? iso(rev.earliest) : null,
    principalTrusted: core.trusted,
    revocationChecked: rev.checked,
    notes: ['the agent label and the counterparties are text written by the principal, they are not verified identities'],
  });
}

function inScope(p, mst, st) {
  if (p.type !== 'action' || p.statement.mandateId !== mst.mandateId || p.statement.action !== st.action || p.statement.currency !== st.currency) return false;
  return p.signerId === mst.agentKeyId && p.statement.agentKeyId === mst.agentKeyId && signatureOk(p);
}

function chainOf(a, core, priors, add) {
  const st = a.statement;
  const mst = core.m.statement;
  const byRef = new Map([[F.refOf(a), a]]);
  const legacy = new Map();
  for (const env of priors) {
    let p;
    try {
      p = F.parse(env);
    } catch (e) {
      continue;
    }
    if (!inScope(p, mst, st)) continue;
    if (p.version !== F.ACTION_VERSION) legacy.set(identity(p), BigInt(p.statement.amount));
    else if (p.statement.mandateRef === core.ref) byRef.set(F.refOf(p), p);
  }
  const mine = BigInt(st.sequence);
  const bySeq = new Map();
  for (const p of byRef.values()) bySeq.set(p.statement.sequence, (bySeq.get(p.statement.sequence) || 0) + 1);
  for (const [seq, n] of bySeq) {
    if (n > 1 && BigInt(seq) <= mine) {
      add('sequence', false, 'the agent signed ' + n + ' different actions numbered ' + seq + ' for ' + st.action + ' under this mandate, so the record of spending forks and its total cannot be trusted');
      return { complete: false, broken: true };
    }
  }
  let cur = a;
  for (let steps = 0; cur.statement.sequence !== '1'; steps += 1) {
    const prev = byRef.get(cur.statement.previousRef);
    const want = BigInt(cur.statement.sequence) - 1n;
    if (!prev || steps > byRef.size) {
      add('sequence', false, 'action ' + want + ' of ' + st.action + ' under this mandate, which action ' + cur.statement.sequence + ' follows, was not supplied, so the running total cannot be proven', false, true);
      return { complete: false, broken: false };
    }
    if (BigInt(prev.statement.sequence) !== want) {
      add('sequence', false, 'action ' + cur.statement.sequence + ' names a previous action numbered ' + prev.statement.sequence);
      return { complete: false, broken: true };
    }
    if (BigInt(prev.statement.total) + BigInt(cur.statement.amount) !== BigInt(cur.statement.total)) {
      add('sequence', false, 'the running total of action ' + cur.statement.sequence + ' is not the total of action ' + want + ' plus its amount');
      return { complete: false, broken: true };
    }
    cur = prev;
  }
  const opening = BigInt(cur.statement.total) - BigInt(cur.statement.amount);
  let older = 0n;
  for (const v of legacy.values()) older += v;
  if (older > opening) {
    add('sequence', false, 'earlier actions in the older format add up to ' + older + ', more than the opening total ' + opening + ' the record of spending started from');
    return { complete: false, broken: true };
  }
  const extra = opening > 0n ? ', starting from an opening total of ' + opening + ' for earlier actions in the older format, whose completeness cannot be proven' : '';
  add('sequence', true, 'action ' + st.sequence + ' follows an unbroken record of ' + st.action + ' back to the first action under this mandate' + extra);
  return { complete: true, broken: false };
}

function expectedCounterparty(opts) {
  if (opts.counterpartyKeyId !== undefined && opts.counterpartyPublicKey !== undefined) F.reject('give counterpartyKeyId or counterpartyPublicKey, not both');
  if (opts.counterpartyKeyId !== undefined) {
    if (typeof opts.counterpartyKeyId !== 'string' || !/^[0-9a-f]{64}$/.test(opts.counterpartyKeyId)) F.reject('counterpartyKeyId is 64 lowercase hex characters');
    return opts.counterpartyKeyId;
  }
  if (opts.counterpartyPublicKey !== undefined) {
    let pk = opts.counterpartyPublicKey;
    if (typeof pk === 'string') {
      const raw = Buffer.from(pk, 'base64');
      if (raw.toString('base64') !== pk) F.reject('counterpartyPublicKey is canonical base64');
      pk = raw;
    }
    return F.keyIdOf(pk);
  }
  return null;
}

async function verifyAction(envelope, opts) {
  const { checks, add } = recorder();
  let a;
  try {
    a = F.parse(envelope);
  } catch (e) {
    add('format', false, e.message);
    return finish(checks, { type: null });
  }
  if (a.type !== 'action') {
    add('format', false, 'a ' + a.type + ' envelope is not an agent action');
    return finish(checks, { type: a.type });
  }
  add('format', true, 'a well formed agent action');
  const sigOk = signatureOk(a);
  add('signature', sigOk, sigOk ? 'the ML-DSA-65 signature of the agent is valid' : 'the action signature does not verify');
  const st = a.statement;
  const agentBound = a.signerId === st.agentKeyId;
  add('agent', agentBound, agentBound ? 'signed by the agent it names' : 'signed by a key other than the agent it names');

  if (opts.mandate === undefined) F.reject('the mandate the action relies on is required');
  const core = await mandateCore(opts.mandate, opts, add, 'mandate ');
  const base = { type: 'action', format: F.formatOf('action', a.version), actionId: st.actionId, mandateId: st.mandateId, agentKeyId: st.agentKeyId, action: st.action, currency: st.currency, amount: st.amount, counterparty: st.counterparty, actedAt: st.actedAt };
  if (!core || !core.ok || !sigOk || !agentBound) return finish(checks, Object.assign(base, { principalTrusted: !!(core && core.trusted) }));
  const mst = core.m.statement;
  const requireAnchor = opts.requireAnchor !== false;

  const bound = st.mandateRef === core.ref && st.mandateId === mst.mandateId && st.agentKeyId === mst.agentKeyId;
  add('mandate binding', bound, bound ? 'the action relies on this exact mandate and its agent' : 'the action does not belong to this mandate or its agent');

  const scope = mst.scopes.find((s) => s.action === st.action);
  if (!scope) {
    add('scope', false, 'the mandate does not permit the action ' + st.action);
  } else {
    add('scope', true, 'the mandate permits ' + st.action);
    const sameCurrency = st.currency === scope.currency;
    add('currency', sameCurrency, sameCurrency ? 'in the permitted currency' : 'in a currency the mandate does not permit');
    const within = BigInt(st.amount) <= BigInt(scope.maxPerAction);
    add('limit per action', within, within ? 'within the limit of ' + scope.maxPerAction : 'above the limit of ' + scope.maxPerAction);
  }
  const cpOk = mst.counterparties.length === 0 || mst.counterparties.includes(st.counterparty);
  add('counterparty', cpOk, cpOk ? (mst.counterparties.length ? 'a permitted counterparty' : 'the mandate permits any counterparty') : 'a counterparty the mandate does not permit');

  let detailsChecked = false;
  const given = ['details', 'detailsDigest'].filter((k) => opts[k] !== undefined);
  if (given.length > 1) F.reject('give details or detailsDigest, not both');
  if (given.length === 1) {
    let d;
    if (opts.details !== undefined) {
      if (!(opts.details instanceof Uint8Array)) F.reject('details is a Uint8Array');
      d = F.sha3(opts.details).toString('hex');
    } else {
      if (typeof opts.detailsDigest !== 'string' || !/^[0-9a-f]{64}$/.test(opts.detailsDigest)) F.reject('detailsDigest is 64 lowercase hex characters');
      d = opts.detailsDigest;
    }
    detailsChecked = true;
    add('details', d === st.detailsDigest, d === st.detailsDigest ? 'the private details match the signed fingerprint' : 'the details differ from those the agent signed');
  }

  const until = untilOf(core.m);
  const actionPos = await checkAnchor(a, opts, add, 'anchor', until);
  if (a.anchor === undefined) {
    if (requireAnchor) add('anchor', false, 'the action is not anchored, so its time is only the claim of the agent', false, true);
    else add('anchor', true, 'not anchored, the action time is the claim of the agent');
  }
  const fromMs = Math.floor(Date.parse(mst.validFrom) / 1000) * 1000;
  const untilMs = Date.parse(mst.validUntil);
  const actedMs = Date.parse(st.actedAt);
  const effectiveMs = actionPos ? actionPos.ms : actedMs;
  const inWindow = effectiveMs >= fromMs && effectiveMs <= untilMs && actedMs >= Date.parse(mst.validFrom) && actedMs <= untilMs;
  add('validity', inWindow, inWindow ? 'within the period of the mandate' : 'outside the period of the mandate');

  if (core.m.anchor === undefined) {
    if (requireAnchor) add('mandate anchor', false, 'the mandate is not anchored, so it cannot be shown to predate the action', false, true);
  } else if (core.position && actionPos) {
    const ordered = !strictlyAfter(core.position, actionPos);
    add('authority first', ordered, ordered ? 'the mandate was recorded before the action' : 'the mandate was recorded after the action');
  } else if (core.position && !actionPos && a.anchor === undefined) {
    const ordered = actedMs >= Math.floor(core.position.ms / 1000) * 1000;
    add('authority first', ordered, ordered ? 'the action claims a time after the mandate was recorded' : 'the action claims a time before the mandate was recorded');
  }

  const rev = await revocationOf(core, opts, add, '');
  if (rev.earliest) {
    if (!actionPos) add('revocation', false, 'the mandate was revoked and this action has no anchor proving it came first', false, true);
    else if (!strictlyAfter(rev.earliest, actionPos)) add('revocation', false, 'the mandate was revoked before this action was recorded');
    else add('revocation', true, 'the mandate was revoked only after this action was recorded');
  } else if (rev.unproven) {
    add('revocation', false, 'a revocation exists whose time is not yet proven', false, true);
  }

  let totalChecked = false;
  let totalProven = false;
  let spent = null;
  const notes = [SELF_ASSERTED];
  const metered = scope && scope.currency !== '';
  const priors = listOption(opts, 'priorActions');
  const reusedId = priors !== undefined && priors.some((env) => {
    let p;
    try {
      p = F.parse(env);
    } catch (e) {
      return false;
    }
    return inScope(p, mst, st) && p.statement.actionId === st.actionId && identity(p) !== identity(a);
  });
  if (reusedId) add('action id', false, 'the agent used this action id for a different action');
  if (a.version !== F.ACTION_VERSION) notes.push(LEGACY_TOTAL);
  if (!metered) {
    add('total', true, 'the action carries no amount');
  } else if (a.version === F.ACTION_VERSION) {
    const signed = BigInt(st.total);
    spent = signed - BigInt(st.amount);
    if (signed > BigInt(scope.maxTotal)) {
      add('total', false, 'the running total ' + signed + ' the agent signed exceeds ' + scope.maxTotal);
    } else if (priors === undefined) {
      add('total', false, 'earlier actions under this mandate were not supplied, so the signed running total ' + signed + ' cannot be shown complete', false, true);
    } else {
      totalChecked = true;
      const chain = chainOf(a, core, priors, add);
      totalProven = chain.complete;
      if (chain.complete) add('total', true, 'the running total ' + signed + ' is within ' + scope.maxTotal + ' and follows an unbroken record of every earlier action of this scope');
      else if (chain.broken) add('total', false, 'the running total ' + signed + ' rests on a broken record of spending');
      else add('total', false, 'the running total ' + signed + ' is within ' + scope.maxTotal + ' but the record of earlier actions is incomplete', false, true);
    }
  } else if (priors === undefined) {
    add('total', false, 'earlier actions under this mandate were not supplied, so the running total is unknown', false, true);
  } else {
    totalChecked = true;
    spent = 0n;
    const self = identity(a);
    const candidates = [];
    for (const env of priors) {
      let p;
      try {
        p = F.parse(env);
      } catch (e) {
        continue;
      }
      if (!inScope(p, mst, st) || identity(p) === self) continue;
      candidates.push(p);
    }
    let unproven = 0;
    for (const copies of groupByIdentity(candidates).values()) {
      if (!actionPos) {
        spent += BigInt(copies[0].statement.amount);
        continue;
      }
      const { position } = await earliestOf(copies, opts, until);
      if (!position) {
        unproven += 1;
        continue;
      }
      if (strictlyAfter(position, actionPos)) continue;
      spent += BigInt(copies[0].statement.amount);
    }
    const total = spent + BigInt(st.amount);
    const ok = total <= BigInt(scope.maxTotal);
    if (!ok) add('total', false, 'the running total ' + total + ' exceeds ' + scope.maxTotal);
    else if (unproven) add('total', false, 'the running total ' + total + ' is within ' + scope.maxTotal + ' but ' + unproven + ' earlier action has no proven time', false, true);
    else if (opts.acceptLegacyActions !== true) add('total', false, 'the running total ' + total + ' of the earlier actions supplied is within ' + scope.maxTotal + ', but this action uses the older format ' + F.FORMAT + ', which cannot prove that no earlier action was left out, so it is accepted only with acceptLegacyActions', false, true);
    else add('total', true, 'the running total ' + total + ' of the earlier actions supplied is within ' + scope.maxTotal + ', the older format cannot prove that no earlier action was left out');
  }

  const cpKey = expectedCounterparty(opts);
  if (cpKey !== null) {
    const same = st.counterparty === 'key ' + cpKey;
    add('counterparty key', same, same ? 'the counterparty is named by the expected key' : 'the counterparty is not named by the expected key');
  }

  return finish(checks, Object.assign(base, {
    principalKeyId: mst.principalKeyId,
    anchoredAt: actionPos ? iso(actionPos) : null,
    mandateAnchoredAt: core.position ? iso(core.position) : null,
    principalTrusted: core.trusted,
    detailsChecked,
    totalChecked,
    totalProven,
    spentBefore: spent === null ? null : spent.toString(),
    sequence: a.version === F.ACTION_VERSION ? st.sequence : null,
    revocationChecked: rev.checked,
    counterpartyBound: cpKey !== null && st.counterparty === 'key ' + cpKey,
    notes,
  }));
}

async function verifyRevoke(envelope, opts) {
  const { checks, add } = recorder();
  let r;
  try {
    r = F.parse(envelope);
  } catch (e) {
    add('format', false, e.message);
    return finish(checks, { type: null });
  }
  if (r.type !== 'revoke') {
    add('format', false, (r.type === 'action' ? 'an action' : 'a ' + r.type) + ' envelope was given where a revocation was expected');
    return finish(checks, { type: r.type });
  }
  add('format', true, 'a well formed mandate revocation');
  const expected = expectedPrincipal(opts);
  if (opts.mandate === undefined) F.reject('the mandate the revocation withdraws is required');
  const sigOk = signatureOk(r);
  add('signature', sigOk, sigOk ? 'the ML-DSA-65 signature of the principal is valid' : 'the revocation signature does not verify');
  const bound = r.signerId === r.statement.principalKeyId;
  add('principal', bound, bound ? 'signed by the principal it names' : 'signed by a key other than the principal it names');
  const trusted = expected === r.statement.principalKeyId;
  add('expected principal', trusted, trusted ? 'revoked by the expected principal' : 'revoked by a different principal than expected');
  const core = await mandateCore(opts.mandate, opts, add, 'mandate ');
  if (core && core.ok) {
    const matches = r.statement.mandateRef === core.ref && r.statement.mandateId === core.m.statement.mandateId && r.statement.principalKeyId === core.m.statement.principalKeyId;
    add('mandate binding', matches, matches ? 'the revocation withdraws this exact mandate' : 'the revocation does not belong to this mandate');
  }
  const pos = sigOk && bound ? await checkAnchor(r, opts, add, 'anchor') : null;
  if (sigOk && bound && r.anchor === undefined) {
    if (opts.requireAnchor !== false) add('anchor', false, 'the revocation is not anchored, so its time is only the claim of the principal', false, true);
    else add('anchor', true, 'not anchored');
  }
  return finish(checks, { type: 'revoke', mandateId: r.statement.mandateId, mandateRef: r.statement.mandateRef, principalKeyId: r.statement.principalKeyId, anchoredAt: pos ? iso(pos) : null, principalTrusted: trusted });
}

async function verify(envelope, options) {
  if (options === undefined || options === null || typeof options !== 'object') F.reject('options is an object that names the expected type');
  const opts = Object.assign({}, options);
  if (!F.TYPES.includes(opts.type)) F.reject('type is mandate, action or revoke, so a record of one type can never be presented as another');
  delayOf(opts);
  if (strictOf(opts) && opts.trustSingleEndpoint === true) F.reject('strict verification needs at least two independent endpoints and refuses trustSingleEndpoint, set strict to false to see what one endpoint reports, which is never a valid result');
  if (opts.at !== undefined) {
    const tp = F.timeProblem(opts.at, 'at');
    if (tp) F.reject(tp);
  }
  const net = { endpoints: new Set(), official: null };
  opts[NET] = net;
  let res;
  if (opts.type === 'mandate') res = await verifyMandate(envelope, opts);
  else if (opts.type === 'action') res = await verifyAction(envelope, opts);
  else res = await verifyRevoke(envelope, opts);
  const checks = res.checks;
  delete res.checks;
  return Object.assign(res, { endpoints: [...net.endpoints], officialEndpoints: net.official, checks });
}

module.exports = { verify };
