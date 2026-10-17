#!/usr/bin/env node
// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const qm = require('..');

const ENVELOPE_MAX = 1024 * 1024;
const DETAILS_MAX = 64 * 1024 * 1024;

const HELP = `qmandate, post quantum mandates for AI agents with Quantova time proofs

  qmandate keygen <keyfile>
  qmandate key <keyfile>
  qmandate grant --key <principal keyfile> --agent <agent key json> --scope ACTION,CURRENCY,PER,TOTAL ...
                 --valid-until TIME [--valid-from TIME] [--counterparty NAME]... [--agent-label TEXT] [--note TEXT] --out FILE
  qmandate check --mandate FILE --action ACTION [--currency CODE] [--amount N] [--counterparty NAME] (--ledger DIR | --spent N)
                 [--revocation FILE]... [--at TIME] [--rpc URL]... [--trust-custom-endpoints] [--allow-endpoint HOST]...
                 [--allow-loopback] [--trust-single-endpoint --no-strict]
  qmandate act --key <agent keyfile> --mandate FILE --ledger DIR --action ACTION [--currency CODE] [--amount N]
               [--counterparty NAME] [--details-file FILE] [--spent N] [--revocation FILE]... [--note TEXT] --out FILE
               [--rpc URL]... [--trust-custom-endpoints] [--allow-endpoint HOST]... [--allow-loopback]
               [--trust-single-endpoint --no-strict]
  qmandate revoke --key <principal keyfile> --mandate FILE [--note TEXT] --out FILE
  qmandate anchor <envelope>... --seed-file <file> [--mandate FILE] [--index N] [--rpc URL]... [--trust-single-endpoint]
                  [--trust-custom-endpoints] [--allow-endpoint HOST]... [--allow-loopback] [--max-fee N]
  qmandate complete <envelope>... --pending FILE [--mandate FILE] [--tx ID] [--rpc URL]... [--trust-single-endpoint]
                    [--allow-endpoint HOST]... [--allow-loopback]
  qmandate verify <envelope> --type mandate|action|revoke [--mandate FILE] [--principal-key-id HEX | --principal-public-key FILE]
                  [--revocation FILE... | --no-revocations] [--prior FILE... | --no-prior-actions]
                  [--details-file FILE] [--counterparty-key-id HEX] [--allow-unanchored] [--at TIME]
                  [--max-anchor-delay SECONDS] [--expect-sender ADDRESS]... [--rpc URL]... [--trust-custom-endpoints]
                  [--allow-endpoint HOST]... [--allow-loopback] [--trust-single-endpoint --no-strict] [--json]

Decisions about expiry use the time of the chain, read from at least two independent endpoints. Endpoints
given with --rpc are used for the time and by verify only with --trust-custom-endpoints, loopback endpoints
only with --allow-loopback and private network endpoints only when named with --allow-endpoint.
--trust-single-endpoint relies on one endpoint, which can then misstate the time alone, so it is refused
unless --no-strict is given, and a result that rests on it is never VALID. An anchor counts only when it is
proven by a finality certificate or by official endpoints of two different operators, any other anchor is
UNPROVEN and never VALID. --expect-sender names the account that must have signed each anchor.
act numbers every action of a scope and keeps the running total in the spend ledger folder given with
--ledger, locked so that concurrent agents can never exceed the total limit. --spent states the amount
spent before the ledger was first used for that mandate and action.
Anchoring agent actions needs --mandate, and the chain refuses the anchor once its deadline, which is
never later than the expiry of the mandate, has passed.

Amounts are whole numbers of minor units, for example 150000 for 1,500.00 USD. A scope without
a currency is written ACTION,,0,0 and permits the action with no amount.

Exit codes are 0 for valid or allowed, 1 for invalid, refused or an error, 2 for indeterminate or unproven
and 64 for usage errors.`;

function usageError(message) {
  const e = new Error(message);
  e.usage = true;
  return e;
}

const SPEC = {
  keygen: { flags: ['force'], values: [] },
  key: { flags: [], values: [] },
  grant: { flags: ['force'], values: ['key', 'agent', 'valid-until', 'valid-from', 'agent-label', 'note', 'out'], multi: ['scope', 'counterparty'] },
  check: { flags: ['trust-single-endpoint', 'trust-custom-endpoints', 'allow-loopback', 'no-strict'], values: ['mandate', 'action', 'currency', 'amount', 'counterparty', 'spent', 'ledger', 'at'], multi: ['revocation', 'rpc', 'allow-endpoint'] },
  act: { flags: ['force', 'trust-single-endpoint', 'trust-custom-endpoints', 'allow-loopback', 'no-strict'], values: ['key', 'mandate', 'ledger', 'action', 'currency', 'amount', 'counterparty', 'details-file', 'spent', 'note', 'out'], multi: ['revocation', 'rpc', 'allow-endpoint'] },
  revoke: { flags: ['force'], values: ['key', 'mandate', 'note', 'out'] },
  anchor: { flags: ['trust-single-endpoint', 'trust-custom-endpoints', 'allow-loopback'], values: ['seed-file', 'index', 'max-fee', 'mandate'], multi: ['rpc', 'allow-endpoint'] },
  complete: { flags: ['trust-single-endpoint', 'allow-loopback'], values: ['pending', 'tx', 'mandate'], multi: ['rpc', 'allow-endpoint'] },
  verify: { flags: ['allow-unanchored', 'no-revocations', 'no-prior-actions', 'json', 'trust-single-endpoint', 'trust-custom-endpoints', 'allow-loopback', 'no-strict'], values: ['type', 'mandate', 'principal-key-id', 'principal-public-key', 'counterparty-key-id', 'details-file', 'at', 'max-anchor-delay'], multi: ['revocation', 'prior', 'rpc', 'allow-endpoint', 'expect-sender'] },
};

function parse(command, argv) {
  const spec = SPEC[command];
  const positional = [];
  const flags = {};
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (!a.startsWith('--')) {
      positional.push(a);
      continue;
    }
    const name = a.slice(2);
    if (spec.flags.includes(name)) {
      flags[name] = true;
    } else if (spec.values.includes(name) || (spec.multi || []).includes(name)) {
      const v = argv[i + 1];
      if (v === undefined || v.startsWith('--')) throw usageError('--' + name + ' needs a value');
      if (v.length === 0) throw usageError('--' + name + ' was given an empty value');
      i += 1;
      if ((spec.multi || []).includes(name)) (flags[name] = flags[name] || []).push(v);
      else if (flags[name] !== undefined) throw usageError('--' + name + ' was given twice');
      else flags[name] = v;
    } else {
      throw usageError('unknown option ' + safe(a).slice(0, 40));
    }
  }
  return { positional, flags };
}

function hexNibble(code) {
  if (code >= 48 && code <= 57) return code - 48;
  if (code >= 97 && code <= 102) return code - 87;
  if (code >= 65 && code <= 70) return code - 55;
  return -1;
}

function readSeed(file, what) {
  if (!file) throw usageError(what + ' is required');
  const fd = openRegular(file, 'key file');
  const raw = Buffer.allocUnsafeSlow(131);
  const seed = new Uint8Array(32);
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile()) throw usageError('the key file must be a regular file');
    if (process.platform !== 'win32') {
      if ((st.mode & 0o077) !== 0) throw usageError('the key file ' + file + ' is readable by other users, restrict it with chmod 600');
      if (typeof process.getuid === 'function' && st.uid !== process.getuid()) throw usageError('the key file ' + file + ' is not owned by the current user');
    }
    const n = fs.readSync(fd, raw, 0, raw.length, 0);
    if (n > 66) throw usageError('the key file must hold only a 32 byte seed as 64 hex characters');
    let end = n;
    while (end > 0 && (raw[end - 1] === 10 || raw[end - 1] === 13 || raw[end - 1] === 32)) end -= 1;
    if (end !== 64) throw usageError('the key file must hold a 32 byte seed as 64 hex characters');
    for (let i = 0; i < 32; i += 1) {
      const hi = hexNibble(raw[2 * i]);
      const lo = hexNibble(raw[2 * i + 1]);
      if (hi < 0 || lo < 0) throw usageError('the key file must hold a 32 byte seed as 64 hex characters');
      seed[i] = (hi << 4) | lo;
    }
    return seed;
  } catch (e) {
    seed.fill(0);
    throw e;
  } finally {
    raw.fill(0);
    fs.closeSync(fd);
  }
}

function openRegular(file, what) {
  const flags = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0) | (fs.constants.O_NONBLOCK || 0);
  let fd;
  try {
    fd = fs.openSync(file, flags);
  } catch (e) {
    throw usageError(e.code === 'ELOOP' ? 'the ' + what + ' must not be a symbolic link' : 'the ' + what + ' ' + safe(file) + ' could not be opened');
  }
  if (!fs.fstatSync(fd).isFile()) {
    fs.closeSync(fd);
    throw usageError('the ' + what + ' must be a regular file');
  }
  return fd;
}

function statOf(file) {
  try {
    return fs.lstatSync(file);
  } catch (e) {
    if (e.code === 'ENOENT') return null;
    throw e;
  }
}

const pendingTemp = new Set();

function cleanupTemp() {
  for (const t of pendingTemp) {
    try {
      fs.rmSync(t, { force: true });
    } catch (e) {
      continue;
    }
  }
}

for (const sig of ['SIGINT', 'SIGTERM', 'SIGHUP']) {
  process.on(sig, () => {
    cleanupTemp();
    process.exit(130);
  });
}

function atomicWrite(dest, data, force) {
  const existing = statOf(dest);
  if (existing && existing.isSymbolicLink()) throw usageError('refusing to write through the symbolic link ' + safe(dest));
  if (existing && !existing.isFile()) throw usageError('something other than a file exists at ' + safe(dest));
  if (existing && !force) throw usageError('a file already exists at ' + safe(dest) + ', pass --force to replace it');
  const dir = path.dirname(dest);
  const tmp = path.join(dir, '.' + path.basename(dest) + '.' + crypto.randomBytes(6).toString('hex') + '.tmp');
  pendingTemp.add(tmp);
  try {
    const fd = fs.openSync(tmp, 'wx', 0o600);
    try {
      fs.fchmodSync(fd, 0o600);
      fs.writeSync(fd, data);
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    if (force) {
      fs.renameSync(tmp, dest);
    } else {
      try {
        fs.linkSync(tmp, dest);
      } catch (e) {
        if (e.code === 'EEXIST') throw usageError('a file already exists at ' + safe(dest) + ', pass --force to replace it');
        throw e;
      }
      fs.rmSync(tmp, { force: true });
    }
    try {
      const dfd = fs.openSync(dir, 'r');
      try {
        fs.fsyncSync(dfd);
      } finally {
        fs.closeSync(dfd);
      }
    } catch (e) {
      if (e.code !== 'EISDIR' && e.code !== 'EPERM' && e.code !== 'EINVAL') throw e;
    }
  } finally {
    fs.rmSync(tmp, { force: true });
    pendingTemp.delete(tmp);
  }
}

function readJson(file, what, invalidExit) {
  const fd = openRegular(file, what);
  const buf = Buffer.alloc(ENVELOPE_MAX + 1);
  let n;
  try {
    n = fs.readSync(fd, buf, 0, buf.length, 0);
  } finally {
    fs.closeSync(fd);
  }
  const bad = (message) => {
    const e = new Error(message);
    if (invalidExit) e.invalid = true;
    else e.usage = true;
    return e;
  };
  if (n > ENVELOPE_MAX) throw bad('the ' + what + ' is larger than ' + ENVELOPE_MAX + ' bytes');
  try {
    return JSON.parse(buf.subarray(0, n).toString('utf8'));
  } catch (e) {
    throw bad('the ' + what + ' ' + safe(file) + ' is not valid JSON');
  }
}

function asciiJson(value) {
  return JSON.stringify(value, null, 2).replace(/[\u007f-\uffff]/g, (c) => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'));
}

function safe(value) {
  return String(value).replace(/[\u0000-\u001f\u007f-\u009f\u061c\u200b-\u200f\u2028-\u202e\u2060-\u2069\ufeff\ufff9-\ufffb]/gu, '?');
}

function withSeed(file, what, fn) {
  const seed = readSeed(file, what);
  try {
    return fn(seed);
  } finally {
    seed.fill(0);
  }
}

async function withSeedAsync(file, what, fn) {
  const seed = readSeed(file, what);
  try {
    return await fn(seed);
  } finally {
    seed.fill(0);
  }
}

function endpoints(flags) {
  const out = { trustSingleEndpoint: !!flags['trust-single-endpoint'], strict: !flags['no-strict'] };
  if (flags.rpc) out.clients = flags.rpc;
  if (flags['allow-endpoint']) out.endpointAllowList = flags['allow-endpoint'];
  if (flags['trust-custom-endpoints']) out.trustCustomEndpoints = true;
  if (flags['allow-loopback']) out.allowLoopback = true;
  if (flags['expect-sender']) out.expectedSender = flags['expect-sender'];
  return out;
}

async function cmdKeygen(positional, flags) {
  if (positional.length !== 1) throw usageError('keygen takes one key file path');
  const seed = qm.generateKey();
  const text = Buffer.alloc(65);
  try {
    const digits = '0123456789abcdef';
    for (let i = 0; i < 32; i += 1) {
      text[2 * i] = digits.charCodeAt(seed[i] >> 4);
      text[2 * i + 1] = digits.charCodeAt(seed[i] & 15);
    }
    text[64] = 10;
    atomicWrite(positional[0], text, flags.force);
    console.log('key id ' + qm.keyId(seed));
  } finally {
    seed.fill(0);
    text.fill(0);
  }
  return 0;
}

async function cmdKey(positional) {
  if (positional.length !== 1) throw usageError('key takes one key file path');
  const desc = withSeed(positional[0], 'a key file', (seed) => qm.describeKey(seed));
  process.stdout.write(asciiJson(desc) + '\n');
  return 0;
}


function need(flags, name) {
  if (flags[name] === undefined) throw usageError('--' + name + ' is required');
  return flags[name];
}

function readDetails(file) {
  const fd = openRegular(file, 'details file');
  try {
    const size = fs.fstatSync(fd).size;
    if (size > DETAILS_MAX) throw usageError('the details file is larger than ' + DETAILS_MAX + ' bytes');
    const buf = Buffer.alloc(size);
    let off = 0;
    while (off < size) {
      const n = fs.readSync(fd, buf, off, size - off, off);
      if (n === 0) break;
      off += n;
    }
    return buf.subarray(0, off);
  } finally {
    fs.closeSync(fd);
  }
}

function scopeOf(text) {
  const parts = text.split(',');
  if (parts.length !== 4) throw usageError('--scope is ACTION,CURRENCY,PER,TOTAL, for example payment.send,USD,500000,2000000');
  return { action: parts[0], currency: parts[1], maxPerAction: parts[2], maxTotal: parts[3] };
}

function writeEnvelope(file, env, force) {
  atomicWrite(file, asciiJson(env) + '\n', force);
}

async function cmdGrant(positional, flags) {
  if (positional.length) throw usageError('grant takes options only');
  const out = need(flags, 'out');
  const agent = readJson(need(flags, 'agent'), 'agent key');
  const scopes = (flags.scope || []).map(scopeOf);
  if (scopes.length === 0) throw usageError('at least one --scope is required');
  const env = withSeed(need(flags, 'key'), '--key', (seed) => qm.grant({
    key: seed, agent, scopes, counterparties: flags.counterparty, validUntil: need(flags, 'valid-until'),
    validFrom: flags['valid-from'], agentLabel: flags['agent-label'], note: flags.note,
  }));
  writeEnvelope(out, env, flags.force);
  console.log('mandate ' + env.statement.mandateId + ' granted to agent ' + env.statement.agentKeyId + ', written to ' + safe(out));
  return 0;
}

async function cmdCheck(positional, flags) {
  if (positional.length) throw usageError('check takes options only');
  const mandate = readJson(need(flags, 'mandate'), 'mandate', true);
  const revocations = (flags.revocation || []).map((f) => readJson(f, 'revocation'));
  if (flags.ledger === undefined && flags.spent === undefined) throw usageError('give --ledger with the spend ledger folder, or --spent with the amount already spent');
  const res = await qm.authorise(mandate, { action: need(flags, 'action'), currency: flags.currency, amount: flags.amount, counterparty: flags.counterparty }, Object.assign({ spent: flags.spent, ledger: flags.ledger, revocations, at: flags.at }, endpoints(flags)));
  if (res.allowed) console.log('ALLOWED');
  else {
    for (const r of res.reasons) console.log('refused  ' + safe(r));
    console.log('REFUSED');
  }
  return res.allowed ? 0 : 1;
}

async function cmdAct(positional, flags) {
  if (positional.length) throw usageError('act takes options only');
  const out = need(flags, 'out');
  const mandate = readJson(need(flags, 'mandate'), 'mandate', true);
  const details = flags['details-file'] !== undefined ? readDetails(flags['details-file']) : undefined;
  const revocations = (flags.revocation || []).map((f) => readJson(f, 'revocation'));
  const env = await withSeedAsync(need(flags, 'key'), '--key', (seed) => qm.act(Object.assign({
    key: seed, mandate, ledger: need(flags, 'ledger'), action: need(flags, 'action'), currency: flags.currency, amount: flags.amount,
    counterparty: flags.counterparty, details, spent: flags.spent, note: flags.note, revocations,
  }, endpoints(flags))));
  writeEnvelope(out, env, flags.force);
  console.log('action ' + env.statement.actionId + ' number ' + env.statement.sequence + ' signed under mandate ' + env.statement.mandateId + ', running total ' + env.statement.total + ', written to ' + safe(out));
  return 0;
}

async function cmdRevoke(positional, flags) {
  if (positional.length) throw usageError('revoke takes options only');
  const out = need(flags, 'out');
  const mandate = readJson(need(flags, 'mandate'), 'mandate', true);
  const env = withSeed(need(flags, 'key'), '--key', (seed) => qm.revoke({ key: seed, mandate, note: flags.note }));
  writeEnvelope(out, env, flags.force);
  console.log('revocation of mandate ' + env.statement.mandateId + ' written to ' + safe(out));
  return 0;
}

function pendingPath(file) {
  return file + '.pending.json';
}

function saveAnchored(files, anchored) {
  anchored.forEach((env, i) => {
    writeEnvelope(files[i], env, true);
    console.log('anchored ' + safe(files[i]) + ' in transaction ' + env.anchor.anchor.tx);
  });
}

async function cmdAnchor(positional, flags) {
  if (positional.length === 0) throw usageError('anchor takes one or more envelopes');
  if (new Set(positional.map((f) => path.resolve(f))).size !== positional.length) throw usageError('each envelope may be given once');
  for (const f of positional) {
    if (statOf(pendingPath(f))) throw usageError('an unfinished anchor exists in ' + safe(pendingPath(f)) + ', finish it with complete first');
  }
  const pendingFile = pendingPath(positional[0]);
  const envs = positional.map((f) => readJson(f, 'envelope', true));
  const mandate = flags.mandate !== undefined ? readJson(flags.mandate, 'mandate', true) : undefined;
  let index = 0;
  if (flags.index !== undefined) {
    if (!/^\d{1,9}$/.test(flags.index)) throw usageError('--index is a whole number');
    index = Number(flags.index);
  }
  const seed = readSeed(flags['seed-file'] || process.env.QSTAMP_SEED_FILE, '--seed-file of a funded Quantova account');
  let saved = false;
  const keep = (pending) => {
    const text = asciiJson(pending) + '\n';
    for (const f of positional) atomicWrite(pendingPath(f), text, saved);
    saved = true;
  };
  let anchored;
  try {
    anchored = await qm.anchor(envs, Object.assign({ seed, index, network: 'testnet', mandate, maxFee: flags['max-fee'], onPending: keep }, endpoints(flags)));
  } catch (e) {
    if (e && e.pending && typeof e.pending === 'object') {
      try {
        keep(e.pending);
        e.message += ', the pending stamp was saved in ' + safe(pendingFile) + ', finish it with qmandate complete ' + positional.map(safe).join(' ') + ' --pending ' + safe(pendingFile);
      } catch (e2) {
        e.message += ', the pending stamp follows on standard output, keep it to finish the anchor';
        process.stdout.write(asciiJson(e.pending) + '\n');
      }
    }
    throw e;
  } finally {
    seed.fill(0);
  }
  saveAnchored(positional, anchored);
  if (saved) for (const f of positional) fs.rmSync(pendingPath(f), { force: true });
  return 0;
}

async function cmdComplete(positional, flags) {
  if (positional.length === 0) throw usageError('complete takes the envelopes given to anchor, in the same order');
  if (!flags.pending) throw usageError('--pending is required');
  const pending = readJson(flags.pending, 'pending stamp');
  if (flags.tx !== undefined) {
    if (!/^QTX1[0-9A-Z]{20,120}$/.test(flags.tx)) throw usageError('--tx is the QTX1 identifier of the stamp transaction');
    if (pending && typeof pending === 'object' && typeof pending.tx === 'string' && pending.tx !== flags.tx) throw usageError('the pending stamp already names another transaction');
    if (pending && typeof pending === 'object') pending.tx = flags.tx;
  }
  const envs = positional.map((f) => readJson(f, 'envelope', true));
  const mandate = flags.mandate !== undefined ? readJson(flags.mandate, 'mandate', true) : undefined;
  const anchored = await qm.complete(envs, pending, Object.assign({ mandate }, endpoints(flags)));
  saveAnchored(positional, anchored);
  fs.rmSync(flags.pending, { force: true });
  for (const f of positional) fs.rmSync(pendingPath(f), { force: true });
  return 0;
}

async function cmdVerify(positional, flags) {
  if (positional.length !== 1) throw usageError('verify takes one envelope');
  if (flags['principal-key-id'] !== undefined && flags['principal-public-key'] !== undefined) throw usageError('give --principal-key-id or --principal-public-key, not both');
  if (flags['principal-key-id'] !== undefined && !/^[0-9a-f]{64}$/.test(flags['principal-key-id'])) throw usageError('--principal-key-id is 64 lowercase hex characters');
  const env = readJson(positional[0], 'envelope', true);
  const opts = { requireAnchor: !flags['allow-unanchored'] };
  if (flags.at !== undefined) opts.at = flags.at;
  if (flags['max-anchor-delay'] !== undefined) {
    if (!/^[1-9][0-9]{0,9}$/.test(flags['max-anchor-delay'])) throw usageError('--max-anchor-delay is a whole number of seconds');
    opts.maxAnchorDelay = Number(flags['max-anchor-delay']);
  }
  if (flags.mandate !== undefined) opts.mandate = readJson(flags.mandate, 'mandate', true);
  if (flags['principal-key-id'] === undefined && flags['principal-public-key'] === undefined) throw usageError('give the expected principal with --principal-key-id or --principal-public-key');
  if (flags['no-revocations'] && flags.revocation) throw usageError('give --revocation or --no-revocations, not both');
  if (flags['no-prior-actions'] && flags.prior) throw usageError('give --prior or --no-prior-actions, not both');
  if (!['mandate', 'action', 'revoke'].includes(flags.type)) throw usageError('give the expected envelope type with --type mandate, action or revoke');
  opts.type = flags.type;
  if (opts.type !== 'mandate' && opts.mandate === undefined) throw usageError('--mandate is required to verify an ' + (opts.type === 'action' ? 'action' : 'revocation'));
  if (flags['principal-key-id'] !== undefined) opts.principalKeyId = flags['principal-key-id'];
  if (flags['counterparty-key-id'] !== undefined) {
    if (!/^[0-9a-f]{64}$/.test(flags['counterparty-key-id'])) throw usageError('--counterparty-key-id is 64 lowercase hex characters');
    opts.counterpartyKeyId = flags['counterparty-key-id'];
  }
  if (flags['principal-public-key'] !== undefined) {
    const desc = readJson(flags['principal-public-key'], 'principal key');
    if (!desc || desc.format !== 'qmandate-key/1' || typeof desc.publicKey !== 'string') throw usageError('the principal key file is not a qmandate-key/1 description');
    opts.principalPublicKey = desc.publicKey;
  }
  if (flags.revocation) opts.revocations = flags.revocation.map((f) => readJson(f, 'revocation'));
  if (flags['no-revocations']) opts.revocations = [];
  if (flags.prior) opts.priorActions = flags.prior.map((f) => readJson(f, 'prior action'));
  if (flags['no-prior-actions']) opts.priorActions = [];
  if (flags['details-file'] !== undefined) opts.details = readDetails(flags['details-file']);
  Object.assign(opts, endpoints(flags));
  const res = await qm.verify(env, opts);
  if (flags.json) {
    process.stdout.write(asciiJson(res) + '\n');
  } else {
    if (res.type) console.log('type  ' + res.type);
    for (const c of res.checks) console.log((c.ok ? 'ok    ' : c.transport ? 'retry ' : c.indeterminate || c.unproven ? 'open  ' : 'FAIL  ') + safe(c.name) + '  ' + safe(c.detail));
    for (const n of res.notes || []) console.log('note  ' + safe(n));
    if ((res.endpoints || []).length) {
      console.log('endpoints  ' + res.endpoints.map(safe).join(', '));
      if (res.officialEndpoints === false) console.log('notice  endpoints other than the official ones of this network were consulted, an anchor confirmed only by them is not proven');
    }
    console.log(res.status.toUpperCase());
  }
  return res.status === 'valid' ? 0 : res.status === 'indeterminate' || res.status === 'unproven' ? 2 : 1;
}

async function main() {
  const [command, ...rest] = process.argv.slice(2);
  if (!command || command === 'help' || command === '--help' || command === '-h') {
    console.log(HELP);
    return command ? 0 : 64;
  }
  if (!Object.hasOwn(SPEC, command)) throw usageError('unknown command ' + safe(command).slice(0, 40));
  const { positional, flags } = parse(command, rest);
  const run = { keygen: cmdKeygen, key: cmdKey, grant: cmdGrant, check: cmdCheck, act: cmdAct, revoke: cmdRevoke, anchor: cmdAnchor, complete: cmdComplete, verify: cmdVerify }[command];
  return run(positional, flags);
}

function friendly(e) {
  if (e && typeof e.syscall === 'string' && typeof e.code === 'string') return 'a file could not be ' + (e.syscall === 'open' || e.syscall === 'read' ? 'opened' : 'written') + ' (' + e.code + ')';
  return (e && e.message) || String(e);
}

main().then(
  (code) => {
    process.exitCode = code;
  },
  (e) => {
    console.error(safe(friendly(e)).slice(0, 600));
    process.exitCode = e && (e.usage || e.code === 'QMANDATE_INVALID_INPUT') ? 64 : 1;
  },
);
