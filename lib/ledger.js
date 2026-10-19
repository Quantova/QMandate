// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const { performance } = require('perf_hooks');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawnSync, execFileSync } = require('child_process');
const F = require('./format');
const native = require('./native');

const LEDGER_FORMAT = 'qmandate-ledger/3';
const LEDGER_FORMAT_V2 = 'qmandate-ledger/2';
const LEDGER_FORMAT_V1 = 'qmandate-ledger/1';
const LOCK_WAIT_MS = 30000;
const STATE_MAX = 4096;
const JOURNAL_MAX = 65536;
const LOCK_MAX = 1024;
const SWEPT_MAX = 10000;
const NAME = /^[0-9a-f]{64}\.[a-z][a-z0-9_.]{0,63}$/;
const JOURNAL = /^([0-9a-f]{64}\.[a-z][a-z0-9_.]{0,63})\.([1-9][0-9]{0,15})\.([0-9a-f]{64})$/;
const KEY_ID = /^[0-9a-f]{64}$/;
const LEDGER_ID = /^[0-9a-f]{32}$/;
const EXECUTED = /^[0-9a-f]{64}\.[a-z][a-z0-9_.]{0,63}\.executed\.(seq\.[1-9][0-9]{0,15}|id\.[0-9a-f]{32})$/;
const EXECUTED_FORMAT = 'qmandate-executed/1';
const CLAIM_DEPTH = 3;
const C = fs.constants;
const NOFOLLOW = C.O_NOFOLLOW || 0;
const READ_FLAGS = C.O_RDONLY | NOFOLLOW | (C.O_NONBLOCK || 0);
const CREATE_FLAGS = C.O_WRONLY | C.O_CREAT | C.O_EXCL | NOFOLLOW;
const STARTED = Math.round(Date.now() - process.uptime() * 1000);
const swept = new Set();

function ledgerError(message) {
  const e = new Error(message);
  e.code = 'QMANDATE_LEDGER';
  return e;
}

function nameOf(mandateRef, action) {
  return mandateRef + '.' + action;
}

function journalName(mandateRef, action, sequence, ref) {
  return nameOf(mandateRef, action) + '.' + sequence + '.' + ref;
}

function executedName(mandateRef, action, statement) {
  const position = statement.sequence !== undefined ? 'seq.' + statement.sequence : 'id.' + statement.actionId;
  return nameOf(mandateRef, action) + '.executed.' + position;
}

function newLedgerId() {
  return crypto.randomBytes(16).toString('hex');
}

function encodeState(state) {
  if (state.agentKeyId === undefined) {
    return JSON.stringify({
      format: LEDGER_FORMAT_V1,
      mandateRef: state.mandateRef,
      action: state.action,
      sequence: state.sequence,
      total: state.total,
      lastRef: state.lastRef,
    }) + '\n';
  }
  if (state.ledgerId === undefined) {
    return JSON.stringify({
      format: LEDGER_FORMAT_V2,
      mandateRef: state.mandateRef,
      action: state.action,
      agentKeyId: state.agentKeyId,
      sequence: state.sequence,
      total: state.total,
      lastRef: state.lastRef,
    }) + '\n';
  }
  return JSON.stringify({
    format: LEDGER_FORMAT,
    mandateRef: state.mandateRef,
    action: state.action,
    agentKeyId: state.agentKeyId,
    ledgerId: state.ledgerId,
    sequence: state.sequence,
    total: state.total,
    lastRef: state.lastRef,
  }) + '\n';
}

function strictJson(text) {
  const value = JSON.parse(text);
  const stack = [];
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    const top = stack[stack.length - 1];
    if (ch === '"') {
      let j = i + 1;
      while (text[j] !== '"') j += text[j] === '\\' ? 2 : 1;
      if (top && top.keys && top.expectKey) {
        const key = JSON.parse(text.slice(i, j + 1));
        if (top.keys.has(key)) throw new Error('the JSON repeats the key ' + JSON.stringify(key));
        top.keys.add(key);
        top.expectKey = false;
      }
      i = j;
    } else if (ch === '{') {
      stack.push({ keys: new Set(), expectKey: true });
    } else if (ch === '[') {
      stack.push({ keys: null });
    } else if (ch === '}' || ch === ']') {
      stack.pop();
    } else if (ch === ',' && top && top.keys) {
      top.expectKey = true;
    }
  }
  return value;
}

function parseState(text, mandateRef, action, agentKeyId) {
  if (text === null || text === undefined) return null;
  const damaged = () => ledgerError('the spend ledger entry for ' + action + ' under mandate ' + mandateRef.slice(0, 16) + ' is damaged, nothing was signed');
  if (typeof text !== 'string' || text.length > STATE_MAX) throw damaged();
  let s;
  try {
    s = strictJson(text);
  } catch (e) {
    throw damaged();
  }
  if (!s || typeof s !== 'object' || ![LEDGER_FORMAT, LEDGER_FORMAT_V2, LEDGER_FORMAT_V1].includes(s.format) || s.mandateRef !== mandateRef || s.action !== action) throw damaged();
  if (s.format !== LEDGER_FORMAT_V1 && (typeof s.agentKeyId !== 'string' || !KEY_ID.test(s.agentKeyId))) throw damaged();
  if (s.format === LEDGER_FORMAT_V1 && s.agentKeyId !== undefined) throw damaged();
  if (s.format === LEDGER_FORMAT && (typeof s.ledgerId !== 'string' || !LEDGER_ID.test(s.ledgerId))) throw damaged();
  if (s.format !== LEDGER_FORMAT && s.ledgerId !== undefined) throw damaged();
  if (agentKeyId !== undefined && s.agentKeyId !== undefined && s.agentKeyId !== agentKeyId) throw damaged();
  if (typeof s.sequence !== 'string' || !/^[1-9][0-9]{0,15}$/.test(s.sequence)) throw damaged();
  if (typeof s.total !== 'string' || !/^(0|[1-9][0-9]{0,31})$/.test(s.total)) throw damaged();
  if (typeof s.lastRef !== 'string' || !/^[0-9a-f]{64}$/.test(s.lastRef)) throw damaged();
  if (encodeState(s) !== text) throw damaged();
  return s;
}

function journalDamaged(mandateRef, action) {
  return ledgerError('the journal of signed actions for ' + action + ' under mandate ' + mandateRef.slice(0, 16) + ' is damaged');
}

function entryOf(text, mandateRef, action) {
  const damaged = () => journalDamaged(mandateRef, action);
  if (typeof text !== 'string' || text.length > JOURNAL_MAX) throw damaged();
  let envelope;
  let p;
  try {
    envelope = strictJson(text);
    p = F.parse(envelope);
  } catch (e) {
    throw damaged();
  }
  if (JSON.stringify(envelope) + '\n' !== text) throw damaged();
  const st = p.statement;
  if (p.type !== 'action' || !F.chained(p.version) || st.mandateRef !== mandateRef || st.action !== action) throw damaged();
  if (p.signerId !== F.keyIdOf(p.publicKey) || p.signerId !== st.agentKeyId || !native.verify(p.publicKey, F.encoded(p), p.signature)) throw damaged();
  return { envelope, parsed: p, ref: F.refOf(p), sequence: st.sequence, previousRef: st.previousRef, total: st.total, amount: st.amount, ledgerId: st.ledgerId };
}

function ledgerIdAfter(state, entry, mandateRef, action) {
  const held = state ? state.ledgerId : undefined;
  if (entry.ledgerId === undefined) {
    if (held !== undefined) throw journalDamaged(mandateRef, action);
    return undefined;
  }
  if (held !== undefined && held !== entry.ledgerId) throw journalDamaged(mandateRef, action);
  return entry.ledgerId;
}

function journalFiles(dir, name) {
  const prefix = name + '.';
  const out = [];
  for (const f of fs.readdirSync(dir)) {
    if (!f.startsWith(prefix) || !f.endsWith('.journal')) continue;
    const m = /^([1-9][0-9]{0,15})\.([0-9a-f]{64})$/.exec(f.slice(prefix.length, -'.journal'.length));
    if (m) out.push({ file: path.join(dir, f), sequence: BigInt(m[1]), ref: m[2] });
  }
  return out;
}

function rolledBack(dir, name, mandateRef, action, from) {
  const ahead = journalFiles(dir, name).filter((j) => j.sequence >= from);
  if (ahead.length === 0) return;
  const top = ahead.reduce((a, b) => (b.sequence > a.sequence ? b : a));
  throw ledgerError('the spend ledger state for ' + action + ' under mandate ' + mandateRef.slice(0, 16) + ' is older than its journal, which already records action ' + top.sequence + ', so the state was restored from an older copy, nothing was signed, call recover or ledgerActions to rebuild the state from the journal');
}

function holderOf(text) {
  const t = String(text).trim();
  if (/^[1-9][0-9]{0,9}$/.test(t)) return { pid: Number(t) };
  let h;
  try {
    h = JSON.parse(t);
  } catch (e) {
    return null;
  }
  if (!h || !Number.isSafeInteger(h.pid) || h.pid <= 0 || !Number.isSafeInteger(h.started) || typeof h.host !== 'string') return null;
  if (h.start !== undefined && (typeof h.start !== 'string' || h.start.length === 0 || h.start.length > 200)) return null;
  return { pid: h.pid, started: h.started, host: h.host, start: h.start };
}

function startOf(pid) {
  try {
    if (process.platform === 'linux') {
      const stat = fs.readFileSync('/proc/' + pid + '/stat', 'utf8');
      const ticks = stat.slice(stat.lastIndexOf(')') + 2).split(' ')[19];
      const boot = fs.readFileSync('/proc/sys/kernel/random/boot_id', 'utf8').trim();
      if (!/^[0-9]{1,20}$/.test(ticks) || !/^[0-9a-f-]{36}$/.test(boot)) return null;
      return 'linux ' + boot + ' ' + ticks;
    }
    if (process.platform === 'darwin' || process.platform === 'freebsd' || process.platform === 'openbsd') {
      const r = spawnSync('/bin/ps', ['-o', 'lstart=', '-p', String(pid)], { encoding: 'utf8', env: { LC_ALL: 'C', TZ: 'UTC' }, timeout: 5000, stdio: ['ignore', 'pipe', 'ignore'] });
      const t = r.status === 0 && typeof r.stdout === 'string' ? r.stdout.trim().replace(/\s+/g, ' ') : '';
      if (!/^[A-Za-z]{3} [A-Za-z]{3} [0-9]{1,2} [0-9]{2}:[0-9]{2}:[0-9]{2} [0-9]{4}$/.test(t)) return null;
      return 'ps ' + t;
    }
  } catch (e) {
    return null;
  }
  return null;
}

let ownStart;
function selfStart() {
  if (ownStart === undefined) ownStart = startOf(process.pid);
  return ownStart;
}

function running(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return e.code !== 'ESRCH';
  }
}

function ownerGone(holder) {
  if (!holder || holder.started === undefined || holder.host !== os.hostname() || holder.pid === process.pid) return false;
  if (!running(holder.pid)) return true;
  if (holder.start === undefined) return false;
  const now = startOf(holder.pid);
  if (now === null) return !running(holder.pid);
  return now !== holder.start;
}

function lockText() {
  const h = { pid: process.pid, started: STARTED, host: os.hostname(), nonce: crypto.randomBytes(16).toString('hex') };
  const start = selfStart();
  if (start !== null) h.start = start;
  return JSON.stringify(h) + '\n';
}

function lockInfo(lock) {
  let fd;
  try {
    fd = fs.openSync(lock, READ_FLAGS);
  } catch (e) {
    return null;
  }
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile() || st.size > LOCK_MAX) return { text: null, holder: null, age: 0, key: null };
    const buf = Buffer.alloc(st.size);
    const text = buf.subarray(0, fs.readSync(fd, buf, 0, buf.length, 0)).toString('utf8');
    const key = crypto.createHash('sha256').update(st.dev + ' ' + st.ino + ' ' + st.mtimeMs + ' ' + text).digest('hex').slice(0, 32);
    return { text, holder: holderOf(text), age: Date.now() - st.mtimeMs, key };
  } finally {
    fs.closeSync(fd);
  }
}

function takeClaim(claim, depth) {
  try {
    if (tryLock(claim, lockText())) return true;
  } catch (e) {
    return false;
  }
  if (depth >= CLAIM_DEPTH || !breakStale(claim, depth + 1)) return false;
  try {
    return tryLock(claim, lockText());
  } catch (e) {
    return false;
  }
}

function breakStale(lock, depth) {
  const level = depth === undefined ? 0 : depth;
  const seen = lockInfo(lock);
  if (!seen || seen.key === null || seen.age < LOCK_WAIT_MS || !ownerGone(seen.holder)) return false;
  const claim = lock + '.' + seen.key + '.break';
  if (!takeClaim(claim, level)) return false;
  try {
    const now = lockInfo(lock);
    if (!now || now.key !== seen.key) return false;
    fs.unlinkSync(lock);
    return true;
  } catch (e) {
    return false;
  } finally {
    fs.rmSync(claim, { force: true });
  }
}

function tryLock(lock, text) {
  if (lockInfo(lock) !== null) return false;
  const tmp = path.join(path.dirname(lock), '.' + path.basename(lock) + '.' + crypto.randomBytes(16).toString('hex') + '.tmp');
  try {
    const fd = fs.openSync(tmp, CREATE_FLAGS, 0o600);
    try {
      fs.writeSync(fd, text);
    } finally {
      fs.closeSync(fd);
    }
    fs.linkSync(tmp, lock);
    return true;
  } catch (e) {
    if (e.code === 'EEXIST' || e.code === 'ENOENT') return false;
    if (e.code !== 'EPERM' && e.code !== 'ENOTSUP' && e.code !== 'EOPNOTSUPP' && e.code !== 'ENOSYS' && e.code !== 'EMLINK') {
      throw ledgerError('the spend ledger could not be locked (' + e.code + ')');
    }
  } finally {
    fs.rmSync(tmp, { force: true });
  }
  return createLock(lock, text);
}

function createLock(lock, text) {
  let fd;
  try {
    fd = fs.openSync(lock, CREATE_FLAGS, 0o600);
  } catch (e) {
    if (e.code === 'EEXIST') return false;
    throw ledgerError('the spend ledger could not be locked (' + e.code + ')');
  }
  try {
    fs.writeSync(fd, text);
  } catch (e) {
    fs.closeSync(fd);
    fd = undefined;
    fs.rmSync(lock, { force: true });
    throw ledgerError('the spend ledger could not be locked (' + e.code + ')');
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
  return true;
}

function lockedError(lock) {
  const seen = lockInfo(lock);
  const holder = seen && seen.holder;
  if (holder && holder.host !== undefined && holder.host !== os.hostname()) {
    return ledgerError('the spend ledger is locked by process ' + holder.pid + ' on the host ' + holder.host.slice(0, 64) + ', which cannot be checked from here, nothing was signed, remove ' + lock + ' once no agent process on that host is active');
  }
  if (holder && holder.pid !== process.pid && !running(holder.pid)) {
    return ledgerError('the spend ledger is locked by process ' + holder.pid + ' which is no longer running, remove ' + lock + ' once no other agent process is active');
  }
  if (seen && !holder) {
    return ledgerError('the spend ledger is locked by a process that left no record of itself, nothing was signed, remove ' + lock + ' once no other agent process is active');
  }
  return ledgerError('the spend ledger stayed locked for ' + LOCK_WAIT_MS / 1000 + ' seconds, nothing was signed');
}

async function acquire(lock) {
  const text = lockText();
  const deadline = performance.now() + LOCK_WAIT_MS;
  for (let wait = 2; ; wait = Math.min(wait * 2, 200)) {
    if (tryLock(lock, text)) return text;
    if (breakStale(lock)) continue;
    if (performance.now() >= deadline) throw lockedError(lock);
    await new Promise((resolve) => setTimeout(resolve, wait + Math.floor(Math.random() * wait)));
  }
}

async function withLock(lock, fn) {
  const text = await acquire(lock);
  try {
    return fn();
  } finally {
    const seen = lockInfo(lock);
    if (seen && seen.text === text) fs.rmSync(lock, { force: true });
  }
}

function readText(file, max) {
  let fd;
  try {
    fd = fs.openSync(file, READ_FLAGS);
  } catch (e) {
    if (e.code === 'ENOENT') return null;
    throw ledgerError('the spend ledger entry ' + path.basename(file) + ' could not be opened (' + e.code + ')');
  }
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile() || st.size > max) throw ledgerError('the spend ledger entry ' + path.basename(file) + ' is not a small regular file');
    const buf = Buffer.alloc(st.size);
    const n = fs.readSync(fd, buf, 0, buf.length, 0);
    return buf.subarray(0, n).toString('utf8');
  } finally {
    fs.closeSync(fd);
  }
}

function syncDir(dir) {
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
}

function writeText(file, text) {
  const dir = path.dirname(file);
  const tmp = path.join(dir, '.' + path.basename(file) + '.tmp');
  fs.rmSync(tmp, { force: true });
  try {
    const fd = fs.openSync(tmp, CREATE_FLAGS, 0o600);
    try {
      fs.writeSync(fd, text);
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    fs.renameSync(tmp, file);
    syncDir(dir);
  } finally {
    fs.rmSync(tmp, { force: true });
  }
}

function tidy(dir, name) {
  try {
    for (const f of [name + '.json', name + '.pending']) fs.rmSync(path.join(dir, '.' + f + '.tmp'), { force: true });
    const key = dir + '\n' + name;
    if (swept.has(key)) return;
    if (swept.size >= SWEPT_MAX) swept.clear();
    swept.add(key);
    const esc = name.replace(/\./g, '\\.');
    const legacy = new RegExp('^\\.' + esc + '\\.json\\.[0-9a-f]{12}\\.tmp$');
    const claim = new RegExp('^' + esc + '\\.json\\.lock(\\.[0-9a-f]{32}\\.break){1,' + (CLAIM_DEPTH + 1) + '}$');
    const staged = new RegExp('^\\.' + esc + '\\.json\\.lock(\\.[0-9a-f]{32}\\.break){0,' + (CLAIM_DEPTH + 1) + '}\\.[0-9a-f]{32}\\.tmp$');
    for (const f of fs.readdirSync(dir)) {
      const file = path.join(dir, f);
      if (legacy.test(f)) fs.rmSync(file, { force: true });
      else if (claim.test(f) && Date.now() - fs.lstatSync(file).mtimeMs >= LOCK_WAIT_MS) fs.rmSync(file, { force: true });
      else if (staged.test(f)) fs.rmSync(file, { force: true });
    }
  } catch (e) {
    return;
  }
}

function promote(dir, pending, entry) {
  fs.renameSync(pending, path.join(dir, journalName(entry.parsed.statement.mandateRef, entry.parsed.statement.action, entry.sequence, entry.ref) + '.journal'));
}

function settle(dir, name, mandateRef, action, agentKeyId) {
  tidy(dir, name);
  const file = path.join(dir, name + '.json');
  const pending = path.join(dir, name + '.pending');
  const current = readText(file, STATE_MAX);
  const text = readText(pending, JOURNAL_MAX);
  const state = parseState(current, mandateRef, action, agentKeyId);
  rolledBack(dir, name, mandateRef, action, (state ? BigInt(state.sequence) : 0n) + 1n);
  if (text === null) return current;
  const agent = agentKeyId !== undefined ? agentKeyId : (state && state.agentKeyId);
  if (!agent) throw ledgerError('the unfinished action in the spend ledger for ' + action + ' under mandate ' + mandateRef.slice(0, 16) + ' cannot be matched to the agent of the mandate, nothing was changed');
  const entry = entryOf(text, mandateRef, action);
  if (entry.parsed.signerId !== agent) throw journalDamaged(mandateRef, action);
  const have = state ? BigInt(state.sequence) : 0n;
  if (BigInt(entry.sequence) <= have) {
    promote(dir, pending, entry);
    return current;
  }
  const follows = BigInt(entry.sequence) === have + 1n && entry.previousRef === (state ? state.lastRef : '')
    && (!state || BigInt(entry.total) === BigInt(state.total) + BigInt(entry.amount));
  if (!follows) throw journalDamaged(mandateRef, action);
  const ledgerId = ledgerIdAfter(state, entry, mandateRef, action);
  const next = encodeState({ mandateRef, action, agentKeyId: agent, ledgerId, sequence: entry.sequence, total: entry.total, lastRef: entry.ref });
  writeText(file, next);
  promote(dir, pending, entry);
  return next;
}

function chainHeads(entries) {
  const byRef = new Map(entries.map((e) => [e.ref, e]));
  const sound = new Map();
  const soundOf = (e) => {
    const walk = [];
    let cur = e;
    let ok = null;
    while (ok === null) {
      if (sound.has(cur.ref)) {
        ok = sound.get(cur.ref);
        break;
      }
      walk.push(cur);
      if (cur.sequence === '1') {
        ok = cur.previousRef === '';
        break;
      }
      const prev = byRef.get(cur.previousRef);
      if (!prev || BigInt(prev.sequence) + 1n !== BigInt(cur.sequence) || BigInt(prev.total) + BigInt(cur.amount) !== BigInt(cur.total) || walk.length > entries.length) {
        ok = false;
        break;
      }
      cur = prev;
    }
    for (const p of walk) sound.set(p.ref, ok);
    return ok;
  };
  let best = [];
  for (const e of entries) {
    if (!soundOf(e)) continue;
    if (best.length === 0 || BigInt(e.sequence) > BigInt(best[0].sequence)) best = [e];
    else if (BigInt(e.sequence) === BigInt(best[0].sequence) && e.ref !== best[0].ref) best.push(e);
  }
  return best;
}

function rebuild(dir, name, mandateRef, action, agentKeyId) {
  tidy(dir, name);
  const file = path.join(dir, name + '.json');
  const current = readText(file, STATE_MAX);
  const state = parseState(current, mandateRef, action, agentKeyId);
  const files = journalFiles(dir, name);
  const have = state ? BigInt(state.sequence) : 0n;
  if (!files.some((j) => j.sequence > have)) return settle(dir, name, mandateRef, action, agentKeyId);
  const agent = agentKeyId !== undefined ? agentKeyId : (state && state.agentKeyId);
  if (!agent) throw ledgerError('the journal of the spend ledger for ' + action + ' under mandate ' + mandateRef.slice(0, 16) + ' cannot be matched to the agent of the mandate, nothing was changed');
  const entries = [];
  for (const j of files) {
    const entry = entryOf(readText(j.file, JOURNAL_MAX), mandateRef, action);
    if (entry.ref !== j.ref || BigInt(entry.sequence) !== j.sequence || entry.parsed.signerId !== agent) throw journalDamaged(mandateRef, action);
    entries.push(entry);
  }
  const best = chainHeads(entries);
  if (best.length > 1) throw ledgerError('the journal of the spend ledger for ' + action + ' under mandate ' + mandateRef.slice(0, 16) + ' holds ' + best.length + ' different actions numbered ' + best[0].sequence + ', so it forks and was not rebuilt');
  const head = best[0];
  if (!head || BigInt(head.sequence) <= have || files.some((j) => j.sequence > BigInt(head.sequence))) throw ledgerError('the journal of the spend ledger for ' + action + ' under mandate ' + mandateRef.slice(0, 16) + ' records actions whose earlier actions are missing, so it was not rebuilt');
  if (state && state.ledgerId !== undefined && head.ledgerId !== undefined && state.ledgerId !== head.ledgerId) throw journalDamaged(mandateRef, action);
  const ledgerId = head.ledgerId !== undefined ? head.ledgerId : (state ? state.ledgerId : undefined);
  writeText(file, encodeState({ mandateRef, action, agentKeyId: agent, ledgerId, sequence: head.sequence, total: head.total, lastRef: head.ref }));
  return settle(dir, name, mandateRef, action, agent);
}

const WRITE_RIGHTS = /\b(add_file|add_subdirectory|delete_child|delete|write|append|writeattr|writeextattr|writesecurity|chown)\b/;

function listing(file, args, dir) {
  try {
    return execFileSync(file, args, { encoding: 'utf8', timeout: 5000, stdio: ['ignore', 'pipe', 'pipe'] });
  } catch (e) {
    throw ledgerError('the permissions of the folder ' + String(dir).slice(0, 200) + ' could not be read');
  }
}

function aclLetsOthersWrite(dir) {
  if (process.platform === 'win32') return false;
  if (process.platform === 'darwin') {
    return listing('/bin/ls', ['-lde', dir], dir).split('\n').some((l) => /^\s*\d+: /.test(l) && / allow /.test(l) && WRITE_RIGHTS.test(l));
  }
  for (const tool of ['/usr/bin/getfacl', '/bin/getfacl']) {
    if (fs.existsSync(tool)) {
      return listing(tool, ['-cp', dir], dir).split('\n').some((l) => /^(default:)?(user|group):[^:]+:[r-]w/.test(l.trim()));
    }
  }
  let version = '';
  try {
    version = execFileSync('/bin/ls', ['--version'], { encoding: 'utf8', timeout: 5000, stdio: ['ignore', 'pipe', 'ignore'] });
  } catch (e) {
    version = '';
  }
  if (!/GNU coreutils/.test(version)) throw ledgerError('access control lists cannot be read on this system, install getfacl so the ledger folder can be checked');
  return /^.{10}\+/.test(listing('/bin/ls', ['-ld', dir], dir));
}

function exposedPlace(dir, ownerUid, depth, includeLast) {
  const self = typeof process.getuid === 'function' ? process.getuid() : null;
  const safe = (p, st) => (self === null || st.uid === 0 || st.uid === self || st.uid === ownerUid) && !((st.mode & 0o002) && !(st.mode & 0o1000)) && !aclLetsOthersWrite(p);
  if (depth > 32) throw ledgerError('the ledger folder is reached through too many symbolic links');
  const full = path.resolve(dir);
  const parts = full.split(path.sep).filter(Boolean);
  let cur = path.parse(full).root;
  if (!safe(cur, fs.statSync(cur))) return cur;
  for (let i = 0; i < parts.length; i += 1) {
    const next = path.join(cur, parts[i]);
    const last = i === parts.length - 1;
    const st = fs.lstatSync(next);
    if (st.isSymbolicLink()) {
      const target = path.resolve(path.dirname(next), fs.readlinkSync(next));
      const bad = exposedPlace(target, ownerUid, depth + 1, !last || includeLast);
      if (bad) return bad;
      cur = fs.realpathSync(target);
      continue;
    }
    if ((!last || includeLast) && !safe(next, st)) return next;
    cur = next;
  }
  return null;
}

function fileLedger(dir) {
  if (typeof dir !== 'string' || dir.length === 0) F.reject('a ledger folder is a path');
  let real = null;
  const base = () => {
    if (real !== null) return real;
    let r;
    try {
      if (fs.lstatSync(dir).isSymbolicLink()) throw new Error('link');
      r = fs.realpathSync(dir);
    } catch (e) {
      throw ledgerError(e.message === 'link' ? 'the ledger folder ' + dir.slice(0, 200) + ' is a symbolic link, give the folder itself' : 'the ledger folder ' + dir.slice(0, 200) + ' could not be opened');
    }
    const st = fs.statSync(r);
    if (!st.isDirectory()) throw ledgerError('the ledger folder ' + dir.slice(0, 200) + ' is not a folder');
    if (st.mode & 0o002) throw ledgerError('the ledger folder ' + dir.slice(0, 200) + ' can be written by every user of this machine, restrict it to the agent and the provider that use it');
    if (aclLetsOthersWrite(r)) throw ledgerError('the ledger folder ' + dir.slice(0, 200) + ' carries an access control list that lets others write, remove it so that only its mode decides who may write');
    const above = exposedPlace(dir, st.uid, 0, false);
    if (above) throw ledgerError('the folder ' + above.slice(0, 200) + ' above the ledger can be changed by another user, so the ledger could be replaced, move the ledger under folders only the agent and the provider control');
    real = r;
    return real;
  };
  const check = (name) => {
    if (typeof name !== 'string' || !NAME.test(name)) F.reject('a ledger entry name is a mandate reference and an action');
    return { mandateRef: name.slice(0, 64), action: name.slice(65) };
  };
  return {
    async read(name) {
      check(name);
      return readText(path.join(base(), name + '.json'), STATE_MAX);
    },
    async compareAndSwap(name, expected, next, entry) {
      const { mandateRef, action } = check(name);
      const st = parseState(next, mandateRef, action);
      if (st === null || st.agentKeyId === undefined) F.reject('the next state of the spend ledger names the agent of the mandate');
      let journal = null;
      if (entry !== undefined) {
        if (!entry || typeof entry !== 'object' || typeof entry.name !== 'string' || typeof entry.text !== 'string') F.reject('a journal entry has a name and the text of the signed action');
        journal = entryOf(entry.text, mandateRef, action);
        if (entry.name !== journalName(mandateRef, action, st.sequence, st.lastRef) || journal.ref !== st.lastRef || journal.sequence !== st.sequence || journal.total !== st.total || journal.parsed.signerId !== st.agentKeyId || journal.ledgerId !== st.ledgerId) {
          F.reject('the journal entry does not match the next state of the spend ledger');
        }
      }
      const root = base();
      const file = path.join(root, name + '.json');
      const pending = path.join(root, name + '.pending');
      return withLock(file + '.lock', () => {
        if (settle(root, name, mandateRef, action, st.agentKeyId) !== expected) return false;
        rolledBack(root, name, mandateRef, action, BigInt(st.sequence));
        if (journal) writeText(pending, entry.text);
        writeText(file, next);
        if (journal) {
          try {
            promote(root, pending, journal);
          } catch (e) {
            return true;
          }
        }
        return true;
      });
    },
    async recover(name, agentKeyId) {
      const { mandateRef, action } = check(name);
      if (agentKeyId !== undefined && (typeof agentKeyId !== 'string' || !KEY_ID.test(agentKeyId))) F.reject('agentKeyId is 64 lowercase hex characters');
      const root = base();
      return withLock(path.join(root, name + '.json.lock'), () => rebuild(root, name, mandateRef, action, agentKeyId));
    },
    async createOnce(name, text) {
      if (typeof name !== 'string' || !EXECUTED.test(name)) F.reject('a record of an executed action is named by the mandate reference, the action and the position the action holds under its mandate');
      if (typeof text !== 'string' || text.length > STATE_MAX) F.reject('a record of an executed action is short text');
      const root = base();
      const file = path.join(root, name);
      let fd;
      try {
        fd = fs.openSync(file, CREATE_FLAGS, 0o600);
      } catch (e) {
        if (e.code === 'EEXIST') return false;
        throw ledgerError('the record of an executed action could not be written (' + e.code + ')');
      }
      try {
        fs.writeSync(fd, text);
        fs.fsyncSync(fd);
      } finally {
        fs.closeSync(fd);
      }
      syncDir(root);
      return true;
    },
    async readExecuted(name) {
      if (typeof name !== 'string' || !EXECUTED.test(name)) F.reject('a record of an executed action is named by the mandate reference, the action and the position the action holds under its mandate');
      return readText(path.join(base(), name), STATE_MAX);
    },
    async readJournal(name) {
      const m = typeof name === 'string' ? JOURNAL.exec(name) : null;
      if (!m) F.reject('a journal entry name is a mandate reference, an action, a number and the reference of the action');
      const { mandateRef, action } = check(m[1]);
      const root = base();
      const final = path.join(root, name + '.journal');
      for (let tries = 0; tries < 2; tries += 1) {
        const text = readText(final, JOURNAL_MAX);
        if (text !== null) return text;
        const pending = readText(path.join(root, m[1] + '.pending'), JOURNAL_MAX);
        if (pending === null) continue;
        let entry;
        try {
          entry = entryOf(pending, mandateRef, action);
        } catch (e) {
          continue;
        }
        if (entry.sequence === m[2] && entry.ref === m[3]) return pending;
      }
      return null;
    },
  };
}

function ledgerOf(value) {
  if (typeof value === 'string') return fileLedger(value);
  if (value && typeof value === 'object' && typeof value.read === 'function' && typeof value.compareAndSwap === 'function') return value;
  F.reject('ledger is the folder of the spend ledger, or an object with read and compareAndSwap that stores it atomically');
}

module.exports = { LEDGER_FORMAT, LEDGER_FORMAT_V2, LEDGER_FORMAT_V1, EXECUTED_FORMAT, LOCK_WAIT_MS, executedName, newLedgerId, startOf, fileLedger, ledgerOf, nameOf, journalName, encodeState, parseState, entryOf, journalDamaged, breakStale, ledgerError };
