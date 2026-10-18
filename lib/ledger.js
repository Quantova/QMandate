// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const F = require('./format');
const native = require('./native');

const LEDGER_FORMAT = 'qmandate-ledger/1';
const LOCK_WAIT_MS = 30000;
const STATE_MAX = 4096;
const JOURNAL_MAX = 65536;
const LOCK_MAX = 1024;
const SWEPT_MAX = 10000;
const NAME = /^[0-9a-f]{64}\.[a-z][a-z0-9_.]{0,63}$/;
const JOURNAL = /^([0-9a-f]{64}\.[a-z][a-z0-9_.]{0,63})\.([1-9][0-9]{0,15})\.([0-9a-f]{64})$/;
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

function encodeState(state) {
  return JSON.stringify({
    format: LEDGER_FORMAT,
    mandateRef: state.mandateRef,
    action: state.action,
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

function parseState(text, mandateRef, action) {
  if (text === null || text === undefined) return null;
  const damaged = () => ledgerError('the spend ledger entry for ' + action + ' under mandate ' + mandateRef.slice(0, 16) + ' is damaged, nothing was signed');
  if (typeof text !== 'string' || text.length > STATE_MAX) throw damaged();
  let s;
  try {
    s = strictJson(text);
  } catch (e) {
    throw damaged();
  }
  if (!s || typeof s !== 'object' || s.format !== LEDGER_FORMAT || s.mandateRef !== mandateRef || s.action !== action) throw damaged();
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
  if (p.type !== 'action' || p.version !== F.ACTION_VERSION || st.mandateRef !== mandateRef || st.action !== action) throw damaged();
  if (p.signerId !== F.keyIdOf(p.publicKey) || p.signerId !== st.agentKeyId || !native.verify(p.publicKey, F.encoded(p), p.signature)) throw damaged();
  return { envelope, parsed: p, ref: F.refOf(p), sequence: st.sequence, previousRef: st.previousRef, total: st.total, amount: st.amount };
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
  return { pid: h.pid, started: h.started, host: h.host };
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
  return !running(holder.pid);
}

function lockText() {
  return JSON.stringify({ pid: process.pid, started: STARTED, host: os.hostname(), nonce: crypto.randomBytes(16).toString('hex') }) + '\n';
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

function breakStale(lock) {
  const seen = lockInfo(lock);
  if (!seen || seen.key === null || seen.age < LOCK_WAIT_MS || !ownerGone(seen.holder)) return false;
  const claim = lock + '.' + seen.key + '.break';
  try {
    fs.closeSync(fs.openSync(claim, CREATE_FLAGS, 0o600));
  } catch (e) {
    return false;
  }
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
  const deadline = Date.now() + LOCK_WAIT_MS;
  for (let wait = 2; ; wait = Math.min(wait * 2, 200)) {
    if (tryLock(lock, text)) return text;
    if (breakStale(lock)) continue;
    if (Date.now() >= deadline) throw lockedError(lock);
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
    const claim = new RegExp('^' + esc + '\\.json\\.lock\\.[0-9a-f]{32}\\.break$');
    for (const f of fs.readdirSync(dir)) {
      const file = path.join(dir, f);
      if (legacy.test(f)) fs.rmSync(file, { force: true });
      else if (claim.test(f) && Date.now() - fs.lstatSync(file).mtimeMs >= LOCK_WAIT_MS) fs.rmSync(file, { force: true });
    }
  } catch (e) {
    return;
  }
}

function promote(dir, pending, entry) {
  fs.renameSync(pending, path.join(dir, journalName(entry.parsed.statement.mandateRef, entry.parsed.statement.action, entry.sequence, entry.ref) + '.journal'));
}

function settle(dir, name, mandateRef, action) {
  tidy(dir, name);
  const file = path.join(dir, name + '.json');
  const pending = path.join(dir, name + '.pending');
  const current = readText(file, STATE_MAX);
  const text = readText(pending, JOURNAL_MAX);
  if (text === null) return current;
  const state = parseState(current, mandateRef, action);
  const entry = entryOf(text, mandateRef, action);
  const have = state ? BigInt(state.sequence) : 0n;
  if (BigInt(entry.sequence) <= have) {
    promote(dir, pending, entry);
    return current;
  }
  const follows = BigInt(entry.sequence) === have + 1n && entry.previousRef === (state ? state.lastRef : '')
    && (!state || BigInt(entry.total) === BigInt(state.total) + BigInt(entry.amount));
  if (!follows) throw journalDamaged(mandateRef, action);
  const next = encodeState({ mandateRef, action, sequence: entry.sequence, total: entry.total, lastRef: entry.ref });
  writeText(file, next);
  promote(dir, pending, entry);
  return next;
}

function fileLedger(dir) {
  if (typeof dir !== 'string' || dir.length === 0) F.reject('a ledger folder is a path');
  let real = null;
  const base = () => {
    if (real !== null) return real;
    let r;
    try {
      r = fs.realpathSync(dir);
    } catch (e) {
      throw ledgerError('the ledger folder ' + dir.slice(0, 200) + ' could not be opened');
    }
    if (!fs.statSync(r).isDirectory()) throw ledgerError('the ledger folder ' + dir.slice(0, 200) + ' is not a folder');
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
      let journal = null;
      if (entry !== undefined) {
        if (!entry || typeof entry !== 'object' || typeof entry.name !== 'string' || typeof entry.text !== 'string') F.reject('a journal entry has a name and the text of the signed action');
        const st = parseState(next, mandateRef, action);
        journal = entryOf(entry.text, mandateRef, action);
        if (entry.name !== journalName(mandateRef, action, st.sequence, st.lastRef) || journal.ref !== st.lastRef || journal.sequence !== st.sequence || journal.total !== st.total) {
          F.reject('the journal entry does not match the next state of the spend ledger');
        }
      }
      const root = base();
      const file = path.join(root, name + '.json');
      const pending = path.join(root, name + '.pending');
      return withLock(file + '.lock', () => {
        if (settle(root, name, mandateRef, action) !== expected) return false;
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
    async recover(name) {
      const { mandateRef, action } = check(name);
      const root = base();
      return withLock(path.join(root, name + '.json.lock'), () => settle(root, name, mandateRef, action));
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

module.exports = { LEDGER_FORMAT, LOCK_WAIT_MS, fileLedger, ledgerOf, nameOf, journalName, encodeState, parseState, entryOf, journalDamaged, breakStale, ledgerError };
