// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const F = require('./format');

const LEDGER_FORMAT = 'qmandate-ledger/1';
const LOCK_WAIT_MS = 30000;
const STATE_MAX = 4096;
const NAME = /^[0-9a-f]{64}\.[a-z][a-z0-9_.]{0,63}$/;

function ledgerError(message) {
  const e = new Error(message);
  e.code = 'QMANDATE_LEDGER';
  return e;
}

function nameOf(mandateRef, action) {
  return mandateRef + '.' + action;
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

function parseState(text, mandateRef, action) {
  if (text === null || text === undefined) return null;
  const damaged = () => ledgerError('the spend ledger entry for ' + action + ' under mandate ' + mandateRef.slice(0, 16) + ' is damaged, nothing was signed');
  if (typeof text !== 'string' || text.length > STATE_MAX) throw damaged();
  let s;
  try {
    s = JSON.parse(text);
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

function holderOf(lock) {
  try {
    const pid = Number(fs.readFileSync(lock, { encoding: 'utf8', flag: fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0) }).trim());
    if (!Number.isSafeInteger(pid) || pid <= 0) return null;
    try {
      process.kill(pid, 0);
      return { pid, running: true };
    } catch (e) {
      return { pid, running: e.code !== 'ESRCH' };
    }
  } catch (e) {
    return null;
  }
}

async function acquire(lock) {
  const deadline = Date.now() + LOCK_WAIT_MS;
  for (let wait = 2; ; wait = Math.min(wait * 2, 200)) {
    try {
      return fs.openSync(lock, 'wx', 0o600);
    } catch (e) {
      if (e.code !== 'EEXIST') throw ledgerError('the spend ledger could not be locked (' + e.code + ')');
    }
    if (Date.now() >= deadline) {
      const holder = holderOf(lock);
      throw ledgerError(holder && !holder.running
        ? 'the spend ledger is locked by process ' + holder.pid + ' which is no longer running, remove ' + lock + ' once no other agent process is active'
        : 'the spend ledger stayed locked for ' + LOCK_WAIT_MS / 1000 + ' seconds, nothing was signed');
    }
    await new Promise((resolve) => setTimeout(resolve, wait + Math.floor(Math.random() * wait)));
  }
}

async function withLock(lock, fn) {
  let fd = await acquire(lock);
  try {
    fs.writeSync(fd, String(process.pid) + '\n');
    fs.closeSync(fd);
    fd = undefined;
    return fn();
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
    fs.rmSync(lock, { force: true });
  }
}

function readText(file) {
  let fd;
  try {
    fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0) | (fs.constants.O_NONBLOCK || 0));
  } catch (e) {
    if (e.code === 'ENOENT') return null;
    throw ledgerError('the spend ledger entry ' + path.basename(file) + ' could not be opened (' + e.code + ')');
  }
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile() || st.size > STATE_MAX) throw ledgerError('the spend ledger entry ' + path.basename(file) + ' is not a small regular file');
    const buf = Buffer.alloc(st.size);
    const n = fs.readSync(fd, buf, 0, buf.length, 0);
    return buf.subarray(0, n).toString('utf8');
  } finally {
    fs.closeSync(fd);
  }
}

function writeText(file, text) {
  const dir = path.dirname(file);
  const tmp = path.join(dir, '.' + path.basename(file) + '.' + crypto.randomBytes(6).toString('hex') + '.tmp');
  try {
    const fd = fs.openSync(tmp, 'wx', 0o600);
    try {
      fs.writeSync(fd, text);
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    fs.renameSync(tmp, file);
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
  }
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
  const fileOf = (name) => {
    if (typeof name !== 'string' || !NAME.test(name)) F.reject('a ledger entry name is a mandate reference and an action');
    return path.join(base(), name + '.json');
  };
  return {
    async read(name) {
      return readText(fileOf(name));
    },
    async compareAndSwap(name, expected, next) {
      const file = fileOf(name);
      return withLock(file + '.lock', () => {
        if (readText(file) !== expected) return false;
        writeText(file, next);
        return true;
      });
    },
  };
}

function ledgerOf(value) {
  if (typeof value === 'string') return fileLedger(value);
  if (value && typeof value === 'object' && typeof value.read === 'function' && typeof value.compareAndSwap === 'function') return value;
  F.reject('ledger is the folder of the spend ledger, or an object with read and compareAndSwap that stores it atomically');
}

module.exports = { LEDGER_FORMAT, fileLedger, ledgerOf, nameOf, encodeState, parseState };
