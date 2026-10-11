// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const nodeCrypto = require('crypto');

const FORMAT = 'qmandate/1';
const ALGORITHM = 'ML-DSA-65';
const TYPES = Object.freeze(['mandate', 'action', 'revoke']);
const KEY_DOMAIN = Buffer.from('quantova/qmandate/key/1', 'ascii');
const REF_DOMAIN = Buffer.from('quantova/qmandate/ref/1', 'ascii');
const ANCHOR_DOMAIN = Buffer.from('quantova/qmandate/anchor/1', 'ascii');
const MAGIC = Buffer.from('QMDT', 'ascii');
const VERSION = 1;
const PUBLIC_KEY_BYTES = 1952;
const SIGNATURE_BYTES = 3309;
const LABEL_MAX = 200;
const NOTE_MAX = 1000;
const SCOPES_MAX = 64;
const COUNTERPARTIES_MAX = 256;
const HEX32 = /^[0-9a-f]{64}$/;
const HEX16 = /^[0-9a-f]{32}$/;
const ACTION_NAME = /^(?=.{1,64}$)[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$/;
const MAX_LIFETIME_MS = 10 * 366 * 24 * 3600 * 1000;
const CURRENCY = /^([A-Z]{3})?$/;
const AMOUNT = /^(0|[1-9][0-9]{0,29})$/;
const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const UNSAFE_TEXT = /[\p{Cc}\p{Cf}\p{Co}\p{Zl}\p{Zp}\p{Default_Ignorable_Code_Point}\u00a0\u1680\u2000-\u200a\u202f\u205f\u3000\u2800\u115f\u1160\u3164\uffa0]/u;

const FIELDS = Object.freeze({
  mandate: ['mandateId', 'principalKeyId', 'agentKeyId', 'agentLabel', 'scopes', 'counterparties', 'validFrom', 'validUntil', 'issuedAt', 'note'],
  action: ['mandateId', 'mandateRef', 'actionId', 'agentKeyId', 'action', 'currency', 'amount', 'counterparty', 'detailsDigest', 'actedAt', 'note'],
  revoke: ['mandateId', 'mandateRef', 'principalKeyId', 'revokedAt', 'note'],
});

function fail(message) {
  const e = new Error('the envelope is not valid, ' + message);
  e.code = 'QMANDATE_INVALID_ENVELOPE';
  throw e;
}

function reject(message) {
  const e = new Error(message);
  e.code = 'QMANDATE_INVALID_INPUT';
  throw e;
}

function sha3(...parts) {
  const h = nodeCrypto.createHash('sha3-256');
  for (const p of parts) h.update(p);
  return h.digest();
}

function keyIdOf(publicKey) {
  if (!(publicKey instanceof Uint8Array) || publicKey.length !== PUBLIC_KEY_BYTES) reject('a public key is ' + PUBLIC_KEY_BYTES + ' bytes');
  return sha3(KEY_DOMAIN, Buffer.from([0]), publicKey).toString('hex');
}

function textProblem(value, max, what) {
  if (typeof value !== 'string') return what + ' must be text';
  if (value.length > max) return what + ' is longer than ' + max + ' characters';
  if (!value.isWellFormed()) return what + ' holds a broken Unicode surrogate';
  if (value.normalize('NFC') !== value) return what + ' must be in Unicode normal form C';
  if (UNSAFE_TEXT.test(value)) return what + ' holds control, invisible or direction characters';
  return null;
}

function timeProblem(value, what) {
  if (typeof value !== 'string' || !ISO_UTC.test(value)) return what + ' must be an ISO 8601 UTC time with milliseconds and a Z suffix';
  const ms = Date.parse(value);
  if (!Number.isFinite(ms) || new Date(ms).toISOString() !== value) return what + ' is not a real calendar time';
  return null;
}

function pattern(value, re, what, rule) {
  if (typeof value !== 'string' || !re.test(value)) return what + ' must be ' + rule;
  return null;
}

function scopesProblem(scopes) {
  if (!Array.isArray(scopes) || scopes.length === 0 || scopes.length > SCOPES_MAX) return 'scopes must list 1 to ' + SCOPES_MAX + ' permitted actions';
  const seen = new Set();
  for (const s of scopes) {
    if (s === null || typeof s !== 'object' || Array.isArray(s)) return 'each scope must be an object';
    const keys = Object.keys(s).sort().join(',');
    if (keys !== 'action,currency,maxPerAction,maxTotal') return 'each scope holds exactly action, currency, maxPerAction and maxTotal';
    const p = pattern(s.action, ACTION_NAME, 'a scope action', 'lowercase letters, digits, dots or underscores starting with a letter')
      || pattern(s.currency, CURRENCY, 'a scope currency', 'a three letter ISO 4217 code, or empty for actions without an amount')
      || pattern(s.maxPerAction, AMOUNT, 'maxPerAction', 'a whole number of minor units')
      || pattern(s.maxTotal, AMOUNT, 'maxTotal', 'a whole number of minor units');
    if (p) return p;
    if (s.currency === '' && (s.maxPerAction !== '0' || s.maxTotal !== '0')) return 'a scope without a currency must set both limits to 0';
    if (BigInt(s.maxPerAction) > BigInt(s.maxTotal)) return 'maxPerAction cannot exceed maxTotal';
    if (seen.has(s.action)) return 'each action may appear in only one scope';
    seen.add(s.action);
  }
  return null;
}

function counterpartiesProblem(list) {
  if (!Array.isArray(list) || list.length > COUNTERPARTIES_MAX) return 'counterparties must list at most ' + COUNTERPARTIES_MAX + ' entries';
  const seen = new Set();
  for (const c of list) {
    const p = textProblem(c, LABEL_MAX, 'a counterparty');
    if (p) return p;
    if (c.length === 0) return 'a counterparty cannot be empty';
    if (seen.has(c)) return 'a counterparty is listed twice';
    seen.add(c);
  }
  return null;
}

function statementProblem(type, st) {
  if (!TYPES.includes(type)) return 'type must be one of ' + TYPES.join(', ');
  if (st === null || typeof st !== 'object' || Array.isArray(st)) return 'the statement must be an object';
  const want = FIELDS[type].slice().sort().join(',');
  if (Object.keys(st).sort().join(',') !== want) return 'a ' + type + ' statement holds exactly ' + FIELDS[type].join(', ');
  const checks = [];
  checks.push(pattern(st.mandateId, HEX16, 'mandateId', '32 lowercase hex characters'));
  checks.push(textProblem(st.note, NOTE_MAX, 'note'));
  if (type === 'mandate') {
    checks.push(pattern(st.principalKeyId, HEX32, 'principalKeyId', '64 lowercase hex characters'));
    checks.push(pattern(st.agentKeyId, HEX32, 'agentKeyId', '64 lowercase hex characters'));
    checks.push(textProblem(st.agentLabel, LABEL_MAX, 'agentLabel'));
    checks.push(scopesProblem(st.scopes));
    checks.push(counterpartiesProblem(st.counterparties));
    checks.push(timeProblem(st.validFrom, 'validFrom'), timeProblem(st.validUntil, 'validUntil'), timeProblem(st.issuedAt, 'issuedAt'));
    if (!checks.some(Boolean) && Date.parse(st.validFrom) >= Date.parse(st.validUntil)) checks.push('validFrom must be earlier than validUntil');
    if (!checks.some(Boolean) && Date.parse(st.validUntil) - Date.parse(st.validFrom) > MAX_LIFETIME_MS) checks.push('a mandate may last at most ten years');
    if (!checks.some(Boolean) && st.principalKeyId === st.agentKeyId) checks.push('the agent key must differ from the principal key');
  } else if (type === 'action') {
    checks.push(pattern(st.mandateRef, HEX32, 'mandateRef', '64 lowercase hex characters'));
    checks.push(pattern(st.actionId, HEX16, 'actionId', '32 lowercase hex characters'));
    checks.push(pattern(st.agentKeyId, HEX32, 'agentKeyId', '64 lowercase hex characters'));
    checks.push(pattern(st.action, ACTION_NAME, 'action', 'lowercase letters, digits, dots or underscores starting with a letter'));
    checks.push(pattern(st.currency, CURRENCY, 'currency', 'a three letter ISO 4217 code, or empty'));
    checks.push(pattern(st.amount, AMOUNT, 'amount', 'a whole number of minor units'));
    checks.push(textProblem(st.counterparty, LABEL_MAX, 'counterparty'));
    checks.push(pattern(st.detailsDigest, HEX32, 'detailsDigest', '64 lowercase hex characters'));
    checks.push(timeProblem(st.actedAt, 'actedAt'));
  } else {
    checks.push(pattern(st.mandateRef, HEX32, 'mandateRef', '64 lowercase hex characters'));
    checks.push(pattern(st.principalKeyId, HEX32, 'principalKeyId', '64 lowercase hex characters'));
    checks.push(timeProblem(st.revokedAt, 'revokedAt'));
  }
  return checks.find(Boolean) || null;
}

function field(buf) {
  if (buf.length > 0xffff) reject('a signed field is too long');
  const len = Buffer.alloc(2);
  len.writeUInt16BE(buf.length);
  return Buffer.concat([len, buf]);
}

function count(n) {
  const b = Buffer.alloc(2);
  b.writeUInt16BE(n);
  return field(b);
}

const ascii = (s) => field(Buffer.from(s, 'ascii'));
const utf8 = (s) => field(Buffer.from(s, 'utf8'));
const hex = (s) => field(Buffer.from(s, 'hex'));

function payload(type, st) {
  const parts = [MAGIC, Buffer.from([VERSION]), ascii(type), hex(st.mandateId)];
  if (type === 'mandate') {
    parts.push(hex(st.principalKeyId), hex(st.agentKeyId), utf8(st.agentLabel), count(st.scopes.length));
    for (const s of st.scopes) parts.push(ascii(s.action), ascii(s.currency), ascii(s.maxPerAction), ascii(s.maxTotal));
    parts.push(count(st.counterparties.length));
    for (const c of st.counterparties) parts.push(utf8(c));
    parts.push(ascii(st.validFrom), ascii(st.validUntil), ascii(st.issuedAt));
  } else if (type === 'action') {
    parts.push(hex(st.mandateRef), hex(st.actionId), hex(st.agentKeyId), ascii(st.action), ascii(st.currency), ascii(st.amount), utf8(st.counterparty), hex(st.detailsDigest), ascii(st.actedAt));
  } else {
    parts.push(hex(st.mandateRef), hex(st.principalKeyId), ascii(st.revokedAt));
  }
  parts.push(utf8(st.note));
  return Buffer.concat(parts);
}

function decodeBase64(value, bytes, what) {
  if (typeof value !== 'string' || value.length !== Math.ceil(bytes / 3) * 4) fail(what + ' must be base64 of ' + bytes + ' bytes');
  const raw = Buffer.from(value, 'base64');
  if (raw.toString('base64') !== value || raw.length !== bytes) fail(what + ' is not canonical base64 of ' + bytes + ' bytes');
  return raw;
}

function exactKeys(obj, required, optional, where) {
  if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) fail(where + ' must be an object');
  const allowed = new Set(required.concat(optional));
  for (const k of Object.keys(obj)) if (!allowed.has(k)) fail(where + ' holds an unexpected field');
  for (const k of required) if (!Object.prototype.hasOwnProperty.call(obj, k)) fail(where + ' is missing ' + k);
}

function plainCopy(value, depth) {
  const d = depth === undefined ? 0 : depth;
  if (d > 6) throw new Error('nested too deeply');
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('not a finite number');
    return value;
  }
  if (typeof value !== 'object') throw new Error('not plain data');
  const proto = Object.getPrototypeOf(value);
  if (Array.isArray(value)) {
    if (proto !== Array.prototype) throw new Error('not a plain array');
    const out = [];
    for (let i = 0; i < value.length; i += 1) {
      const desc = Object.getOwnPropertyDescriptor(value, i);
      if (!desc || !('value' in desc)) throw new Error('not plain data');
      out.push(plainCopy(desc.value, d + 1));
    }
    return out;
  }
  if (proto !== Object.prototype && proto !== null) throw new Error('not a plain object');
  const out = {};
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string') throw new Error('not plain data');
    const desc = Object.getOwnPropertyDescriptor(value, key);
    if (!('value' in desc) || !desc.enumerable) throw new Error('not plain data');
    Object.defineProperty(out, key, { value: plainCopy(desc.value, d + 1), enumerable: true, writable: true, configurable: true });
  }
  return out;
}

function parse(envelope) {
  exactKeys(envelope, ['format', 'type', 'algorithm', 'signer', 'statement', 'signature'], ['anchor'], 'the envelope');
  if (envelope.format !== FORMAT) fail('format must be ' + FORMAT);
  if (envelope.algorithm !== ALGORITHM) fail('algorithm must be ' + ALGORITHM);
  if (!TYPES.includes(envelope.type)) fail('type must be one of ' + TYPES.join(', '));
  exactKeys(envelope.signer, ['id', 'publicKey'], [], 'signer');
  if (typeof envelope.signer.id !== 'string' || !HEX32.test(envelope.signer.id)) fail('signer.id must be 64 lowercase hex characters');
  const publicKey = decodeBase64(envelope.signer.publicKey, PUBLIC_KEY_BYTES, 'signer.publicKey');
  let statement;
  try {
    statement = plainCopy(envelope.statement);
  } catch (e) {
    fail('the statement is not plain data');
  }
  const problem = statementProblem(envelope.type, statement);
  if (problem) fail(problem);
  const signature = decodeBase64(envelope.signature, SIGNATURE_BYTES, 'signature');
  const anchor = Object.prototype.hasOwnProperty.call(envelope, 'anchor') ? envelope.anchor : undefined;
  return { type: envelope.type, signerId: envelope.signer.id, publicKey, statement, signature, anchor };
}

function refOf(parsed) {
  return sha3(REF_DOMAIN, Buffer.from([0]), payload(parsed.type, parsed.statement), parsed.signature).toString('hex');
}

function anchorDigest(parsed) {
  return sha3(ANCHOR_DOMAIN, Buffer.from([0]), payload(parsed.type, parsed.statement), parsed.signature);
}

module.exports = {
  FORMAT, ALGORITHM, TYPES, FIELDS, PUBLIC_KEY_BYTES, SIGNATURE_BYTES, LABEL_MAX, NOTE_MAX,
  sha3, keyIdOf, textProblem, timeProblem, statementProblem, payload, parse, refOf, anchorDigest, reject, plainCopy,
};
