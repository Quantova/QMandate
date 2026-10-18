'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn, spawnSync } = require('child_process');

const CALL_LIMIT_MS = 2000;
const CLI_LIMIT_MS = 15000;

function iterations(base) {
  const v = Number(process.env.QFUZZ_ITERATIONS);
  return Number.isSafeInteger(v) && v > base ? v : base;
}

function mulberry32(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function canon(root) {
  const out = [];
  const stack = [{ v: root }];
  while (stack.length) {
    const item = stack.pop();
    if (item.text !== undefined) {
      out.push(item.text);
      continue;
    }
    const v = item.v;
    if (v === undefined) out.push('u');
    else if (v === null) out.push('n');
    else if (typeof v === 'number') out.push('#' + String(v));
    else if (typeof v === 'string') out.push('s' + JSON.stringify(v));
    else if (typeof v === 'boolean') out.push(v ? 't' : 'f');
    else if (typeof v === 'bigint') out.push('b' + v.toString());
    else if (Array.isArray(v)) {
      out.push('[');
      stack.push({ text: ']' });
      for (let i = v.length - 1; i >= 0; i -= 1) stack.push({ v: v[i] }, { text: ',' });
    } else if (typeof v === 'object') {
      out.push('{');
      stack.push({ text: '}' });
      const keys = Object.keys(v).sort();
      for (let i = keys.length - 1; i >= 0; i -= 1) stack.push({ v: v[keys[i]] }, { text: ',' + JSON.stringify(keys[i]) + ':' });
    } else out.push('?' + typeof v);
  }
  return out.join('');
}

function same(a, b) {
  return canon(a) === canon(b);
}

function copy(v) {
  if (Array.isArray(v)) return v.map(copy);
  if (v && typeof v === 'object') {
    const out = {};
    for (const k of Object.keys(v)) Object.defineProperty(out, k, { value: copy(v[k]), enumerable: true, writable: true, configurable: true });
    return out;
  }
  return v;
}

function put(obj, key, value) {
  Object.defineProperty(obj, key, { value, enumerable: true, writable: true, configurable: true });
}

const LOOKALIKE = {
  a: ['\u0430', '\uff41', '\u0251'], e: ['\u0435', '\uff45'], o: ['\u043e', '\u03bf', '0', '\uff4f'], p: ['\u0440'], c: ['\u0441', '\u03f2'], x: ['\u0445'], y: ['\u0443'], i: ['\u0456', '\u0131', 'l', '1'], l: ['1', 'I', '\u04cf'], s: ['\u0455'],
  A: ['\u0410', '\u0391', '\uff21'], B: ['\u0412', '\u0392'], C: ['\u0421'], E: ['\u0415', '\u0395'], H: ['\u041d'], I: ['\u0406', 'l', '1', '\u0399'], K: ['\u041a', '\u039a', 'K'], M: ['\u041c'], N: ['\u039d'], O: ['\u041e', '0', '\u039f', '\uff2f'], P: ['\u0420'], S: ['\u0405'], T: ['\u0422', '\u03a4'], X: ['\u0425'],
  0: ['O', '\u043e', '\uff10'], 1: ['l', 'I', '\uff11'], 2: ['\uff12'], 3: ['\uff13'], 5: ['S'], 8: ['B'], '-': ['\u2010', '\u2011', '\u2212', '\u2013'], ' ': ['\u00a0', '\u2009', '\u3000'], '.': ['\u2024'], '/': ['\u2215'], ':': ['\u2236'], '=': ['\uff1d'], '+': ['\uff0b'],
};
const INVISIBLE = ['\u200b', '\u200d', '\u2060', '\ufeff', '\u202e', '\u0000', '\u00ad', '\u180e'];
const NUMBER_EDGES = [-0, 0, -1, 1e3, 1.5, 0.1, 2 ** 31, 2 ** 32, 2 ** 53 - 1, 2 ** 53, 2 ** 53 + 2, 2 ** 63, 2 ** 64, 1e21, 1e308, -1e308, Number.MIN_VALUE, -(2 ** 53), NaN, Infinity, -Infinity];
const NUMBER_TEXT = ['-0', '0', '00', '01', '007', '1e3', '1E3', '1e+3', '1.0', '0x10', '0b1', '0o7', '+1', ' 1', '1 ', '1_000', '1,000', '\u0661', '\uff11', '9007199254740991', '9007199254740992', '9007199254740993',
  '18446744073709551615', '18446744073709551616', '-9223372036854775808', '9223372036854775807', '9223372036854775808', '340282366920938463463374607431768211456', '1' + '0'.repeat(30), '9'.repeat(31), '-1', 'NaN', 'Infinity'];
const ODD_STRINGS = ['', ' ', 'null', 'true', '__proto__', 'constructor', 'prototype', 'toString', 'hasOwnProperty', '\ud800', '\udfff', '\u{1f600}', '\u00e9', '\u00e9', '\u0130', '\u00df', '\ufb01', 'A'.repeat(70000), '0'.repeat(64), 'F'.repeat(64),
  '2026-02-30T00:00:00.000Z', '2026-13-01T00:00:00.000Z', '2026-01-01T24:00:00.000Z', '2026-01-01T00:00:60.000Z', '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00Z', '+275760-09-13T00:00:00.000Z', '1970-01-01T00:00:00.000Z', '9999-12-31T23:59:59.999Z'];
const EXTRA_KEYS = ['extra', 'anchor', 'anchors', 'note', 'Format', 'format ', 'signature\u200b', 'statement', 'type', 'version', 'receipts', 'valid', 'status'];

function mutator(seed, extraPool) {
  const rnd = mulberry32(seed);
  const int = (n) => Math.floor(rnd() * n);
  const pick = (a) => a[int(a.length)];
  const pool = [];
  const deepPool = Array.isArray(extraPool) ? extraPool : [];

  function entries(root) {
    const out = [{ path: [], value: root, parent: null, key: null }];
    for (let i = 0; i < out.length && out.length < 20000; i += 1) {
      const e = out[i];
      const v = e.value;
      if (v && typeof v === 'object' && e.path.length < 64) {
        for (const k of Object.keys(v)) out.push({ path: e.path.concat([k]), value: v[k], parent: v, key: k });
      }
    }
    return out;
  }
  const isObject = (x) => x !== null && typeof x === 'object' && !Array.isArray(x);
  function set(root, e, value) {
    if (e.parent === null) return value;
    put(e.parent, e.key, value);
    return root;
  }
  function del(root, e) {
    if (e.parent === null) return root;
    if (Array.isArray(e.parent)) e.parent.splice(Number(e.key), 1);
    else delete e.parent[e.key];
    return root;
  }
  const leaves = (v, test) => entries(v).filter((e) => e.parent !== null && test(e.value));
  const nodes = (v) => entries(v).filter((e) => e.parent !== null);
  const objects = (v) => entries(v).filter((e) => isObject(e.value));

  function lookalike(s) {
    if (!s.length) return pick(INVISIBLE);
    const spots = [];
    for (let i = 0; i < s.length; i += 1) if (LOOKALIKE[s[i]]) spots.push(i);
    const r = int(5);
    if (r === 0 || spots.length === 0) {
      const i = int(s.length + 1);
      return s.slice(0, i) + pick(INVISIBLE) + s.slice(i);
    }
    if (r === 1) return s.normalize('NFD') === s ? s + '\u0301' : s.normalize('NFD');
    if (r === 2) return s.replace(/[!-~]/g, (c) => String.fromCharCode(c.charCodeAt(0) + 0xfee0));
    const i = pick(spots);
    return s.slice(0, i) + pick(LOOKALIKE[s[i]]) + s.slice(i + 1);
  }

  function changeString(s) {
    const ops = [
      () => s.toUpperCase(), () => s.toLowerCase(), () => s + 'x', () => s.slice(0, -1), () => s.slice(1), () => ' ' + s, () => s + ' ', () => s + s,
      () => { if (!s.length) return 'x'; const i = int(s.length); return s.slice(0, i) + String.fromCharCode(s.charCodeAt(i) ^ (1 << int(7))) + s.slice(i + 1); },
      () => s.split('').reverse().join(''), () => pick(ODD_STRINGS), () => (pool.length ? pick(pool) : 'x'), () => (deepPool.length ? pick(deepPool) : 'y'),
      () => s.replace(/Z$/, '+00:00'), () => s.replace(/\.\d{3}Z$/, 'Z'), () => s.replace(/T/, ' '), () => s.replace(/\d(?=\D*$)/, (d) => String((Number(d) + 1) % 10)),
    ];
    return pick(ops)();
  }

  function otherType(v) {
    const t = Array.isArray(v) ? 'array' : v === null ? 'null' : typeof v;
    const ops = [() => null, () => true, () => false, () => 0, () => 1, () => [], () => ({}), () => [v], () => ({ value: v }), () => String(v), () => undefined];
    if (t === 'string') ops.push(() => Number(v), () => (/^\d+$/.test(v) ? BigInt(v) : 1n), () => Buffer.from(v).toJSON(), () => Array.from(v));
    if (t === 'number') ops.push(() => String(v), () => BigInt(Math.trunc(Number.isFinite(v) ? v : 0)), () => [v]);
    for (;;) {
      const nv = pick(ops)();
      if (!same(nv, v)) return nv;
    }
  }

  function numberEdge(v) {
    if (typeof v === 'number') return pick([() => pick(NUMBER_EDGES), () => String(v), () => v + 1, () => v - 1, () => -v, () => v * 1000, () => v + 0.5, () => BigInt(Math.trunc(v)), () => pick(NUMBER_TEXT)])();
    if (typeof v === 'string' && /^\d+$/.test(v)) return pick([() => '0' + v, () => '00' + v, () => v + '.0', () => v + 'e0', () => (BigInt(v) * 1000n).toString(), () => (BigInt(v) + 1n).toString(), () => (v === '0' ? '1' : (BigInt(v) - 1n).toString()), () => '+' + v, () => '-' + v, () => ' ' + v, () => Number(v), () => -0, () => pick(NUMBER_TEXT), () => pick(NUMBER_EDGES)])();
    return pick([() => pick(NUMBER_EDGES), () => pick(NUMBER_TEXT)])();
  }

  function encoding(s) {
    if (/^[0-9a-f]+$/.test(s) && s.length % 2 === 0) {
      return pick([
        () => s.toUpperCase(), () => s.replace(/[a-f]/, (c) => c.toUpperCase()), () => s.slice(0, -1), () => s + '0', () => s + '00', () => '0x' + s, () => s.slice(2),
        () => Buffer.from(s, 'hex').toString('base64'), () => s.slice(0, 32) + ' ' + s.slice(32),
        () => { const i = int(s.length); return s.slice(0, i) + ((parseInt(s[i], 16) ^ (1 << int(4))).toString(16)) + s.slice(i + 1); },
      ])();
    }
    if (/^[A-Za-z0-9+/]+={0,2}$/.test(s) && s.length >= 8) {
      return pick([
        () => s.replace(/=+$/, ''), () => s + '=', () => s + '==', () => s.replace(/\+/g, '-').replace(/\//g, '_'), () => s.slice(0, 40) + '\n' + s.slice(40), () => s.slice(0, 40) + ' ' + s.slice(40),
        () => s.toLowerCase(), () => s.toUpperCase(), () => s.slice(0, -4), () => s + 'AAAA', () => Buffer.from(s, 'base64').toString('hex'),
        () => { const b = Buffer.from(s, 'base64'); return Buffer.concat([b, Buffer.from([0])]).toString('base64'); },
        () => { const b = Buffer.from(s, 'base64'); return b.subarray(0, b.length - 1).toString('base64'); },
        () => { const t = s.replace(/=+$/, ''); const last = t[t.length - 1]; const alt = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'; const idx = alt.indexOf(last); return t.slice(0, -1) + alt[idx ^ 1] + s.slice(t.length); },
      ])();
    }
    return changeString(s);
  }

  function flipBytes(s) {
    if (/^[A-Za-z0-9+/]+={0,2}$/.test(s) && s.length >= 16) {
      const b = Buffer.from(s, 'base64');
      const n = 1 + int(3);
      for (let i = 0; i < n; i += 1) b[int(b.length)] ^= 1 << int(8);
      return b.toString('base64');
    }
    if (/^[0-9a-f]+$/.test(s) && s.length % 2 === 0 && s.length >= 2) {
      const b = Buffer.from(s, 'hex');
      b[int(b.length)] ^= 1 << int(8);
      return b.toString('hex');
    }
    return encoding(s);
  }

  const MUTATIONS = {
    value(out) {
      const es = leaves(out, (x) => typeof x === 'string' || typeof x === 'number' || typeof x === 'boolean');
      if (!es.length) return out;
      const e = pick(es);
      const v = e.value;
      return set(out, e, typeof v === 'string' ? changeString(v) : typeof v === 'number' ? v + 1 + int(5) : !v);
    },
    remove(out) {
      const es = nodes(out);
      return es.length ? del(out, pick(es)) : out;
    },
    add(out) {
      const es = objects(out);
      if (!es.length) return { value: out };
      const o = pick(es).value;
      const k = pick(EXTRA_KEYS.concat(Object.keys(o).map((x) => x + '\u200b'), Object.keys(o).map((x) => x.toUpperCase())));
      if (Object.prototype.hasOwnProperty.call(o, k)) put(o, k + '_', 1);
      else put(o, k, pick([1, 'x', null, {}, [], true, pick(pool.length ? pool : ['z'])]));
      return out;
    },
    retype(out) {
      const e = pick(entries(out));
      return set(out, e, otherType(e.value));
    },
    lookalike(out) {
      const es = leaves(out, (x) => typeof x === 'string');
      if (!es.length) return out;
      const e = pick(es);
      return set(out, e, lookalike(e.value));
    },
    number(out) {
      const nums = leaves(out, (x) => typeof x === 'number' || (typeof x === 'string' && /^\d+$/.test(x)));
      const es = nums.length && int(4) ? nums : nodes(out);
      if (!es.length) return out;
      const e = pick(es);
      return set(out, e, numberEdge(e.value));
    },
    encoding(out) {
      const es = leaves(out, (x) => typeof x === 'string' && (/^[0-9a-f]{16,}$/.test(x) || /^[A-Za-z0-9+/]{16,}={0,2}$/.test(x)));
      if (!es.length) return out;
      const e = pick(es);
      return set(out, e, encoding(e.value));
    },
    signature(out) {
      const es = leaves(out, (x) => typeof x === 'string' && x.length >= 64 && (/^[0-9a-f]+$/.test(x) || /^[A-Za-z0-9+/]+={0,2}$/.test(x)));
      if (!es.length) return out;
      const sig = es.filter((e) => /signature/i.test(e.key));
      const e = sig.length && int(3) ? pick(sig) : pick(es);
      return set(out, e, flipBytes(e.value));
    },
    format(out) {
      const es = leaves(out, (x) => typeof x === 'string' && /^[a-z0-9-]+\/\d+$/.test(x));
      const f = es.length ? null : 'x/1';
      const e = es.length ? pick(es) : null;
      const value = e ? e.value : f;
      const [name, ver] = value.split('/');
      const variants = [value + value, value + ' ' + value, [value, value], { format: value }, value + '/' + ver, name.toUpperCase() + '/' + ver, name + '/0' + ver, name + '/' + (Number(ver) + 1), name + '/' + (Number(ver) - 1), value + '\u0000', ' ' + value, value + ' ', name + '\u200b/' + ver, name + '-' + ver, name + '/' + ver + '.0', 'qstamp/1', 'qsign/1', 'qmandate/2', 'qspend/1', 'qtax/1'];
      let nv = pick(variants);
      if (same(nv, value)) nv = value + value;
      if (!e) {
        if (isObject(out)) put(out, 'format', nv);
        return out;
      }
      return set(out, e, nv);
    },
    proto(out) {
      const es = objects(out);
      if (!es.length) return { __proto_target: out };
      const o = pick(es).value;
      const r = int(6);
      const keys = Object.keys(o).filter((k) => k !== '__proto__');
      if (r === 0) put(o, '__proto__', { polluted: true, isAdmin: true });
      else if (r === 1) put(o, 'constructor', { prototype: { polluted: true } });
      else if (r === 2) put(o, '__proto__', pick([null, 'x', [], { valid: true, status: 'valid' }]));
      else if (r === 3) put(o, 'prototype', { valid: true });
      else if (r === 4 && keys.length) {
        const k = pick(keys);
        const v = o[k];
        delete o[k];
        const holder = {};
        put(holder, k, v);
        put(o, '__proto__', holder);
      } else if (keys.length) {
        const k = pick(keys);
        const proto = { polluted: true };
        put(proto, k, o[k]);
        delete o[k];
        Object.setPrototypeOf(o, proto);
      } else put(o, '__proto__', { polluted: true });
      return out;
    },
    structure(out) {
      const r = int(5);
      const e = pick(entries(out));
      const v = e.value;
      if (r === 0) {
        let o = v;
        for (let i = 0; i < 3000; i += 1) o = { a: o };
        return set(out, e, o);
      }
      if (r === 1) return set(out, e, Array.from({ length: 5000 }, () => (v && typeof v === 'object' ? {} : v)));
      if (r === 2) return set(out, e, [v, v]);
      if (r === 3) return set(out, e, 'x'.repeat(1 << 20));
      return [out];
    },
  };
  const NAMES = Object.keys(MUTATIONS);

  function textMutate(text) {
    const keyRe = /"([A-Za-z]+)":("(?:[^"\\]|\\.)*"|-?\d+)/g;
    const keys = [...text.matchAll(keyRe)];
    const k = keys.length ? pick(keys) : null;
    const ops = [
      () => (k ? text.slice(0, k.index) + '"' + k[1] + '":"x",' + text.slice(k.index) : text + ' '),
      () => (k ? text.slice(0, k.index + k[0].length) + ',"' + k[1] + '":"x"' + text.slice(k.index + k[0].length) : text + ' '),
      () => text.replace(/\{/, '{"__proto__":{"isAdmin":true},'),
      () => text.replace(/:(\d+)/, ':$1.0'), () => text.replace(/:(\d+)/, ':$1e0'), () => text.replace(/:(\d+)/, ':-0'), () => text.replace(/:(\d+)/, ':0$1'),
      () => text.replace(/"format":"([^"]*)"/, '"format":"$1","format":"$1"'),
      () => text.replace(/"format":"([^"]*)"/, '"format":"$1","format":"other/1"'),
      () => '[' + text + ']', () => '\ufeff' + text, () => text.slice(0, -1), () => text.replace(/,/, ',,'), () => text.replace(/"/, "'"),
      () => '['.repeat(5000) + ']'.repeat(5000), () => text.replace(/:/, ':' + '['.repeat(3000) + '1' + ']'.repeat(3000) + ',"x":'),
      () => text.replace(/\\u|"([0-9a-f])/, (m, c) => (c ? '"\\u00' + c.charCodeAt(0).toString(16) : m)),
    ];
    return pick(ops)();
  }

  function mutate(base, i) {
    if (!pool.length) for (const e of entries(base)) if (typeof e.value === 'string' && e.value.length < 200 && !pool.includes(e.value)) pool.push(e.value);
    const which = i === undefined ? pick(NAMES.concat(['text'])) : (NAMES.concat(['text']))[i % (NAMES.length + 1)];
    if (which === 'text') {
      const text = textMutate(JSON.stringify(base));
      try {
        return { op: which, value: JSON.parse(text) };
      } catch (e) {
        return { op: which, value: text };
      }
    }
    let out = copy(base);
    const rounds = int(4) === 0 ? 2 : 1;
    for (let r = 0; r < rounds; r += 1) out = MUTATIONS[r === 0 ? which : pick(NAMES)](out);
    return { op: which, value: out };
  }

  return { rnd, int, pick, mutate, textMutate, lookalike, NAMES: NAMES.concat(['text']) };
}

async function timed(fn) {
  const t0 = process.hrtime.bigint();
  let result;
  let error;
  try {
    result = await fn();
  } catch (e) {
    error = e;
  }
  return { result, error, ms: Number(process.hrtime.bigint() - t0) / 1e6 };
}

function describe(v) {
  let s;
  try {
    s = JSON.stringify(v, (k, x) => (typeof x === 'bigint' ? x.toString() + 'n' : x));
  } catch (e) {
    s = 'a value nested too deeply to print';
  }
  return String(s).slice(0, 300);
}

function changes(base, value) {
  const out = [];
  const stack = [[base, value, '']];
  while (stack.length && out.length < 6) {
    const [a, b, p] = stack.pop();
    if (canon(a) === canon(b)) continue;
    const objects = a && b && typeof a === 'object' && typeof b === 'object' && Array.isArray(a) === Array.isArray(b) && p.split('.').length < 8;
    if (objects) {
      for (const k of new Set(Object.keys(a).concat(Object.keys(b)))) stack.push([a[k], b[k], p + '.' + k]);
      if (Object.getPrototypeOf(b) !== Object.getPrototypeOf(a)) out.push((p || '.') + ' has another prototype');
    } else out.push((p || '.') + ' ' + describe(a).slice(0, 80) + ' became ' + describe(b).slice(0, 120));
  }
  return out.join(' | ');
}

async function campaign(o) {
  const assert = require('node:assert');
  const n = iterations(o.iterations || 1000);
  const m = mutator(o.seed, o.pool);
  const stats = { iterations: n, mutated: 0, unchanged: 0, threw: 0, maxMs: 0, ops: {} };
  const baseForm = canon(o.base);
  for (let i = 0; i < n; i += 1) {
    const { op, value } = m.mutate(o.base, i);
    if (o.skip ? o.skip(value) : canon(value) === baseForm) {
      stats.unchanged += 1;
      continue;
    }
    stats.mutated += 1;
    stats.ops[op] = (stats.ops[op] || 0) + 1;
    const r = await timed(() => o.check(value));
    if (r.ms > stats.maxMs) stats.maxMs = Math.round(r.ms * 10) / 10;
    assert.ok(r.ms < (o.limitMs || CALL_LIMIT_MS), o.name + ' iteration ' + i + ' (' + op + ') took ' + Math.round(r.ms) + ' ms on ' + describe(value));
    if (r.error) {
      stats.threw += 1;
      const code = r.error && r.error.code;
      assert.ok(typeof code === 'string' && code.startsWith(o.code), o.name + ' iteration ' + i + ' (' + op + ') threw without the ' + o.code + ' code, ' + (r.error && r.error.name) + ' ' + (r.error && r.error.message) + ' on ' + changes(o.base, value));
      continue;
    }
    assert.ok(!o.valid(r.result), o.name + ' iteration ' + i + ' (' + op + ') accepted a changed input, ' + changes(o.base, value));
  }
  assert.ok(stats.mutated >= Math.min(n, 1000) * 0.9, o.name + ' produced only ' + stats.mutated + ' changed inputs');
  return stats;
}

function tempDir(tag) {
  return fs.mkdtempSync(path.join(os.tmpdir(), tag + '-'));
}

const OFFLINE = path.join(__dirname, 'offline.js');

function runCli(bin, args, limitMs) {
  return new Promise((resolve) => {
    const t0 = Date.now();
    const child = spawn(process.execPath, ['-r', OFFLINE, bin].concat(args), { stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    let err = '';
    child.stdout.on('data', (d) => { if (out.length < 1 << 20) out += d; });
    child.stderr.on('data', (d) => { if (err.length < 1 << 20) err += d; });
    const timer = setTimeout(() => child.kill('SIGKILL'), limitMs || CLI_LIMIT_MS);
    child.on('close', (code, signal) => {
      clearTimeout(timer);
      resolve({ code, signal, out, err, ms: Date.now() - t0 });
    });
  });
}

function hostileFiles(dir, validText, cap) {
  const files = [];
  const add = (name, content) => {
    const f = path.join(dir, name);
    fs.writeFileSync(f, content);
    files.push({ name, file: f });
  };
  const text = validText;
  const firstKey = text.match(/^\{"([^"]+)":/);
  add('repeated-top-key.json', firstKey ? text.replace(/^\{/, '{"' + firstKey[1] + '":"x",') : '{"a":1,"a":2}');
  add('repeated-last-key.json', text.replace(/\}$/, ',"signature":"x"}'));
  const inner = /":\{"([^"]+)":/.test(text) ? text.replace(/":\{"([^"]+)":/, '":{"$1":"x","$1":') : text.replace(/\}$/, ',"x":{"y":1,"y":2}}');
  add('repeated-inner-key.json', inner);
  add('repeated-key-escaped.json', firstKey ? text.replace(/^\{/, '{"\\u00' + firstKey[1].charCodeAt(0).toString(16) + firstKey[1].slice(1) + '":"x",') : '{"a":1,"\\u0061":2}');
  add('deep-array.json', '['.repeat(200000) + ']'.repeat(200000));
  add('deep-object.json', '{"a":'.repeat(100000) + '1' + '}'.repeat(100000));
  add('deep-inside.json', text.replace(/\}$/, ',"x":' + '{"a":'.repeat(50000) + '1' + '}'.repeat(50000) + '}'));
  add('proto-top.json', text.replace(/^\{/, '{"__proto__":{"isAdmin":true,"valid":true},'));
  add('proto-inner.json', /":\{"/.test(text) ? text.replace(/":\{"/, '":{"__proto__":{"valid":true},"') : text.replace(/\}$/, ',"x":{"__proto__":{"valid":true}}}'));
  add('constructor-top.json', text.replace(/^\{/, '{"constructor":{"prototype":{"valid":true}},'));
  const pad = Math.max(0, cap + 4096 - Buffer.byteLength(text));
  add('over-cap.json', text.replace(/\}$/, ' '.repeat(pad) + '}'));
  add('over-cap-string.json', '{"x":"' + 'a'.repeat(cap + 4096) + '"}');
  const sub = path.join(dir, 'a-directory');
  fs.mkdirSync(sub);
  files.push({ name: 'directory', file: sub });
  if (process.platform !== 'win32') {
    const fifo = path.join(dir, 'a-fifo');
    const r = spawnSync('mkfifo', [fifo]);
    if (r.status === 0) files.push({ name: 'fifo', file: fifo });
    if (fs.existsSync('/dev/zero')) files.push({ name: 'dev-zero', file: '/dev/zero' });
    if (fs.existsSync('/dev/urandom')) files.push({ name: 'dev-urandom', file: '/dev/urandom' });
    const link = path.join(dir, 'a-link.json');
    try {
      fs.symlinkSync('/dev/zero', link);
      files.push({ name: 'symlink-to-dev-zero', file: link });
    } catch (e) {
      void e;
    }
  }
  return files.filter((f) => {
    try {
      return !fs.lstatSync(f.file).isFile() || fs.readFileSync(f.file, 'utf8') !== text;
    } catch (e) {
      return true;
    }
  });
}

const SAYS_VALID = /(?<![A-Za-z])VALID(?![A-Za-z])|"status"\s*:\s*"valid"|"valid"\s*:\s*true/;

async function cliCampaign(o) {
  const assert = require('node:assert');
  const dir = tempDir(o.tag || 'qcli');
  const results = [];
  try {
    const files = hostileFiles(dir, o.validText, o.cap);
    for (const variant of o.commands) {
      const runs = await Promise.all(files.map(async (f) => ({ f, r: await runCli(o.bin, variant(f.file), o.limitMs) })));
      for (const { f, r } of runs) {
        const where = f.name + ' with ' + variant('FILE').join(' ');
        assert.strictEqual(r.signal, null, where + ' did not finish within the limit, it was stopped after ' + r.ms + ' ms');
        assert.notStrictEqual(r.code, 0, where + ' exited 0\n' + r.out.slice(0, 400));
        assert.ok(!SAYS_VALID.test(r.out) && !SAYS_VALID.test(r.err), where + ' printed VALID\n' + r.out.slice(0, 400));
        results.push({ name: f.name, code: r.code, ms: r.ms });
      }
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  return results;
}

module.exports = { iterations, mulberry32, mutator, campaign, canon, same, copy, timed, changes, describe, runCli, cliCampaign, hostileFiles, tempDir, CALL_LIMIT_MS, SAYS_VALID };
