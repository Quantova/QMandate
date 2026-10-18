// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const OLD = /the installed Qstamp is older than 0\.3\.0 and cannot prove anchors/;

function stub(version, proven, finality, deadline) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qstamp-stub-'));
  fs.mkdirSync(path.join(dir, 'lib'));
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: '@quantovainc/qstamp', version, main: 'index.js' }));
  fs.writeFileSync(path.join(dir, 'index.js'), proven ? 'module.exports = { isProven: () => false };\n' : 'module.exports = {};\n');
  if (finality) fs.writeFileSync(path.join(dir, 'lib', 'finality.js'), '\n');
  if (deadline) fs.writeFileSync(path.join(dir, 'lib', 'deadline.js'), '\n');
  return dir;
}

function loadWith(dir) {
  const script = [
    "const Module = require('module');",
    "const path = require('path');",
    'const original = Module._resolveFilename;',
    `const dir = ${JSON.stringify(dir)};`,
    'Module._resolveFilename = function (request, ...rest) {',
    "  if (request === '@quantovainc/qstamp') return path.join(dir, 'index.js');",
    "  if (request.startsWith('@quantovainc/qstamp/')) return path.join(dir, request.slice(20));",
    '  return original.call(this, request, ...rest);',
    '};',
    `require(${JSON.stringify(ROOT)});`,
  ].join('\n');
  try {
    return spawnSync(process.execPath, ['-e', script], { encoding: 'utf8' });
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

test('the package refuses to load against a Qstamp that cannot prove anchors', () => {
  const refused = [
    stub('0.2.1', false, true, true),
    stub('0.3.0', false, true, true),
    stub('0.3.0', false, false, false),
    stub('0.2.1', true, false, false),
    stub('0.2.1', true, true, false),
    stub('0.2.1', true, false, true),
    stub('0.2.9', true, false, false),
    stub('not a version', true, false, false),
  ];
  for (const dir of refused) {
    const r = loadWith(dir);
    assert.notStrictEqual(r.status, 0, dir);
    assert.match(r.stderr, OLD);
  }
  for (const dir of [stub('0.3.0', true, false, false), stub('0.4.2', true, false, false), stub('1.0.0', true, false, false), stub('0.2.1', true, true, true)]) {
    const r = loadWith(dir);
    assert.strictEqual(r.status, 0, r.stderr);
  }
});
