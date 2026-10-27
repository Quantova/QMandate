// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const qstamp = require('@quantovainc/qstamp');
const { honest, provenByPinnedOperators } = require('./honest');

test('the shared deadline stops anchor checks across the whole verify pass', async () => {
  const h = await honest();
  const restore = provenByPinnedOperators();
  const realVerify = qstamp.verify;
  let calls = 0;
  qstamp.verify = (...a) => {
    calls += 1;
    return realVerify(...a);
  };
  const perf = require('perf_hooks').performance;
  const realNow = perf.now.bind(perf);
  let first = true;
  perf.now = () => {
    if (first) {
      first = false;
      return 0;
    }
    return 1e12;
  };
  try {
    const res = await h.qm.verify(h.records.action, h.options.action);
    assert.equal(calls, 0);
    assert.notEqual(res.status, 'valid');
    assert.ok(res.checks.some((x) => !x.ok && /reached its time limit/.test(x.detail)));
  } finally {
    perf.now = realNow;
    qstamp.verify = realVerify;
    restore();
    h.cleanup();
  }
});

test('a generous deadline still checks every anchor', async () => {
  const h = await honest();
  const restore = provenByPinnedOperators();
  try {
    const res = await h.qm.verify(h.records.action, Object.assign({}, h.options.action, { deadlineMs: 600000 }));
    assert.equal(res.status, 'valid', JSON.stringify(res.checks.filter((x) => !x.ok)));
  } finally {
    restore();
    h.cleanup();
  }
});

test('deadlineMs is bounded', async () => {
  const h = await honest();
  try {
    await assert.rejects(h.qm.verify(h.records.action, Object.assign({}, h.options.action, { deadlineMs: 0 })), /deadlineMs/);
    await assert.rejects(h.qm.verify(h.records.action, Object.assign({}, h.options.action, { deadlineMs: 600001 })), /deadlineMs/);
  } finally {
    h.cleanup();
  }
});
