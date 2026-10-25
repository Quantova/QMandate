// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const qm = require('..');
const { honest, provenByPinnedOperators, iso } = require('./honest');

test('a revocation without a proven time keeps an action from verifying valid even when a later revocation is anchored', async (t) => {
  t.after(provenByPinnedOperators());
  const h = await honest();
  try {
    const only = await qm.verify(h.records.action, Object.assign({}, h.options.action, { revocations: [h.records.revoke] }));
    assert.strictEqual(only.status, 'valid', JSON.stringify(only.checks.filter((c) => !c.ok)));
    const early = qm.revoke({ key: h.principal, mandate: h.records.mandate, note: 'stolen key', revokedAt: iso(Date.parse(h.records.mandate.statement.validFrom) + 1000) });
    for (const revocations of [[h.records.revoke, early], [early, h.records.revoke]]) {
      const r = await qm.verify(h.records.action, Object.assign({}, h.options.action, { revocations }));
      assert.notStrictEqual(r.status, 'valid', 'an action verified valid next to a revocation whose time is not proven');
      assert.ok(r.checks.some((c) => c.name === 'revocation' && !c.ok), JSON.stringify(r.checks.filter((c) => !c.ok)));
    }
  } finally {
    h.cleanup();
  }
});
