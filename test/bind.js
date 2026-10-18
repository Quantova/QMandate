// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const F = require('../lib/format');
const native = require('../lib/native');
const crypto = require('crypto');

const PAYEE_KEY = 'c0ffee'.padEnd(64, '0');
const PAYEE = 'key ' + PAYEE_KEY;
const EARLY = '2026-10-01T00:00:00.000Z';

function bound(env) {
  return { detailsDigest: env.statement.detailsDigest, counterpartyKeyId: PAYEE_KEY };
}

function grantIssuedEarly(principal, agent, scopes, validFrom, validUntil) {
  const pk = native.publicKey(principal);
  const st = {
    mandateId: crypto.randomBytes(16).toString('hex'),
    principalKeyId: F.keyIdOf(pk),
    agentKeyId: F.keyIdOf(native.publicKey(agent)),
    agentLabel: '',
    scopes,
    counterparties: [],
    validFrom,
    validUntil,
    issuedAt: EARLY,
    note: '',
  };
  const sig = native.sign(principal, F.payload('mandate', st, F.VERSION), Uint8Array.from(crypto.randomBytes(32)));
  return { format: F.FORMAT, type: 'mandate', algorithm: F.ALGORITHM, signer: { id: st.principalKeyId, publicKey: Buffer.from(pk).toString('base64') }, statement: st, signature: Buffer.from(sig).toString('base64') };
}

module.exports = { PAYEE, PAYEE_KEY, bound, grantIssuedEarly };
