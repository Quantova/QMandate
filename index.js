// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const M = require('./lib/mandate');
const { verify } = require('./lib/verify');
const F = require('./lib/format');

module.exports = {
  generateKey: M.generateKey,
  publicKey: M.publicKey,
  keyId: M.keyId,
  describeKey: M.describeKey,
  grant: M.grant,
  authorise: M.authorise,
  act: M.act,
  revoke: M.revoke,
  anchor: M.anchor,
  verify,
  mandateRef: (mandate) => F.refOf(M.mandateOf(mandate)),
  anchorDigest: (envelope) => F.anchorDigest(F.parse(envelope)).toString('hex'),
  FORMAT: F.FORMAT,
  ALGORITHM: F.ALGORITHM,
  TYPES: F.TYPES,
};
