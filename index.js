// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const M = require('./lib/mandate');
const { verify } = require('./lib/verify');
const F = require('./lib/format');
const Ledger = require('./lib/ledger');

module.exports = {
  generateKey: M.generateKey,
  publicKey: M.publicKey,
  keyId: M.keyId,
  describeKey: M.describeKey,
  grant: M.grant,
  authorise: M.authorise,
  act: M.act,
  consume: M.consume,
  ledgerActions: M.ledgerActions,
  revoke: M.revoke,
  anchor: M.anchor,
  complete: M.complete,
  verify,
  fileLedger: Ledger.fileLedger,
  mandateRef: (mandate) => F.refOf(M.mandateOf(mandate)),
  anchorDigest: (envelope) => F.anchorDigest(F.parse(envelope)).toString('hex'),
  FORMAT: F.FORMAT,
  ACTION_FORMAT: F.ACTION_FORMAT,
  CHAIN_FORMAT: F.CHAIN_FORMAT,
  LEGACY_CUTOFF: F.LEGACY_CUTOFF,
  ALGORITHM: F.ALGORITHM,
  TYPES: F.TYPES,
};
