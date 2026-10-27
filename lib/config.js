// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const DEFAULT_LEGACY_FORMAT_CUTOFF = '2026-10-19T05:09:09.000Z';

function legacyFormatCutoff(env) {
  const source = env || process.env;
  const given = source.QMANDATE_LEGACY_CUTOFF;
  return typeof given === 'string' && ISO_UTC.test(given) ? given : DEFAULT_LEGACY_FORMAT_CUTOFF;
}

module.exports = { DEFAULT_LEGACY_FORMAT_CUTOFF, legacyFormatCutoff, LEGACY_FORMAT_CUTOFF: legacyFormatCutoff() };
