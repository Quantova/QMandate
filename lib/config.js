// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const DEFAULT_LEGACY_FORMAT_CUTOFF = '2026-10-19T05:09:09.000Z';

function legacyFormatCutoff() {
  return DEFAULT_LEGACY_FORMAT_CUTOFF;
}

module.exports = { DEFAULT_LEGACY_FORMAT_CUTOFF, legacyFormatCutoff, LEGACY_FORMAT_CUTOFF: DEFAULT_LEGACY_FORMAT_CUTOFF };
