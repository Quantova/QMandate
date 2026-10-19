// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const wasm = require('../wasm/qmandate_native.js');

function bytes(value, label) {
  if (!((ArrayBuffer.isView(value) && value instanceof Uint8Array)) || !(value.buffer instanceof ArrayBuffer)) throw new Error(label + ' must be a Uint8Array');
  return Uint8Array.from(value);
}

module.exports = {
  publicKey: (seed) => Uint8Array.from(wasm.publicKey(bytes(seed, 'the signing key'))),
  sign: (seed, message, randomness) => Uint8Array.from(wasm.sign(bytes(seed, 'the signing key'), bytes(message, 'the message'), bytes(randomness, 'the randomness'))),
  verify: (publicKey, message, signature) => wasm.verify(bytes(publicKey, 'the public key'), bytes(message, 'the message'), bytes(signature, 'the signature')),
  PUBLIC_KEY_BYTES: wasm.publicKeyBytes(),
  SIGNATURE_BYTES: wasm.signatureBytes(),
};
