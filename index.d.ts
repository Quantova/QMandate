// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

export type EnvelopeType = 'mandate' | 'action' | 'revoke';

export interface Scope {
  action: string;
  currency: string;
  maxPerAction: string;
  maxTotal: string;
}

export interface Envelope {
  format: 'qmandate/1';
  type: EnvelopeType;
  algorithm: 'ML-DSA-65';
  signer: { id: string; publicKey: string };
  statement: Record<string, unknown>;
  signature: string;
  anchor?: unknown;
}

export interface KeyDescription {
  format: 'qmandate-key/1';
  algorithm: 'ML-DSA-65';
  id: string;
  publicKey: string;
}

export interface GrantOptions {
  key: Uint8Array;
  agent: KeyDescription | Uint8Array | string;
  agentLabel?: string;
  scopes: Scope[];
  counterparties?: string[];
  validFrom?: string;
  validUntil: string;
  note?: string;
}

export interface ActionRequest {
  action: string;
  currency?: string;
  amount?: string;
  counterparty?: string;
}

export interface AuthoriseOptions {
  at?: string;
  spent?: string;
  agentKeyId?: string;
  principalKeyId?: string;
}

export interface AuthoriseResult {
  allowed: boolean;
  reasons: string[];
  scope: Scope | null;
  mandateId: string;
  mandateRef: string;
  at: string;
}

export interface ActOptions extends ActionRequest {
  key: Uint8Array;
  mandate: Envelope;
  details?: Uint8Array;
  detailsDigest?: string;
  spent?: string;
  actedAt?: string;
  note?: string;
}

export interface RevokeOptions {
  key: Uint8Array;
  mandate: Envelope;
  revokedAt?: string;
  note?: string;
}

export interface AnchorOptions {
  seed: Uint8Array;
  index: number;
  network?: 'testnet';
  rpc?: string;
  client?: unknown;
  meter?: number;
  maxFee?: string | number;
  timeoutMs?: number;
  onPending?: (pending: unknown) => void | Promise<void>;
}

export interface VerifyOptions {
  type: EnvelopeType;
  mandate?: Envelope;
  principalKeyId?: string;
  principalPublicKey?: Uint8Array | string;
  revocations?: Envelope[];
  priorActions?: Envelope[];
  details?: Uint8Array;
  detailsDigest?: string;
  requireAnchor?: boolean;
  at?: string;
  rpc?: string;
  client?: unknown;
  clients?: Array<string | unknown>;
  contract?: string;
  trustCustomContract?: boolean;
}

export interface VerifyCheck {
  name: string;
  ok: boolean;
  detail: string;
  transport: boolean;
  indeterminate: boolean;
}

export interface VerifyResult {
  valid: boolean;
  status: 'valid' | 'invalid' | 'indeterminate';
  type: EnvelopeType | null;
  checks: VerifyCheck[];
  [field: string]: unknown;
}

export function generateKey(): Uint8Array;
export function publicKey(key: Uint8Array): Uint8Array;
export function keyId(key: Uint8Array): string;
export function describeKey(key: Uint8Array): KeyDescription;
export function grant(options: GrantOptions): Envelope;
export function authorise(mandate: Envelope, request: ActionRequest, options?: AuthoriseOptions): AuthoriseResult;
export function act(options: ActOptions): Envelope;
export function revoke(options: RevokeOptions): Envelope;
export function anchor(envelopes: Envelope | Envelope[], options: AnchorOptions): Promise<Envelope[]>;
export function verify(envelope: unknown, options: VerifyOptions): Promise<VerifyResult>;
export function mandateRef(mandate: Envelope): string;
export function anchorDigest(envelope: Envelope): string;
export const FORMAT: 'qmandate/1';
export const ALGORITHM: 'ML-DSA-65';
export const TYPES: readonly EnvelopeType[];
