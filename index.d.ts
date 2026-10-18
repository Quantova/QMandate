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
  format: 'qmandate/1' | 'qmandate/2';
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

export interface EndpointOptions {
  network?: 'testnet';
  rpc?: string | string[];
  client?: unknown;
  clients?: Array<string | unknown>;
  trustSingleEndpoint?: boolean;
  trustCustomEndpoints?: boolean;
  allowLoopback?: boolean;
  endpointAllowList?: string[];
  clockSlackMs?: number;
  strict?: boolean;
}

export interface JournalEntry {
  name: string;
  text: string;
}

export interface LedgerStore {
  read(name: string): Promise<string | null>;
  compareAndSwap(name: string, expected: string | null, next: string, entry?: JournalEntry): Promise<boolean>;
  journal?(name: string, envelopeText: string): Promise<void>;
  readJournal?(name: string): Promise<string | null>;
  recover?(name: string): Promise<string | null>;
}

export interface LedgerActions {
  mandateRef: string;
  action: string;
  sequence: string;
  total: string;
  actions: Envelope[];
  complete: boolean;
}

export interface AuthoriseOptions extends EndpointOptions {
  at?: string;
  revocations?: Envelope[];
  ledger?: string | LedgerStore;
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
  atSupplied: boolean;
  chainTime: string;
  spent: string;
}

export interface ActOptions extends ActionRequest, EndpointOptions {
  key: Uint8Array;
  revocations?: Envelope[];
  mandate: Envelope;
  ledger: string | LedgerStore;
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

export interface AnchorOptions extends EndpointOptions {
  seed: Uint8Array;
  index: number;
  mandate?: Envelope;
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
  acceptLegacyActions?: boolean;
  details?: Uint8Array;
  detailsDigest?: string;
  counterpartyKeyId?: string;
  counterpartyPublicKey?: Uint8Array | string;
  strict?: boolean;
  requireAnchor?: boolean;
  maxAnchorDelay?: number;
  at?: string;
  rpc?: string | string[];
  client?: unknown;
  clients?: Array<string | unknown>;
  trustSingleEndpoint?: boolean;
  trustCustomEndpoints?: boolean;
  allowLoopback?: boolean;
  endpointAllowList?: string[];
  expectedSender?: string | string[];
  contract?: string;
  trustCustomContract?: boolean;
}

export interface VerifyCheck {
  name: string;
  ok: boolean;
  detail: string;
  transport: boolean;
  indeterminate: boolean;
  unproven: boolean;
}

export interface VerifyResult {
  valid: boolean;
  status: 'valid' | 'invalid' | 'indeterminate' | 'unproven';
  type: EnvelopeType | null;
  checks: VerifyCheck[];
  notes?: string[];
  [field: string]: unknown;
  endpoints: string[];
  officialEndpoints: boolean | null;
}

export function generateKey(): Uint8Array;
export function publicKey(key: Uint8Array): Uint8Array;
export function keyId(key: Uint8Array): string;
export function describeKey(key: Uint8Array): KeyDescription;
export function grant(options: GrantOptions): Envelope;
export function authorise(mandate: Envelope, request: ActionRequest, options?: AuthoriseOptions): Promise<AuthoriseResult>;
export function act(options: ActOptions): Promise<Envelope>;
export function ledgerActions(ledger: string | LedgerStore, mandate: Envelope, action: string): Promise<LedgerActions>;
export function revoke(options: RevokeOptions): Envelope;
export function anchor(envelopes: Envelope | Envelope[], options: AnchorOptions): Promise<Envelope[]>;
export function complete(envelopes: Envelope | Envelope[], pending: unknown, options?: EndpointOptions & { mandate?: Envelope; timeoutMs?: number }): Promise<Envelope[]>;
export function verify(envelope: unknown, options: VerifyOptions): Promise<VerifyResult>;
export function fileLedger(folder: string): LedgerStore;
export function mandateRef(mandate: Envelope): string;
export function anchorDigest(envelope: Envelope): string;
export const FORMAT: 'qmandate/1';
export const ACTION_FORMAT: 'qmandate/2';
export const ALGORITHM: 'ML-DSA-65';
export const TYPES: readonly EnvelopeType[];
