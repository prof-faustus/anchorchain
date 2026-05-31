// Txid: double-SHA-256 of the raw transaction bytes, stored internal order, with
// a distinct brand from Hash.
import type { Result } from './result.js';
import { ok, err } from './result.js';
import type { BsvError } from './errors.js';
import { hashBadLength, hashBadHex } from './errors.js';
import type { Hash } from './hash.js';
import { reverseBytes, toHexLower, fromHex } from './bytes.js';
import { doubleSha256 } from './hashing.js';

declare const TxidBrand: unique symbol;
export type Txid = Uint8Array & { readonly [TxidBrand]: 'Txid' };
const TXID_LEN = 32;

export function ofTransactionBytes(raw: Uint8Array): Txid {
  return doubleSha256(raw) as unknown as Txid;
}
export function fromInternalBytes(bytes: Uint8Array): Result<Txid, BsvError> {
  if (bytes.length !== TXID_LEN) return err(hashBadLength(bytes.length));
  return ok(Uint8Array.from(bytes) as Txid);
}
export function fromDisplayHex(hex: string): Result<Txid, BsvError> {
  if (hex.length !== TXID_LEN * 2) return err(hashBadHex('length'));
  const parsed = fromHex(hex);
  if (!parsed.ok) return err(hashBadHex('charset'));
  return ok(reverseBytes(parsed.value) as Txid);
}
export function toInternalBytes(t: Txid): Uint8Array {
  return Uint8Array.from(t);
}
export function toDisplayHex(t: Txid): string {
  return toHexLower(reverseBytes(t));
}
export function equals(a: Txid, b: Txid): boolean {
  let diff = 0;
  for (let i = 0; i < TXID_LEN; i++) diff |= (a[i] as number) ^ (b[i] as number);
  return diff === 0;
}
export function asHash(t: Txid): Hash {
  return Uint8Array.from(t) as unknown as Hash;
}
