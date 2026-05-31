// Hash: an immutable 32-byte value stored in internal (little-endian) order;
// display hex is big-endian (the conventional block/tx id presentation). The
// internal-vs-display byte order is converted once, here.
import type { Result } from './result.js';
import { ok, err } from './result.js';
import type { BsvError } from './errors.js';
import { hashBadLength, hashBadHex } from './errors.js';
import { reverseBytes, toHexLower, fromHex } from './bytes.js';

declare const HashBrand: unique symbol;
export type Hash = Uint8Array & { readonly [HashBrand]: 'Hash' };
export const HASH_LEN = 32;

export function fromInternalBytes(bytes: Uint8Array): Result<Hash, BsvError> {
  if (bytes.length !== HASH_LEN) return err(hashBadLength(bytes.length));
  return ok(Uint8Array.from(bytes) as Hash);
}
export function fromDisplayHex(hex: string): Result<Hash, BsvError> {
  if (hex.length !== HASH_LEN * 2) return err(hashBadHex('length'));
  const parsed = fromHex(hex);
  if (!parsed.ok) return err(hashBadHex('charset'));
  return ok(reverseBytes(parsed.value) as Hash);
}
export function toInternalBytes(h: Hash): Uint8Array {
  return Uint8Array.from(h);
}
export function toDisplayHex(h: Hash): string {
  return toHexLower(reverseBytes(h));
}
export function equals(a: Hash, b: Hash): boolean {
  let diff = 0;
  for (let i = 0; i < HASH_LEN; i++) diff |= (a[i] as number) ^ (b[i] as number);
  return diff === 0;
}
export function zero(): Hash {
  return new Uint8Array(HASH_LEN) as Hash;
}
