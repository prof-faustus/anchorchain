// Script: raw locking/unlocking script bytes (post-Genesis opcode set). Thin and
// validated; opcode interpretation beyond minimal pushdata is left to the SDK.
import type { Result } from './result.js';
import { ok, err } from './result.js';
import type { BsvError } from './errors.js';
import { fromHex as bytesFromHex } from './bytes.js';
import { toHexLower, concat } from './bytes.js';

declare const ScriptBrand: unique symbol;
export type Script = Uint8Array & { readonly [ScriptBrand]: 'Script' };

export const OP_FALSE = 0x00;
export const OP_TRUE = 0x51;
export const OP_RETURN = 0x6a;
export const OP_PUSHDATA1 = 0x4c;
export const OP_PUSHDATA2 = 0x4d;
export const OP_PUSHDATA4 = 0x4e;

export function fromBytes(bytes: Uint8Array): Script {
  return Uint8Array.from(bytes) as Script;
}
export function fromHex(hex: string): Result<Script, BsvError> {
  const parsed = bytesFromHex(hex);
  if (!parsed.ok) return err(parsed.error);
  return ok(parsed.value as Script);
}
export function toBytes(s: Script): Uint8Array {
  return Uint8Array.from(s);
}
export function toHex(s: Script): string {
  return toHexLower(s);
}
export function length(s: Script): number {
  return s.length;
}

// Minimal-length pushdata encoding for arbitrary-size data (post-Genesis: no
// 520-byte limit). Selects the smallest push opcode for the length.
export function pushData(payload: Uint8Array): Uint8Array {
  const n = payload.length;
  if (n <= 75) return concat(Uint8Array.of(n), payload);
  if (n <= 0xff) return concat(Uint8Array.of(OP_PUSHDATA1, n), payload);
  if (n <= 0xffff) return concat(Uint8Array.of(OP_PUSHDATA2, n & 0xff, (n >> 8) & 0xff), payload);
  return concat(Uint8Array.of(OP_PUSHDATA4, n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >>> 24) & 0xff), payload);
}

// Read one minimal pushdata chunk at offset; returns the payload and next offset.
export function readPush(bytes: Uint8Array, offset: number): { payload: Uint8Array; nextOffset: number } | undefined {
  if (offset >= bytes.length) return undefined;
  const op = bytes[offset] as number;
  let len: number;
  let start: number;
  if (op >= 0 && op <= 75) {
    len = op;
    start = offset + 1;
  } else if (op === OP_PUSHDATA1) {
    if (offset + 2 > bytes.length) return undefined;
    len = bytes[offset + 1] as number;
    start = offset + 2;
  } else if (op === OP_PUSHDATA2) {
    if (offset + 3 > bytes.length) return undefined;
    len = (bytes[offset + 1] as number) | ((bytes[offset + 2] as number) << 8);
    start = offset + 3;
  } else if (op === OP_PUSHDATA4) {
    if (offset + 5 > bytes.length) return undefined;
    len = ((bytes[offset + 1] as number) | ((bytes[offset + 2] as number) << 8) | ((bytes[offset + 3] as number) << 16) | ((bytes[offset + 4] as number) << 24)) >>> 0;
    start = offset + 5;
  } else {
    return undefined;
  }
  if (start + len > bytes.length) return undefined;
  return { payload: Uint8Array.from(bytes.subarray(start, start + len)), nextOffset: start + len };
}
