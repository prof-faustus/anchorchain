// Total byte helpers. Fallible reads return a Result and never throw on in-range
// input; writers assert room (programmer misuse only).
import type { Result } from './result.js';
import { ok, err } from './result.js';
import type { BsvError } from './errors.js';
import { bytesOutOfRange, hashBadHex, throwBsv } from './errors.js';

export function readU32LE(buf: Uint8Array, offset: number): Result<number, BsvError> {
  if (offset < 0 || offset + 4 > buf.length) return err(bytesOutOfRange(offset, 4, buf.length));
  return ok(((buf[offset] as number) | ((buf[offset + 1] as number) << 8) | ((buf[offset + 2] as number) << 16) | ((buf[offset + 3] as number) << 24)) >>> 0);
}
export function writeU32LE(value: number, into: Uint8Array, offset: number): void {
  if (offset < 0 || offset + 4 > into.length) throwBsv(bytesOutOfRange(offset, 4, into.length));
  into[offset] = value & 0xff;
  into[offset + 1] = (value >>> 8) & 0xff;
  into[offset + 2] = (value >>> 16) & 0xff;
  into[offset + 3] = (value >>> 24) & 0xff;
}

export interface VarInt {
  value: bigint;
  nextOffset: number;
}
export function readVarInt(buf: Uint8Array, offset: number): Result<VarInt, BsvError> {
  if (offset < 0 || offset >= buf.length) return err(bytesOutOfRange(offset, 1, buf.length));
  const first = buf[offset] as number;
  if (first < 0xfd) return ok({ value: BigInt(first), nextOffset: offset + 1 });
  if (first === 0xfd) {
    if (offset + 3 > buf.length) return err(bytesOutOfRange(offset, 3, buf.length));
    return ok({ value: BigInt((buf[offset + 1] as number) | ((buf[offset + 2] as number) << 8)), nextOffset: offset + 3 });
  }
  if (first === 0xfe) {
    if (offset + 5 > buf.length) return err(bytesOutOfRange(offset, 5, buf.length));
    const r = readU32LE(buf, offset + 1);
    if (!r.ok) return r;
    return ok({ value: BigInt(r.value), nextOffset: offset + 5 });
  }
  if (offset + 9 > buf.length) return err(bytesOutOfRange(offset, 9, buf.length));
  const lo = readU32LE(buf, offset + 1);
  const hi = readU32LE(buf, offset + 5);
  if (!lo.ok) return lo;
  if (!hi.ok) return hi;
  return ok({ value: (BigInt(hi.value) << 32n) | BigInt(lo.value), nextOffset: offset + 9 });
}
export function writeVarInt(value: bigint): Uint8Array {
  if (value < 0n) throwBsv(bytesOutOfRange(0, -1, 0));
  if (value < 0xfdn) return Uint8Array.of(Number(value));
  if (value <= 0xffffn) return Uint8Array.of(0xfd, Number(value & 0xffn), Number((value >> 8n) & 0xffn));
  if (value <= 0xffffffffn) {
    const out = new Uint8Array(5);
    out[0] = 0xfe;
    writeU32LE(Number(value), out, 1);
    return out;
  }
  const out = new Uint8Array(9);
  out[0] = 0xff;
  writeU32LE(Number(value & 0xffffffffn), out, 1);
  writeU32LE(Number((value >> 32n) & 0xffffffffn), out, 5);
  return out;
}

export function reverseBytes(buf: Uint8Array): Uint8Array {
  const out = new Uint8Array(buf.length);
  for (let i = 0; i < buf.length; i++) out[i] = buf[buf.length - 1 - i] as number;
  return out;
}
export function concat(...parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

const HEX = '0123456789abcdef';
export function toHexLower(buf: Uint8Array): string {
  let s = '';
  for (let i = 0; i < buf.length; i++) {
    const b = buf[i] as number;
    s += HEX[(b >> 4) & 0x0f];
    s += HEX[b & 0x0f];
  }
  return s;
}
export function fromHex(str: string): Result<Uint8Array, BsvError> {
  if (str.length % 2 !== 0) return err(hashBadHex('length'));
  const out = new Uint8Array(str.length / 2);
  for (let i = 0; i < out.length; i++) {
    const hi = nibble(str.charCodeAt(i * 2));
    const lo = nibble(str.charCodeAt(i * 2 + 1));
    if (hi < 0 || lo < 0) return err(hashBadHex('charset'));
    out[i] = (hi << 4) | lo;
  }
  return ok(out);
}
function nibble(c: number): number {
  if (c >= 0x30 && c <= 0x39) return c - 0x30;
  if (c >= 0x61 && c <= 0x66) return c - 0x61 + 10;
  if (c >= 0x41 && c <= 0x46) return c - 0x41 + 10;
  return -1;
}
