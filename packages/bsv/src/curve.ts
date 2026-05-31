// secp256k1 (the BSV curve) group operations, wrapping the SDK so no other
// package performs curve math directly. Used by the privacy (commitments, range
// proofs, zk membership) and custody (threshold/Shamir) packages.
import { Curve, Point as SdkPoint, BigNumber } from '@bsv/sdk';
import type { Result } from './result.js';
import { ok, err } from './result.js';
import type { BsvError } from './errors.js';
import { curveBadPoint } from './errors.js';
import { toHexLower, fromHex } from './bytes.js';

const curve = new Curve();

export type Scalar = bigint;
declare const PointBrand: unique symbol;
export type Point = { readonly [PointBrand]: 'Point' };

export const CURVE_N: bigint = BigInt(curve.n.toString());
export const CURVE_P: bigint = BigInt(curve.p.toString());

function wrap(p: SdkPoint): Point {
  return p as unknown as Point;
}
function unwrap(p: Point): SdkPoint {
  return p as unknown as SdkPoint;
}
function toBn(s: bigint): BigNumber {
  return new BigNumber(scalarMod(s).toString());
}

export const CURVE_G: Point = wrap(curve.g);

export function scalarMod(x: bigint): Scalar {
  const r = x % CURVE_N;
  return r < 0n ? r + CURVE_N : r;
}
export function scalarAdd(a: Scalar, b: Scalar): Scalar {
  return scalarMod(a + b);
}
export function scalarMul(a: Scalar, b: Scalar): Scalar {
  return scalarMod(a * b);
}
export function scalarSub(a: Scalar, b: Scalar): Scalar {
  return scalarMod(a - b);
}
export function scalarIsZero(a: Scalar): boolean {
  return scalarMod(a) === 0n;
}
// Modular inverse mod n via Fermat (n is prime).
export function scalarInv(a: Scalar): Scalar {
  let base = scalarMod(a);
  let exp = CURVE_N - 2n;
  let result = 1n;
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % CURVE_N;
    base = (base * base) % CURVE_N;
    exp >>= 1n;
  }
  return result;
}

export function reduceScalar(bytes: Uint8Array): Scalar {
  return scalarMod(BigInt('0x' + (bytes.length === 0 ? '0' : toHexLower(bytes))));
}

export function pointMul(p: Point, k: Scalar): Point {
  return wrap(unwrap(p).mul(toBn(k)));
}
export function pointMulG(k: Scalar): Point {
  return wrap(curve.g.mul(toBn(k)));
}
export function pointAdd(a: Point, b: Point): Point {
  return wrap(unwrap(a).add(unwrap(b)));
}
export function pointNeg(p: Point): Point {
  return wrap(unwrap(p).neg());
}
export function pointEq(a: Point, b: Point): boolean {
  return unwrap(a).eq(unwrap(b));
}
export function encodePoint(p: Point): Uint8Array {
  return Uint8Array.from(unwrap(p).encode(true) as number[]);
}
export function pointToHex(p: Point): string {
  return unwrap(p).encode(true, 'hex') as string;
}
export function decodePoint(bytes: Uint8Array): Result<Point, BsvError> {
  if (bytes.length !== 33) return err(curveBadPoint(`expected 33 compressed bytes, got ${bytes.length}`));
  try {
    return ok(wrap(SdkPoint.fromString(toHexLower(bytes))));
  } catch (e) {
    return err(curveBadPoint(e instanceof Error ? e.message : 'decode failed'));
  }
}
export function pointFromHex(hex: string): Result<Point, BsvError> {
  const bytes = fromHex(hex);
  if (!bytes.ok) return err(curveBadPoint('not hex'));
  return decodePoint(bytes.value);
}

// A second, independent generator H for Pedersen commitments. H's discrete log
// w.r.t. G MUST be unknown (otherwise the commitment is not binding), so H is
// derived by a nothing-up-my-sleeve hash-to-curve (try-and-increment): hash a
// fixed domain string to a candidate x-coordinate and take the first valid curve
// point. Nobody knows log_G(H). (Documented in docs/SECURITY.md.)
import { doubleSha256 } from './hashing.js';
const enc = new TextEncoder();

function hashToCurve(domain: string): Point {
  for (let counter = 0; counter < 100000; counter++) {
    const x = doubleSha256(enc.encode(domain + ':' + counter));
    for (const prefix of [0x02, 0x03]) {
      const compressed = new Uint8Array(33);
      compressed[0] = prefix;
      compressed.set(x, 1);
      const p = decodePoint(compressed);
      if (p.ok) return p.value;
    }
  }
  throw new Error('hashToCurve: no valid point found (unreachable)');
}

export const CURVE_H: Point = hashToCurve('AnchorChain/pedersen/H/v1');
