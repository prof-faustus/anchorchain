// ECDSA over secp256k1, built on the curve wrappers so signing/verification do not
// reach into the SDK directly. Low-s normalised (BSV policy). Used by the custody
// (Shamir-reconstruction signing) and identity (challenge-response) layers.
import type { Scalar, Point } from './curve.js';
import { CURVE_N, scalarMod, scalarAdd, scalarMul, scalarSub, scalarInv, reduceScalar, pointMul, pointMulG, pointAdd, encodePoint } from './curve.js';

export interface EcdsaSig {
  r: Scalar;
  s: Scalar;
}

const HALF_N = CURVE_N >> 1n;

function secureRandScalar(): Scalar {
  for (;;) {
    const bytes = new Uint8Array(32);
    globalThis.crypto.getRandomValues(bytes);
    const s = reduceScalar(bytes);
    if (s !== 0n) return s;
  }
}

// The affine x-coordinate of a point, read from its compressed encoding.
function pointX(p: Point): bigint {
  const enc = encodePoint(p); // 33 bytes: prefix || x (big-endian)
  let x = 0n;
  for (let i = 1; i < 33; i++) x = (x << 8n) | BigInt(enc[i] as number);
  return x;
}

export function pubKeyOf(privateKey: Scalar): Point {
  return pointMulG(scalarMod(privateKey));
}

export function ecdsaSign(privateKey: Scalar, msgHash: Uint8Array): EcdsaSig {
  const d = scalarMod(privateKey);
  const z = reduceScalar(msgHash);
  for (;;) {
    const k = secureRandScalar();
    const r = scalarMod(pointX(pointMulG(k)));
    if (r === 0n) continue;
    let s = scalarMul(scalarInv(k), scalarAdd(z, scalarMul(r, d)));
    if (s === 0n) continue;
    if (s > HALF_N) s = scalarSub(0n, s); // low-s: N - s
    return { r, s };
  }
}

export function ecdsaVerify(publicKey: Point, msgHash: Uint8Array, sig: EcdsaSig): boolean {
  const { r, s } = sig;
  if (r <= 0n || r >= CURVE_N || s <= 0n || s >= CURVE_N) return false;
  const z = reduceScalar(msgHash);
  const w = scalarInv(s);
  const u1 = scalarMul(z, w);
  const u2 = scalarMul(r, w);
  try {
    const R = pointAdd(pointMulG(u1), pointMul(publicKey, u2));
    return scalarMod(pointX(R)) === scalarMod(r);
  } catch {
    return false; // point at infinity / invalid combination
  }
}
