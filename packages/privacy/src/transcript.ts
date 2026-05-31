// Fiat-Shamir transcript and scalar helpers shared by the sigma protocols. The
// challenge is the double-SHA-256 of a domain label followed by the canonical
// encodings of every public point and scalar in the statement and the prover's
// commitments — binding the challenge to the whole transcript, which is what makes
// the non-interactive proofs sound in the random-oracle model.
import type { Scalar, Point } from '@anchorchain/bsv';
import { CURVE_N, scalarMod, reduceScalar, doubleSha256, encodePoint, concat } from '@anchorchain/bsv';

const enc = new TextEncoder();

// 32-byte big-endian encoding of a scalar (reduced mod n).
export function scalarBytes32(s: Scalar): Uint8Array {
  let hex = scalarMod(s).toString(16);
  if (hex.length > 64) hex = hex.slice(-64);
  hex = hex.padStart(64, '0');
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

// A cryptographically random non-zero scalar in [1, n).
export function randScalar(): Scalar {
  for (;;) {
    const bytes = new Uint8Array(32);
    globalThis.crypto.getRandomValues(bytes);
    const s = reduceScalar(bytes);
    if (s !== 0n) return s;
  }
}

// Fiat-Shamir challenge over a label, a list of points, and a list of scalars.
export function challenge(label: string, points: Point[], scalars: Scalar[] = []): Scalar {
  const parts: Uint8Array[] = [enc.encode(label)];
  for (const p of points) parts.push(encodePoint(p));
  for (const s of scalars) parts.push(scalarBytes32(s));
  const c = reduceScalar(doubleSha256(concat(...parts)));
  return c === 0n ? 1n : c; // avoid a zero challenge (negligible) which would be degenerate
}

export { CURVE_N };
