// Shamir secret sharing over the scalar field GF(n) of secp256k1 (n is prime). A
// secret scalar is the constant term of a random degree-(t-1) polynomial; each
// share is an evaluation (x_i, y_i). Any t shares reconstruct the secret by
// Lagrange interpolation at 0; fewer than t reveal nothing about it.
import type { Scalar } from '@anchorchain/bsv';
import { scalarMod, scalarAdd, scalarMul, scalarSub, scalarInv, reduceScalar } from '@anchorchain/bsv';

export interface Share {
  x: Scalar;
  y: Scalar;
}

function randScalar(): Scalar {
  for (;;) {
    const b = new Uint8Array(32);
    globalThis.crypto.getRandomValues(b);
    const s = reduceScalar(b);
    if (s !== 0n) return s;
  }
}

function evalPoly(coeffs: Scalar[], x: Scalar): Scalar {
  let acc = 0n;
  for (let i = coeffs.length - 1; i >= 0; i--) acc = scalarAdd(scalarMul(acc, x), coeffs[i] as Scalar);
  return acc;
}

export type ShamirError = { kind: 'BadParams'; message: string };

// Split `secret` into `numShares` shares with reconstruction threshold `threshold`.
export function splitSecret(secret: Scalar, threshold: number, numShares: number): { ok: true; shares: Share[] } | { ok: false; error: ShamirError } {
  if (threshold < 1 || threshold > numShares) return { ok: false, error: { kind: 'BadParams', message: `threshold ${threshold} must be in [1, ${numShares}]` } };
  const coeffs: Scalar[] = [scalarMod(secret)];
  for (let i = 1; i < threshold; i++) coeffs.push(randScalar());
  const shares: Share[] = [];
  for (let i = 1; i <= numShares; i++) {
    const x = BigInt(i);
    shares.push({ x, y: evalPoly(coeffs, x) });
  }
  return { ok: true, shares };
}

// Reconstruct the secret (the polynomial's value at 0) from a set of shares by
// Lagrange interpolation. Supplying fewer than the threshold yields a value that
// does not match the true secret (the caller binds reconstruction to a public key).
export function reconstruct(shares: Share[]): Scalar {
  let secret = 0n;
  for (let j = 0; j < shares.length; j++) {
    const sj = shares[j] as Share;
    let num = 1n;
    let den = 1n;
    for (let m = 0; m < shares.length; m++) {
      if (m === j) continue;
      const sm = shares[m] as Share;
      num = scalarMul(num, sm.x);
      den = scalarMul(den, scalarSub(sm.x, sj.x));
    }
    secret = scalarAdd(secret, scalarMul(sj.y, scalarMul(num, scalarInv(den))));
  }
  return secret;
}
