// Pedersen commitments on secp256k1: C(v, r) = v*G + r*H, where H is the
// nothing-up-my-sleeve generator with unknown discrete log w.r.t. G (provided by
// @anchorchain/bsv). The commitment is perfectly hiding (r is uniform) and
// computationally binding (opening to two values would reveal log_G(H)). It is
// additively homomorphic: C(v1,r1) + C(v2,r2) = C(v1+v2, r1+r2). This is what lets
// a confidential amount be conserved across a transaction without revealing it.
import type { Scalar, Point } from '@anchorchain/bsv';
import { CURVE_G, CURVE_H, pointMul, pointMulG, pointAdd, pointNeg, pointEq, scalarMod, scalarIsZero, pointToHex } from '@anchorchain/bsv';

export type Commitment = Point;

// v*G + r*H, with the v=0 / r=0 cases handled so we never form the identity via a
// zero multiply (the SDK point ops are happiest on non-identity inputs).
export function commit(value: Scalar, blinding: Scalar): Commitment {
  const v = scalarMod(value);
  const r = scalarMod(blinding);
  const rH = scalarIsZero(r) ? undefined : pointMul(CURVE_H, r);
  if (scalarIsZero(v)) {
    if (rH === undefined) throw new Error('commit(0, 0) is the identity and is not a usable commitment');
    return rH;
  }
  const vG = pointMulG(v);
  return rH === undefined ? vG : pointAdd(vG, rH);
}

export function addCommit(a: Commitment, b: Commitment): Commitment {
  return pointAdd(a, b);
}
export function subCommit(a: Commitment, b: Commitment): Commitment {
  return pointAdd(a, pointNeg(b));
}
export function commitEq(a: Commitment, b: Commitment): boolean {
  return pointEq(a, b);
}
export function commitToHex(c: Commitment): string {
  return pointToHex(c);
}

// The base points, re-exported for the proof modules and callers that build
// statements over G and H.
export const G: Point = CURVE_G;
export const H: Point = CURVE_H;
