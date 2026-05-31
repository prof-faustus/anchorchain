// A SOUND, zero-knowledge range proof that a Pedersen commitment C = v*G + r*H
// hides a value v in [0, 2^bits), by bit decomposition:
//   - commit to each bit: C_i = b_i*G + r_i*H, with the per-bit blindings chosen so
//     that sum_i 2^i * C_i == C (this binds the bits to the committed value);
//   - prove each C_i opens to 0 OR to 1 with a one-out-of-many OR over base H
//     (so each b_i is genuinely a bit, not an arbitrary field element).
// Together these force v = sum_i b_i 2^i in [0, 2^bits). It is zero-knowledge: the
// bit commitments and OR proofs reveal nothing about the bits.
//
// COST / HONESTY: the proof is LINEAR in `bits` (two group elements + three scalars
// per bit). It is NOT a Bulletproof — there is no logarithmic aggregation and no
// inner-product argument. It is a Fiat-Shamir sigma-protocol proof under discrete
// log in the random-oracle model, with no trusted setup and no post-quantum claim.
import type { Scalar, Point } from '@anchorchain/bsv';
import { scalarMod, scalarSub, scalarMul, scalarAdd, pointMul, pointAdd } from '@anchorchain/bsv';
import type { Commitment } from './commit.js';
import { commit, subCommit, commitEq, G, H } from './commit.js';
import type { OrProof } from './sigma.js';
import { proveOneOfMany, verifyOneOfMany } from './sigma.js';
import { randScalar } from './transcript.js';

export interface RangeProof {
  bits: number;
  bitCommits: Point[];
  bitProofs: OrProof[];
}

export type RangeError = { kind: 'OutOfRange'; message: string } | { kind: 'BadBits'; message: string };

const bitLabel = (i: number): string => `anchorchain/privacy/range/bit/${i}`;

export function proveRange(value: Scalar, blinding: Scalar, bits: number): { ok: true; proof: RangeProof; commitment: Commitment } | { ok: false; error: RangeError } {
  if (bits <= 0 || bits > 256) return { ok: false, error: { kind: 'BadBits', message: `bits ${bits} out of (0, 256]` } };
  const v = scalarMod(value);
  if (v >= 1n << BigInt(bits)) return { ok: false, error: { kind: 'OutOfRange', message: `value does not fit in ${bits} bits` } };
  const commitment = commit(v, blinding);

  for (;;) {
    // per-bit blindings, with r_0 fixed so that sum_i 2^i r_i == blinding
    const r = new Array<Scalar>(bits);
    let weighted = 0n;
    for (let i = 1; i < bits; i++) {
      r[i] = randScalar();
      weighted = scalarAdd(weighted, scalarMul(r[i] as Scalar, scalarMod(1n << BigInt(i))));
    }
    r[0] = scalarSub(blinding, weighted);
    const b0 = (v >> 0n) & 1n;
    if (b0 === 0n && scalarMod(r[0] as Scalar) === 0n) continue; // avoid commit(0,0); negligible

    const bitCommits = new Array<Point>(bits);
    const bitProofs = new Array<OrProof>(bits);
    for (let i = 0; i < bits; i++) {
      const bi = (v >> BigInt(i)) & 1n;
      const ci = commit(bi, r[i] as Scalar);
      bitCommits[i] = ci;
      // statements over base H: P0 = C_i opens to 0; P1 = C_i - G opens to 1
      const p0 = ci;
      const p1 = subCommit(ci, G);
      bitProofs[i] = proveOneOfMany(bitLabel(i), H, [p0, p1], Number(bi), r[i] as Scalar);
    }
    return { ok: true, proof: { bits, bitCommits, bitProofs }, commitment };
  }
}

export function verifyRange(commitment: Commitment, proof: RangeProof): boolean {
  if (proof.bits <= 0 || proof.bits > 256) return false;
  if (proof.bitCommits.length !== proof.bits || proof.bitProofs.length !== proof.bits) return false;
  // 1) the bits must reconstruct the committed value: sum_i 2^i C_i == C
  let acc: Point | undefined;
  for (let i = 0; i < proof.bits; i++) {
    const weight = scalarMod(1n << BigInt(i));
    const term = weightedPoint(proof.bitCommits[i] as Point, weight);
    acc = acc === undefined ? term : addP(acc, term);
  }
  if (acc === undefined || !commitEq(acc as Commitment, commitment)) return false;
  // 2) each bit commitment must open to 0 or 1
  for (let i = 0; i < proof.bits; i++) {
    const ci = proof.bitCommits[i] as Point;
    const p1 = subCommit(ci, G);
    if (!verifyOneOfMany(bitLabel(i), H, [ci, p1], proof.bitProofs[i] as OrProof)) return false;
  }
  return true;
}

// Scalar-weighted point and point add, kept local so the verifier reads as the math.
function weightedPoint(p: Point, w: Scalar): Point {
  return pointMul(p, w);
}
function addP(a: Point, b: Point): Point {
  return pointAdd(a, b);
}
