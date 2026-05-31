// The two sigma protocols every higher proof is built from, made non-interactive
// by Fiat-Shamir. Both are zero-knowledge and sound under the discrete-log
// assumption in the random-oracle model. THESE ARE SIGMA-PROTOCOL PROOFS — not
// zk-STARKs, not Bulletproofs. They carry no trusted setup and no post-quantum
// claim, and their size is linear in the statement (see range.ts for the cost).
import type { Scalar, Point } from '@anchorchain/bsv';
import { pointMul, pointAdd, pointNeg, pointEq, scalarAdd, scalarSub, scalarMul, scalarMod } from '@anchorchain/bsv';
import { challenge, randScalar } from './transcript.js';

// --- Schnorr proof of knowledge of x such that P = x * base -------------------
export interface SchnorrProof {
  a: Point; // commitment k*base
  s: Scalar; // k + e*x
}

export function proveDlog(label: string, base: Point, p: Point, x: Scalar): SchnorrProof {
  const k = randScalar();
  const a = pointMul(base, k);
  const e = challenge(label, [base, p, a]);
  return { a, s: scalarAdd(k, scalarMul(e, x)) };
}

export function verifyDlog(label: string, base: Point, p: Point, proof: SchnorrProof): boolean {
  const e = challenge(label, [base, p, proof.a]);
  // s*base == a + e*p
  return pointEq(pointMul(base, proof.s), pointAdd(proof.a, pointMul(p, e)));
}

// --- One-out-of-many OR (CDS '94): knowledge of x with P_t = x*base for SOME t,
// without revealing t. Simulated branches for j != t, a real branch for t, with
// the challenge split so the sub-challenges sum to the Fiat-Shamir challenge. -----
export interface OrProof {
  a: Point[];
  e: Scalar[];
  s: Scalar[];
}

export function proveOneOfMany(label: string, base: Point, statements: Point[], trueIndex: number, witness: Scalar): OrProof {
  const m = statements.length;
  const a = new Array<Point>(m);
  const e = new Array<Scalar>(m);
  const s = new Array<Scalar>(m);
  let sumFake = 0n;
  // simulate every false branch: pick e_j, s_j, derive A_j = s_j*base - e_j*P_j
  for (let j = 0; j < m; j++) {
    if (j === trueIndex) continue;
    e[j] = randScalar();
    s[j] = randScalar();
    a[j] = pointAdd(pointMul(base, s[j] as Scalar), pointNeg(pointMul(statements[j] as Point, e[j] as Scalar)));
    sumFake = scalarAdd(sumFake, e[j] as Scalar);
  }
  // real branch commitment
  const k = randScalar();
  a[trueIndex] = pointMul(base, k);
  // bind the whole transcript, then split the challenge
  const total = challenge(label, [base, ...statements, ...a]);
  e[trueIndex] = scalarSub(total, sumFake);
  s[trueIndex] = scalarAdd(k, scalarMul(e[trueIndex] as Scalar, witness));
  return { a, e, s };
}

export function verifyOneOfMany(label: string, base: Point, statements: Point[], proof: OrProof): boolean {
  const m = statements.length;
  if (proof.a.length !== m || proof.e.length !== m || proof.s.length !== m) return false;
  // the sub-challenges must sum to the Fiat-Shamir challenge over the transcript
  const total = challenge(label, [base, ...statements, ...proof.a]);
  let sum = 0n;
  for (const ej of proof.e) sum = scalarAdd(sum, ej);
  if (scalarMod(sum) !== scalarMod(total)) return false;
  // and every branch equation must hold: s_j*base == A_j + e_j*P_j
  for (let j = 0; j < m; j++) {
    const lhs = pointMul(base, proof.s[j] as Scalar);
    const rhs = pointAdd(proof.a[j] as Point, pointMul(statements[j] as Point, proof.e[j] as Scalar));
    if (!pointEq(lhs, rhs)) return false;
  }
  return true;
}
