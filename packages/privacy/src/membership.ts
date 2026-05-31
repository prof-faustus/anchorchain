// A zero-knowledge membership proof: a Pedersen commitment C = v*G + r*H hides a
// value v that is one of a PUBLIC set {s_0, ..., s_{m-1}}, without revealing which.
// For each candidate s_k, form P_k = C - s_k*G; if v = s_k then P_k = r*H, so the
// prover knows its discrete log w.r.t. H. A one-out-of-many OR over base H proves
// "I know log_H(P_k) for SOME k" — i.e. v is in the set — hiding the index. Sound
// and zero-knowledge under discrete log in the random-oracle model. Linear in |set|.
import type { Scalar, Point } from '@anchorchain/bsv';
import { pointMulG, scalarMod, scalarIsZero } from '@anchorchain/bsv';
import type { Commitment } from './commit.js';
import { subCommit, H } from './commit.js';
import type { OrProof } from './sigma.js';
import { proveOneOfMany, verifyOneOfMany } from './sigma.js';

export interface MembershipProof {
  setSize: number;
  or: OrProof;
}

export type MembershipError = { kind: 'NotInSet'; message: string } | { kind: 'EmptySet'; message: string };

const LABEL = 'anchorchain/privacy/membership/v1';

// P_k = C - s_k*G (with s_k = 0 handled without a zero multiply).
function candidate(commitment: Commitment, sk: Scalar): Point {
  return scalarIsZero(sk) ? commitment : subCommit(commitment, pointMulG(scalarMod(sk)));
}

export function proveMembership(commitment: Commitment, blinding: Scalar, set: Scalar[], value: Scalar): { ok: true; proof: MembershipProof } | { ok: false; error: MembershipError } {
  if (set.length === 0) return { ok: false, error: { kind: 'EmptySet', message: 'empty set' } };
  const v = scalarMod(value);
  const trueIndex = set.findIndex((s) => scalarMod(s) === v);
  if (trueIndex < 0) return { ok: false, error: { kind: 'NotInSet', message: 'value is not in the set' } };
  const statements = set.map((s) => candidate(commitment, s));
  return { ok: true, proof: { setSize: set.length, or: proveOneOfMany(LABEL, H, statements, trueIndex, blinding) } };
}

export function verifyMembership(commitment: Commitment, set: Scalar[], proof: MembershipProof): boolean {
  if (set.length === 0 || proof.setSize !== set.length) return false;
  const statements = set.map((s) => candidate(commitment, s));
  return verifyOneOfMany(LABEL, H, statements, proof.or);
}
