// Compact (logarithmic) age predicate — the idattr <-> AnchorChain Bulletproofs bridge.
//
// `idattr-zkp` (the identity-attribution workspace) proves "age >= min" with a
// SELF-CONTAINED, LINEAR-size proof: a bit-decomposition range proof with a per-bit
// Schnorr-OR, over Ristretto (curve25519). This module proves the SAME statement with a
// LOGARITHMIC Bulletproof over secp256k1, reusing the audited proveRangeBP/verifyRangeBP.
//
// HONEST LABELLING. This is a real bridge of a STATEMENT, not of a commitment: the two
// backends live over different groups (Ristretto vs secp256k1), so no commitment is shared
// byte-for-byte. To use this compact backend the issuer publishes the birth-year commitment
// in secp256k1; the Ristretto idattr-zkp credential carries the analogous commitment in its
// own group. There is no trusted setup. The age predicate and its soundness argument are
// identical to the Rust `prove_age_at_least` / `verify_age_at_least`:
//
//   * Issuer commitment:  C_birth = birth_year*G + r_birth*H   (Pedersen, secp256k1).
//   * The verifier RECOMPUTES the delta commitment from the issuer's commitment — it never
//     trusts a prover-supplied one:
//        C_delta = threshold_year*G - C_birth = commit(threshold_year - birth_year, -r_birth).
//     C_delta therefore opens to delta = threshold_year - birth_year, and ONLY to that.
//   * The holder proves delta in [0, 2^AGE_BITS). An under-age holder has delta < 0, whose
//     representative mod n is astronomically large and out of range, so no honest proof exists.
//
// threshold_year = current_year - min_age  (e.g. 2026 - 21 = 2005).

import type { Scalar } from '@anchorchain/bsv';
import { pointMulG, scalarSub, scalarMod } from '@anchorchain/bsv';
import type { Commitment } from './commit.js';
import { commit, subCommit } from './commit.js';
import type { RangeProofBP } from './bulletproofs.js';
import { proveRangeBP, verifyRangeBP } from './bulletproofs.js';

// Matches idattr-zkp RANGE_BITS (= 32): ample for any age/year delta. Power of two and
// <= 256, as the Bulletproof requires.
export const AGE_BITS = 32;

export type AgeBridgeError =
  | { kind: 'UnderAge'; message: string }
  | { kind: 'BadThreshold'; message: string };

// Issuer side: commit to the holder's birth year, C_birth = birth_year*G + r_birth*H. The
// issuer keeps (birth_year, r_birth) with the holder; only C_birth is published/signed.
export function issuerBirthCommitment(birthYear: bigint, rBirth: Scalar): Commitment {
  return commit(scalarMod(birthYear), rBirth);
}

// Verifier-recomputable delta commitment: threshold_year*G - C_birth, which equals
// commit(threshold_year - birth_year, -r_birth). Depends only on the public threshold and the
// issuer's commitment, so a prover cannot substitute a commitment of their own.
export function ageDeltaCommitment(thresholdYear: bigint, cBirth: Commitment): Commitment {
  return subCommit(pointMulG(scalarMod(thresholdYear)), cBirth);
}

// Holder side: prove "birth_year <= threshold_year" (i.e. at least min_age) without revealing
// birth_year. Needs the secret birth_year and the issuer's blinding r_birth (the opening of the
// published C_birth). Returns UnderAge with no proof if the holder is in fact under-age.
export function proveAgeAtLeastBP(
  birthYear: bigint,
  rBirth: Scalar,
  thresholdYear: bigint,
  bits: number = AGE_BITS,
): { ok: true; proof: RangeProofBP } | { ok: false; error: AgeBridgeError } {
  if (thresholdYear < 0n) {
    return { ok: false, error: { kind: 'BadThreshold', message: 'threshold year must be non-negative' } };
  }
  if (birthYear > thresholdYear) {
    return { ok: false, error: { kind: 'UnderAge', message: 'birth year exceeds threshold: no honest proof exists' } };
  }
  const delta = thresholdYear - birthYear; // in [0, threshold_year]
  const negR = scalarSub(0n, rBirth); // blinding of C_delta is -r_birth (mod n)
  // commit(delta, negR) computed inside proveRangeBP equals ageDeltaCommitment(threshold, C_birth)
  // by construction; the verifier re-derives that same commitment from C_birth, so we need not
  // carry it in the proof.
  const res = proveRangeBP(delta, negR, bits);
  if (!res.ok) {
    return { ok: false, error: { kind: 'BadThreshold', message: `range proof failed: ${res.error.message}` } };
  }
  return { ok: true, proof: res.proof };
}

// Verifier side: accept iff `proof` is a valid Bulletproof that the issuer-bound delta lies in
// range. The delta commitment is recomputed from C_birth and the public threshold here, so the
// prover never supplies it — this is what binds the proof to the issuer's attestation.
export function verifyAgeAtLeastBP(
  cBirth: Commitment,
  thresholdYear: bigint,
  proof: RangeProofBP,
  bits: number = AGE_BITS,
): boolean {
  if (proof.bits !== bits) return false;
  const cDelta = ageDeltaCommitment(thresholdYear, cBirth);
  return verifyRangeBP(cDelta, proof);
}
