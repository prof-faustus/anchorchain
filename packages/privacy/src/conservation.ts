// Homomorphic value conservation in zero-knowledge. Given confidential input and
// output commitments, the net commitment D = sum(inputs) - sum(outputs) is public.
// If value is conserved (sum of input values == sum of output values) then the G
// component of D cancels and D = (excess blinding)*H. The prover proves knowledge
// of log_H(D) with a Schnorr proof; this is possible IFF D has no G component, i.e.
// IFF value is conserved (binding of the commitment forbids faking a G component).
// The verifier learns only that the books balance — never any amount, nor even the
// excess blinding. This is the confidential-amount conservation check for the
// credit and settlement layers.
import type { Scalar, Point } from '@anchorchain/bsv';
import { pointAdd, pointNeg } from '@anchorchain/bsv';
import type { Commitment } from './commit.js';
import { H } from './commit.js';
import type { SchnorrProof } from './sigma.js';
import { proveDlog, verifyDlog } from './sigma.js';

const LABEL = 'anchorchain/privacy/conservation/v1';

function sumPoints(points: Point[]): Point | undefined {
  let acc: Point | undefined;
  for (const p of points) acc = acc === undefined ? p : pointAdd(acc, p);
  return acc;
}

// The public net commitment D = sum(inputs) - sum(outputs).
export function netCommitment(inputs: Commitment[], outputs: Commitment[]): Point | undefined {
  const inSum = sumPoints(inputs);
  if (inSum === undefined) return undefined;
  const outSum = sumPoints(outputs);
  return outSum === undefined ? inSum : pointAdd(inSum, pointNeg(outSum));
}

// Prove conservation: the prover supplies the excess blinding r = sum(r_in) -
// sum(r_out); the proof is a Schnorr PoK that D = r*H.
export function proveConservation(inputs: Commitment[], outputs: Commitment[], excessBlinding: Scalar): { ok: true; proof: SchnorrProof } | { ok: false } {
  const d = netCommitment(inputs, outputs);
  if (d === undefined) return { ok: false };
  return { ok: true, proof: proveDlog(LABEL, H, d, excessBlinding) };
}

export function verifyConservation(inputs: Commitment[], outputs: Commitment[], proof: SchnorrProof): boolean {
  const d = netCommitment(inputs, outputs);
  if (d === undefined) return false;
  return verifyDlog(LABEL, H, d, proof);
}
