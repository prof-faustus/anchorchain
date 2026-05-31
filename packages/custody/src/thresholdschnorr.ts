// Threshold Schnorr signing in which the private key is NEVER reconstructed.
//
// The key x is Shamir-shared as x_i at points i (see shamir.ts). A fixed signing
// set S of t parties signs a message without ever assembling x: each party j
// contributes a partial signature s_j = k_j + e * lambda_j * x_j, where lambda_j is
// the public Lagrange coefficient of j over S at 0. Because sum_j lambda_j x_j = x
// (Lagrange interpolation at 0) and sum_j k_j = k, the aggregate s = sum_j s_j
// satisfies s*G = R + e*P, a valid Schnorr signature — yet no party ever holds more
// than its own share times a public coefficient.
//
// This is GENUINELY a "key never exists" scheme for SCHNORR, unlike the
// reconstruction custody in index.ts. It is deliberately distinct from, and NOT,
// threshold ECDSA — sound threshold ECDSA cannot be rolled safely from scratch, so
// it is not attempted. Nonces are COMMITTED in round one (a hash of R_j published
// before any R_j is revealed), which stops a party choosing its nonce adaptively
// after seeing the others within a session. Concurrent-session (ROS) hardening would
// require the full FROST two-nonce binding construction and is out of scope here;
// use one signing session at a time.
import type { Scalar, Point, Hash } from '@anchorchain/bsv';
import { ok, err, pointMulG, pointMul, pointAdd, pointEq, encodePoint, scalarAdd, scalarMul, scalarSub, scalarInv, scalarMod, reduceScalar, doubleSha256, concat, HashOps } from '@anchorchain/bsv';
import type { Result } from '@anchorchain/bsv';
import type { Share } from './shamir.js';

export interface NonceCommitment {
  index: bigint;
  commitment: Hash;
}
export interface NonceReveal {
  index: bigint;
  R: Point;
}
export interface PartialSig {
  index: bigint;
  s: Scalar;
}
export interface SchnorrSignature {
  R: Point;
  s: Scalar;
}

export type ThresholdError =
  | { kind: 'BadCommitment'; message: string; index: bigint }
  | { kind: 'EmptySet'; message: string }
  | { kind: 'NotRevealed'; message: string };

// Lagrange coefficient of party j over the signing set, evaluated at 0.
export function lagrangeCoefficient(signingSet: bigint[], j: bigint): Scalar {
  let num = 1n;
  let den = 1n;
  for (const m of signingSet) {
    if (m === j) continue;
    num = scalarMul(num, m);
    den = scalarMul(den, scalarSub(m, j));
  }
  return scalarMul(num, scalarInv(den));
}

function nonceCommitmentHash(index: bigint, R: Point): Hash {
  return doubleSha256(concat(new TextEncoder().encode('threshold-schnorr/nonce/'), encodePoint(R), encodePoint(pointMulG(index === 0n ? 1n : index))));
}

// The per-party signer. Holds its own share and, between rounds, its secret nonce.
export class ThresholdParty {
  private readonly share: Share;
  private nonce: Scalar | undefined;
  private R: Point | undefined;

  constructor(share: Share) {
    this.share = share;
  }

  get index(): bigint {
    return this.share.x;
  }

  // Round 1: pick a nonce, publish a commitment to its public point.
  commit(): NonceCommitment {
    const k = randScalar();
    this.nonce = k;
    this.R = pointMulG(k);
    return { index: this.share.x, commitment: nonceCommitmentHash(this.share.x, this.R) };
  }

  // Round 2: reveal the nonce point (after every party has committed).
  reveal(): NonceReveal {
    if (this.R === undefined) throw new Error('commit() must precede reveal()');
    return { index: this.share.x, R: this.R };
  }

  // Round 3: partial signature over the aggregated R and group public key P.
  partialSign(message: Uint8Array, publicKey: Point, aggregatedR: Point, signingSet: bigint[]): PartialSig {
    if (this.nonce === undefined) throw new Error('commit()/reveal() must precede partialSign()');
    const e = challengeOf(aggregatedR, publicKey, message);
    const lambda = lagrangeCoefficient(signingSet, this.share.x);
    const s = scalarAdd(this.nonce, scalarMul(e, scalarMul(lambda, this.share.y)));
    return { index: this.share.x, s };
  }
}

function challengeOf(R: Point, publicKey: Point, message: Uint8Array): Scalar {
  const e = reduceScalar(doubleSha256(concat(encodePoint(R), encodePoint(publicKey), message)));
  return e === 0n ? 1n : e;
}

function randScalar(): Scalar {
  for (;;) {
    const b = new Uint8Array(32);
    globalThis.crypto.getRandomValues(b);
    const s = reduceScalar(b);
    if (s !== 0n) return s;
  }
}

// Check that each revealed R_j matches its round-1 commitment.
export function verifyCommitments(commitments: NonceCommitment[], reveals: NonceReveal[]): boolean {
  if (commitments.length !== reveals.length) return false;
  for (const rev of reveals) {
    const c = commitments.find((x) => x.index === rev.index);
    if (c === undefined || !HashOps.equals(c.commitment, nonceCommitmentHash(rev.index, rev.R))) return false;
  }
  return true;
}

// Aggregate the revealed nonces and partial signatures into one Schnorr signature.
export function aggregate(reveals: NonceReveal[], partials: PartialSig[]): Result<SchnorrSignature, ThresholdError> {
  if (reveals.length === 0) return err({ kind: 'EmptySet', message: 'no reveals' });
  let R: Point | undefined;
  for (const rev of reveals) R = R === undefined ? rev.R : pointAdd(R, rev.R);
  let s = 0n;
  for (const p of partials) s = scalarAdd(s, p.s);
  return ok({ R: R as Point, s: scalarMod(s) });
}

export function aggregatedR(reveals: NonceReveal[]): Point {
  let R: Point | undefined;
  for (const rev of reveals) R = R === undefined ? rev.R : pointAdd(R, rev.R);
  return R as Point;
}

// Verify a Schnorr signature against the group public key: s*G == R + e*P.
export function verifyThresholdSchnorr(publicKey: Point, message: Uint8Array, sig: SchnorrSignature): boolean {
  const e = challengeOf(sig.R, publicKey, message);
  return pointEq(pointMulG(sig.s), pointAdd(sig.R, pointMul(publicKey, e)));
}
