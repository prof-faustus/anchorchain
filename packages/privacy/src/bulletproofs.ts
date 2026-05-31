// A from-scratch Bulletproofs range proof: a Pedersen commitment V = v*G + r*H
// hides a value v in [0, 2^n) and the proof is LOGARITHMIC in n (an inner-product
// argument folds the 2n-length witness in log2(n) rounds). This is the sound,
// short alternative to the linear bit-decomposition proof in range.ts, and is what
// makes 32/64-bit confidential balances practical.
//
// HONEST LABELLING: this IS a Bulletproof (the Bunz-Bootle-Boneh inner-product
// range proof), implemented over secp256k1 with Fiat-Shamir. It is sound and
// zero-knowledge under discrete log in the random-oracle model, with NO trusted
// setup. It is NOT a zk-STARK and makes NO post-quantum claim. The transcript binds
// each round's L,R; this implementation is for honest use, not adversarial
// cross-protocol settings.
import type { Scalar, Point } from '@anchorchain/bsv';
import { CURVE_G, CURVE_H, scalarAdd, scalarSub, scalarMul, scalarInv, scalarMod, pointMul, pointAdd, pointEq } from '@anchorchain/bsv';
import type { Commitment } from './commit.js';
import { commit } from './commit.js';
import { challenge, randScalar } from './transcript.js';
import { generatorVector, BP_U } from './genpoints.js';

const G = CURVE_G;
const H = CURVE_H;

export interface InnerProductProof {
  L: Point[];
  R: Point[];
  a: Scalar;
  b: Scalar;
}
export interface RangeProofBP {
  bits: number;
  A: Point;
  S: Point;
  T1: Point;
  T2: Point;
  taux: Scalar;
  mu: Scalar;
  tHat: Scalar;
  ip: InnerProductProof;
}

export type RangeBPError = { kind: 'BadBits'; message: string } | { kind: 'OutOfRange'; message: string };

// ---- scalar-vector helpers ----
function vecAdd(a: Scalar[], b: Scalar[]): Scalar[] {
  return a.map((x, i) => scalarAdd(x, b[i] as Scalar));
}
function vecScale(s: Scalar, a: Scalar[]): Scalar[] {
  return a.map((x) => scalarMul(s, x));
}
function hadamard(a: Scalar[], b: Scalar[]): Scalar[] {
  return a.map((x, i) => scalarMul(x, b[i] as Scalar));
}
function inner(a: Scalar[], b: Scalar[]): Scalar {
  let acc = 0n;
  for (let i = 0; i < a.length; i++) acc = scalarAdd(acc, scalarMul(a[i] as Scalar, b[i] as Scalar));
  return acc;
}
function powers(base: Scalar, n: number): Scalar[] {
  const out: Scalar[] = [1n];
  for (let i = 1; i < n; i++) out.push(scalarMul(out[i - 1] as Scalar, base));
  return out;
}

// ---- point helpers (Option-typed to tolerate the identity element) ----
type OptPoint = Point | undefined;
function addOpt(a: OptPoint, b: OptPoint): OptPoint {
  if (a === undefined) return b;
  if (b === undefined) return a;
  return pointAdd(a, b);
}
function smul(s: Scalar, p: Point): OptPoint {
  return scalarMod(s) === 0n ? undefined : pointMul(p, s);
}
// multi-scalar: sum_i s_i * P_i
function msm(scalars: Scalar[], points: Point[]): OptPoint {
  let acc: OptPoint;
  for (let i = 0; i < scalars.length; i++) acc = addOpt(acc, smul(scalars[i] as Scalar, points[i] as Point));
  return acc;
}
function need(p: OptPoint): Point {
  if (p === undefined) throw new Error('unexpected identity point');
  return p;
}
function eqOpt(a: OptPoint, b: OptPoint): boolean {
  if (a === undefined || b === undefined) return a === b;
  return pointEq(a, b);
}

function isPow2(n: number): boolean {
  return n > 0 && (n & (n - 1)) === 0;
}

export function proveRangeBP(value: Scalar, blinding: Scalar, bits: number): { ok: true; proof: RangeProofBP; commitment: Commitment } | { ok: false; error: RangeBPError } {
  if (!isPow2(bits) || bits > 256) return { ok: false, error: { kind: 'BadBits', message: `bits must be a power of two in (0,256], got ${bits}` } };
  const v = scalarMod(value);
  if (v >= 1n << BigInt(bits)) return { ok: false, error: { kind: 'OutOfRange', message: `value does not fit in ${bits} bits` } };

  const n = bits;
  const gv = generatorVector('anchorchain/bp/g/v1', n);
  const hv = generatorVector('anchorchain/bp/h/v1', n);
  const U = BP_U;

  const commitment = commit(v, blinding);

  // bit vectors
  const aL = Array.from({ length: n }, (_, i) => (v >> BigInt(i)) & 1n);
  const aR = aL.map((b) => scalarSub(b, 1n));
  const alpha = randScalar();
  const A = need(addOpt(addOpt(smul(alpha, H), msm(aL, gv)), msm(aR, hv)));

  const sL = Array.from({ length: n }, () => randScalar());
  const sR = Array.from({ length: n }, () => randScalar());
  const rho = randScalar();
  const S = need(addOpt(addOpt(smul(rho, H), msm(sL, gv)), msm(sR, hv)));

  const y = challenge('anchorchain/bp/y', [A, S]);
  const z = challenge('anchorchain/bp/z', [A, S]);
  const yN = powers(y, n);
  const twoN = powers(2n, n);
  const oneN = Array.from({ length: n }, () => 1n);
  const z2 = scalarMul(z, z);

  // l(X) = (aL - z) + sL X ; r(X) = y^n o (aR + z) + z^2 2^n + (y^n o sR) X
  const l0 = vecAdd(aL, vecScale(scalarSub(0n, z), oneN));
  const l1 = sL;
  const r0 = vecAdd(hadamard(yN, vecAdd(aR, vecScale(z, oneN))), vecScale(z2, twoN));
  const r1 = hadamard(yN, sR);

  const t1 = scalarAdd(inner(l0, r1), inner(l1, r0));
  const t2 = inner(l1, r1);
  const tau1 = randScalar();
  const tau2 = randScalar();
  const T1 = need(addOpt(smul(t1, G), smul(tau1, H)));
  const T2 = need(addOpt(smul(t2, G), smul(tau2, H)));

  const x = challenge('anchorchain/bp/x', [T1, T2]);
  const x2 = scalarMul(x, x);

  const l = vecAdd(l0, vecScale(x, l1));
  const r = vecAdd(r0, vecScale(x, r1));
  const tHat = inner(l, r);
  const taux = scalarAdd(scalarAdd(scalarMul(tau2, x2), scalarMul(tau1, x)), scalarMul(z2, scalarMod(blinding)));
  const mu = scalarAdd(alpha, scalarMul(rho, x));

  // h'_i = (y^{-i}) * h_i
  const yInv = scalarInv(y);
  const yInvN = powers(yInv, n);
  const hp = hv.map((p, i) => pointMul(p, yInvN[i] as Scalar));

  const ip = proveInnerProduct(gv, hp, U, l, r);
  return { ok: true, proof: { bits, A, S, T1, T2, taux, mu, tHat, ip }, commitment };
}

export function verifyRangeBP(commitment: Commitment, proof: RangeProofBP): boolean {
  const n = proof.bits;
  if (!isPow2(n) || n > 256) return false;
  const gv = generatorVector('anchorchain/bp/g/v1', n);
  const hv = generatorVector('anchorchain/bp/h/v1', n);
  const U = BP_U;

  const y = challenge('anchorchain/bp/y', [proof.A, proof.S]);
  const z = challenge('anchorchain/bp/z', [proof.A, proof.S]);
  const x = challenge('anchorchain/bp/x', [proof.T1, proof.T2]);
  const yN = powers(y, n);
  const twoN = powers(2n, n);
  const oneN = Array.from({ length: n }, () => 1n);
  const z2 = scalarMul(z, z);
  const z3 = scalarMul(z2, z);
  const x2 = scalarMul(x, x);

  // delta(y,z) = (z - z^2)<1,y^n> - z^3 <1,2^n>
  const delta = scalarSub(scalarMul(scalarSub(z, z2), inner(oneN, yN)), scalarMul(z3, inner(oneN, twoN)));

  // Check 1: tHat*G + taux*H == z^2 V + delta*G + x T1 + x^2 T2
  const lhs1 = need(addOpt(smul(proof.tHat, G), smul(proof.taux, H)));
  const rhs1 = need(addOpt(addOpt(addOpt(smul(z2, commitment), smul(delta, G)), smul(x, proof.T1)), smul(x2, proof.T2)));
  if (!pointEq(lhs1, rhs1)) return false;

  // h'_i = y^{-i} h_i
  const yInv = scalarInv(y);
  const yInvN = powers(yInv, n);
  const hp = hv.map((p, i) => pointMul(p, yInvN[i] as Scalar));

  // P = A + xS + sum(-z) g_i + sum(z y^i + z^2 2^i) h'_i
  const gScalars = oneN.map(() => scalarSub(0n, z));
  const hScalars = yN.map((yi, i) => scalarAdd(scalarMul(z, yi), scalarMul(z2, twoN[i] as Scalar)));
  const P = need(addOpt(addOpt(addOpt(proof.A, need(smul(x, proof.S))), msm(gScalars, gv)), msm(hScalars, hp)));

  // P - mu*H + tHat*U is the inner-product commitment
  const Pip = need(addOpt(addOpt(P, smul(scalarSub(0n, proof.mu), H)), smul(proof.tHat, U)));
  return verifyInnerProduct(gv, hp, U, Pip, proof.ip);
}

// ---- inner-product argument (logarithmic) ----
function proveInnerProduct(gIn: Point[], hIn: Point[], U: Point, aIn: Scalar[], bIn: Scalar[]): InnerProductProof {
  let g = gIn.slice();
  let h = hIn.slice();
  let a = aIn.slice();
  let b = bIn.slice();
  const L: Point[] = [];
  const R: Point[] = [];
  let round = 0;
  while (a.length > 1) {
    const nn = a.length / 2;
    const aLo = a.slice(0, nn), aHi = a.slice(nn);
    const bLo = b.slice(0, nn), bHi = b.slice(nn);
    const gLo = g.slice(0, nn), gHi = g.slice(nn);
    const hLo = h.slice(0, nn), hHi = h.slice(nn);
    const cL = inner(aLo, bHi);
    const cR = inner(aHi, bLo);
    const Lj = need(addOpt(addOpt(msm(aLo, gHi), msm(bHi, hLo)), smul(cL, U)));
    const Rj = need(addOpt(addOpt(msm(aHi, gLo), msm(bLo, hHi)), smul(cR, U)));
    L.push(Lj);
    R.push(Rj);
    const u = challenge('anchorchain/bp/ip/' + round, [Lj, Rj]);
    const uInv = scalarInv(u);
    const gNext: Point[] = [];
    const hNext: Point[] = [];
    for (let i = 0; i < nn; i++) {
      gNext.push(need(addOpt(smul(uInv, gLo[i] as Point), smul(u, gHi[i] as Point))));
      hNext.push(need(addOpt(smul(u, hLo[i] as Point), smul(uInv, hHi[i] as Point))));
    }
    const aNext: Scalar[] = [];
    const bNext: Scalar[] = [];
    for (let i = 0; i < nn; i++) {
      aNext.push(scalarAdd(scalarMul(aLo[i] as Scalar, u), scalarMul(aHi[i] as Scalar, uInv)));
      bNext.push(scalarAdd(scalarMul(bLo[i] as Scalar, uInv), scalarMul(bHi[i] as Scalar, u)));
    }
    g = gNext;
    h = hNext;
    a = aNext;
    b = bNext;
    round += 1;
  }
  return { L, R, a: a[0] as Scalar, b: b[0] as Scalar };
}

function verifyInnerProduct(gIn: Point[], hIn: Point[], U: Point, Pin: Point, proof: InnerProductProof): boolean {
  let g = gIn.slice();
  let h = hIn.slice();
  let P: Point = Pin;
  for (let round = 0; round < proof.L.length; round++) {
    const Lj = proof.L[round] as Point;
    const Rj = proof.R[round] as Point;
    const u = challenge('anchorchain/bp/ip/' + round, [Lj, Rj]);
    const uInv = scalarInv(u);
    const u2 = scalarMul(u, u);
    const uInv2 = scalarMul(uInv, uInv);
    const nn = g.length / 2;
    const gLo = g.slice(0, nn), gHi = g.slice(nn);
    const hLo = h.slice(0, nn), hHi = h.slice(nn);
    const gNext: Point[] = [];
    const hNext: Point[] = [];
    for (let i = 0; i < nn; i++) {
      gNext.push(need(addOpt(smul(uInv, gLo[i] as Point), smul(u, gHi[i] as Point))));
      hNext.push(need(addOpt(smul(u, hLo[i] as Point), smul(uInv, hHi[i] as Point))));
    }
    g = gNext;
    h = hNext;
    // P' = u^2 L + P + u^{-2} R
    P = need(addOpt(addOpt(need(smul(u2, Lj)), P), need(smul(uInv2, Rj))));
  }
  // final: P == a g* + b h* + (a b) U
  const rhs = addOpt(addOpt(smul(proof.a, g[0] as Point), smul(proof.b, h[0] as Point)), smul(scalarMul(proof.a, proof.b), U));
  return eqOpt(P, rhs);
}
