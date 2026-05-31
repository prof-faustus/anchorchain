// Metadata-obfuscation mode. Sensitive numeric metadata about a memory or file
// (size, age, score, count) leaks information even when the content is committed.
// In obfuscated mode a field is published only as a Pedersen commitment together
// with a range proof that it lies in a coarse BUCKET [low, low + 2^bucketBits) —
// the verifier learns the bucket, never the exact value, and the cleartext value
// is never present in the obfuscated record. Cleartext mode (for non-sensitive
// fields or local debugging) carries the value openly and is clearly typed as such,
// so the two can never be confused.
import type { Scalar } from '@anchorchain/bsv';
import { pointMulG, pointNeg, pointAdd, scalarMod, scalarIsZero } from '@anchorchain/bsv';
import type { Commitment } from './commit.js';
import { commit } from './commit.js';
import type { RangeProof } from './range.js';
import { proveRange, verifyRange } from './range.js';
import type { MembershipProof } from './membership.js';
import { proveMembership, verifyMembership } from './membership.js';

export type MetadataMode = 'cleartext' | 'obfuscated';

export interface CleartextField {
  mode: 'cleartext';
  name: string;
  value: Scalar;
}

export interface ObfuscatedField {
  mode: 'obfuscated';
  name: string;
  commitment: Commitment; // commitment to the true value
  bucketLow: Scalar;
  bucketBits: number;
  rangeProof: RangeProof; // proof that value - bucketLow in [0, 2^bucketBits)
}

// A categorical field obfuscated to "the value is one of this public set", hiding
// which element, via a zero-knowledge membership proof.
export interface MembershipFieldObf {
  mode: 'obfuscated-set';
  name: string;
  commitment: Commitment;
  set: Scalar[];
  proof: MembershipProof;
}

export type MetadataField = CleartextField | ObfuscatedField | MembershipFieldObf;

// A whole record of mixed cleartext and obfuscated fields, verified together.
export interface MetadataRecord {
  fields: MetadataField[];
}

export function cleartextField(name: string, value: Scalar): CleartextField {
  return { mode: 'cleartext', name, value };
}

// Obfuscate a field: commit to the value and prove it falls in the given bucket
// without revealing it. Fails if the value is outside the bucket.
export function obfuscateField(name: string, value: Scalar, blinding: Scalar, bucketLow: Scalar, bucketBits: number): { ok: true; field: ObfuscatedField } | { ok: false; error: string } {
  const offset = scalarMod(scalarMod(value) - scalarMod(bucketLow));
  // proveRange will reject an offset that does not fit in bucketBits, i.e. a value
  // below the bucket (wraps to a huge scalar) or at/above low + 2^bucketBits.
  const r = proveRange(offset, blinding, bucketBits);
  if (!r.ok) return { ok: false, error: 'value is not within the bucket' };
  return { ok: true, field: { mode: 'obfuscated', name, commitment: commit(value, blinding), bucketLow, bucketBits, rangeProof: r.proof } };
}

// Verify an obfuscated field: derive the commitment to (value - bucketLow) from the
// published commitment and check the range proof against it.
export function verifyObfuscatedField(field: ObfuscatedField): boolean {
  // C' = C - bucketLow*G commits to (value - bucketLow) under the same blinding
  const shifted = scalarIsZero(field.bucketLow) ? field.commitment : pointAdd(field.commitment, pointNeg(pointMulG(scalarMod(field.bucketLow))));
  return verifyRange(shifted as Commitment, field.rangeProof);
}

// Obfuscate a categorical field to membership in a public set, hiding the element.
export function obfuscateSetField(name: string, value: Scalar, blinding: Scalar, set: Scalar[]): { ok: true; field: MembershipFieldObf } | { ok: false; error: string } {
  const commitment = commit(value, blinding);
  const proof = proveMembership(commitment, blinding, set, value);
  if (!proof.ok) return { ok: false, error: 'value is not in the set' };
  return { ok: true, field: { mode: 'obfuscated-set', name, commitment, set, proof: proof.proof } };
}

export function verifySetField(field: MembershipFieldObf): boolean {
  return verifyMembership(field.commitment, field.set, field.proof);
}

// Verify a whole record: cleartext fields are trivially accepted, bucket fields by
// their range proof, set fields by their membership proof.
export function verifyRecord(record: MetadataRecord): boolean {
  for (const f of record.fields) {
    if (f.mode === 'cleartext') continue;
    if (f.mode === 'obfuscated' && !verifyObfuscatedField(f)) return false;
    if (f.mode === 'obfuscated-set' && !verifySetField(f)) return false;
  }
  return true;
}
