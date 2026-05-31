// The single double-SHA-256 site, via the BSV SDK. No package computes a chain
// hash directly.
import { Hash as SdkHash } from '@bsv/sdk';
import type { Hash } from './hash.js';
import { fromInternalBytes } from './hash.js';
import { throwBsv, hashBadLength } from './errors.js';

export function doubleSha256(data: Uint8Array): Hash {
  const digest = SdkHash.hash256(Array.from(data));
  const wrapped = fromInternalBytes(Uint8Array.from(digest));
  if (!wrapped.ok) throwBsv(hashBadLength(digest.length));
  return wrapped.value;
}

// SHA-256 (single) — used only where a non-chain digest is needed (e.g. schema
// fingerprints); never as a Merkle/chain node hash.
export function sha256(data: Uint8Array): Uint8Array {
  return Uint8Array.from(SdkHash.sha256(Array.from(data)));
}
