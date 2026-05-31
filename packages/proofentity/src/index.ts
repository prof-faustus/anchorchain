// The proof entity is the artifact a holder PRESENTS to claim that a particular
// memory or file leaf is anchored on chain. Verification is HEADER-ONLY (SPV): the
// verifier holds nothing but a validated block-header chain — no full blocks, no
// full transactions — and decides the claim by reconstructing the batch root from
// the leaf and its Merkle path and matching it against the merkle root committed by
// a header. This is the trust boundary of the whole system: a proof entity is only
// as good as the header chain it terminates in, and nothing else is trusted.
//
// Two presentation forms are supported:
//   - FULL: the holder discloses the leaf and its complete Merkle path.
//   - ASSISTED: the holder discloses only the lower portion of the path plus the
//     public proof-assistance labels (proof-sharding selective disclosure). This is
//     selective disclosure by structure, NOT zero-knowledge.
import type { Hash, VerifyResult, Result, HeaderChain } from '@anchorchain/bsv';
import { ok, err, HashOps, verifyOk, verifyFail } from '@anchorchain/bsv';
import type { MerkleProof } from '@anchorchain/merkle';
import { reconstructRoot } from '@anchorchain/merkle';
import type { DisclosedPortion, ProofAssistance } from '@anchorchain/shard';
import { verifyWithAssistance } from '@anchorchain/shard';

export type Tier = 'ephemeral' | 'critical';

export type ProofEntityError =
  | { kind: 'NoAnchoredRoot'; message: string }
  | { kind: 'BadField'; message: string; field: string };

export type ProofVerifyReason =
  | { kind: 'RootMismatch' }
  | { kind: 'NoHeaderAtHeight' }
  | { kind: 'RootNotAnchored' }
  | { kind: 'HeightRootMismatch' };

// The presentable credential. `anchorTxidDisplay` and `schemaFingerprintHex` are
// carried for the holder's and auditor's convenience; the verification decision
// depends ONLY on the leaf, the path, and the header chain.
export interface ProofEntity {
  leaf: Hash;
  index: number;
  proof: MerkleProof;
  anchorTxidDisplay: string;
  blockHeight?: number;
  schemaFingerprintHex?: string;
  tier?: Tier;
}

export interface ProofEntityInput {
  leaf: Hash;
  index: number;
  proof: MerkleProof;
  anchorTxidDisplay: string;
  blockHeight?: number;
  schemaFingerprintHex?: string;
  tier?: Tier;
}

export function makeProofEntity(input: ProofEntityInput): Result<ProofEntity, ProofEntityError> {
  if (input.index < 0) return err({ kind: 'BadField', message: 'index must be >= 0', field: 'index' });
  if (input.anchorTxidDisplay.length !== 64) return err({ kind: 'BadField', message: 'anchor txid must be 32-byte display hex', field: 'anchorTxidDisplay' });
  const e: ProofEntity = { leaf: input.leaf, index: input.index, proof: input.proof, anchorTxidDisplay: input.anchorTxidDisplay };
  if (input.blockHeight !== undefined) e.blockHeight = input.blockHeight;
  if (input.schemaFingerprintHex !== undefined) e.schemaFingerprintHex = input.schemaFingerprintHex;
  if (input.tier !== undefined) e.tier = input.tier;
  return ok(e);
}

// The root this entity reconstructs from its leaf and path (the holder's claim).
export function claimedRoot(entity: ProofEntity): Hash {
  return reconstructRoot(entity.leaf, entity.proof);
}

// HEADER-ONLY verification. If the entity names a block height, the reconstructed
// root must equal the merkle root committed by the header at exactly that height
// (the strongest claim: it pins the anchor to a position in the chain). Otherwise
// the reconstructed root need only be present somewhere in the header chain.
export function verifyHeaderOnly(entity: ProofEntity, headers: HeaderChain): VerifyResult<ProofVerifyReason> {
  const root = claimedRoot(entity);
  if (entity.blockHeight !== undefined) {
    const committed = headers.merkleRootAtHeight(entity.blockHeight);
    if (committed === undefined) return verifyFail({ kind: 'NoHeaderAtHeight' });
    return HashOps.equals(root, committed) ? verifyOk() : verifyFail({ kind: 'HeightRootMismatch' });
  }
  return headers.containsMerkleRoot(root) === undefined ? verifyFail({ kind: 'RootNotAnchored' }) : verifyOk();
}

// The block height at which this entity's claim is anchored, derived from the
// header chain (None if the reconstructed root is not in the chain).
export function anchoredHeight(entity: ProofEntity, headers: HeaderChain): number | undefined {
  return headers.containsMerkleRoot(claimedRoot(entity))?.height;
}

// ASSISTED (selectively-disclosed) presentation: verify a disclosed lower portion
// plus public assistance labels against an anchored root, terminating in the
// header chain. Delegates to the proof-sharding verifier — still header-only.
export function verifyAssistedHeaderOnly(disclosed: DisclosedPortion, assistance: ProofAssistance, anchoredRoot: Hash, headers: HeaderChain): VerifyResult<ProofVerifyReason> {
  const r = verifyWithAssistance(disclosed, assistance, anchoredRoot, headers);
  if (r.ok) return verifyOk();
  // Map the shard reasons onto this layer's vocabulary without inventing trust.
  return verifyFail(r.reason.kind === 'RootNotAnchored' ? { kind: 'RootNotAnchored' } : { kind: 'RootMismatch' });
}
