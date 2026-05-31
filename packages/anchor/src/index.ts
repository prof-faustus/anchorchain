// Anchoring: close a batch into a Merkle root R, embed R in a post-Genesis
// OP_RETURN data-carrier transaction, submit it, and record a manifest. Produces
// reference proofs exactly per paper §V.A: { vector_id, merkle_path, anchor_tx,
// block_height }, plus schema fingerprint and tier. Idempotent on batch id:
// re-anchoring a closed batch returns the existing anchor, never a second tx.
import type { Hash, Txid, Result, VerifyResult, NodeClient } from '@anchorchain/bsv';
import { ok, err, HashOps, TxidOps, concat, writeVarInt, buildDataCarrier, parseDataCarrier, parseTransaction, serializeTransaction, txidOf } from '@anchorchain/bsv';
import type { MerkleProof, MerkleVerifyReason } from '@anchorchain/merkle';
import { merkleRoot, merkleProof, verifyProof } from '@anchorchain/merkle';
import type { Batch, Tier } from '@anchorchain/memstore';
import { batchLeaves } from '@anchorchain/memstore';

export type AnchorError =
  | { kind: 'EmptyBatch'; message: string }
  | { kind: 'CarrierError'; message: string }
  | { kind: 'SubmitFailed'; message: string; detail: string }
  | { kind: 'NotAnchored'; message: string }
  | { kind: 'UnknownVector'; message: string; vectorId: string };

export interface AnchorManifest {
  batchId: string;
  rootDisplay: string;
  anchorTxidDisplay: string;
  blockHeight?: number;
  tier?: Tier;
  leafCount: number;
  schemaFingerprintHex?: string;
}

export interface ReferenceProof {
  vectorId: string;
  merklePath: MerkleProof;
  anchorTxidDisplay: string;
  blockHeight?: number;
  schemaFingerprintHex?: string;
  tier?: Tier;
}

interface AnchorRecord {
  manifest: AnchorManifest;
  batch: Batch;
  root: Hash;
  rawTx: Uint8Array;
}

const MAGIC = Uint8Array.of(0x41, 0x43, 0x48, 0x31); // "ACH1"
const enc = new TextEncoder();

export function encodeAnchorBlob(root: Hash, leafCount: number, batchId: string): Uint8Array {
  const lc = new Uint8Array(4);
  new DataView(lc.buffer).setUint32(0, leafCount, false);
  const id = enc.encode(batchId);
  return concat(MAGIC, HashOps.toInternalBytes(root), lc, writeVarInt(BigInt(id.length)), id);
}
export function decodeAnchorBlob(blob: Uint8Array): Result<{ root: Hash; leafCount: number; batchId: string }, AnchorError> {
  if (blob.length < 40 || blob[0] !== 0x41 || blob[1] !== 0x43 || blob[2] !== 0x48 || blob[3] !== 0x31) return err({ kind: 'CarrierError', message: 'bad anchor blob' });
  const root = HashOps.fromInternalBytes(blob.subarray(4, 36));
  if (!root.ok) return err({ kind: 'CarrierError', message: 'bad root' });
  const leafCount = new DataView(blob.buffer, blob.byteOffset + 36, 4).getUint32(0, false);
  // batchId length varint at offset 40
  const len = blob[40] as number;
  const batchId = new TextDecoder().decode(blob.subarray(41, 41 + len));
  return ok({ root: root.value, leafCount, batchId });
}

export class Anchorer {
  private readonly anchored = new Map<string, AnchorRecord>();
  private readonly carrierMax: number;

  constructor(carrierMax?: number) {
    this.carrierMax = carrierMax ?? 100 * 1024 * 1024;
  }

  isAnchored(batchId: string): boolean {
    return this.anchored.has(batchId);
  }
  manifest(batchId: string): AnchorManifest | undefined {
    return this.anchored.get(batchId)?.manifest;
  }
  rootOf(batchId: string): Hash | undefined {
    return this.anchored.get(batchId)?.root;
  }

  // Idempotent: a second call for the same batch id returns the existing anchor.
  async anchorBatch(batch: Batch, node: NodeClient, opts?: { tier?: Tier; schemaFingerprintHex?: string; blockHeight?: number }): Promise<Result<AnchorManifest, AnchorError>> {
    const existing = this.anchored.get(batch.batchId);
    if (existing !== undefined) return ok(existing.manifest);
    if (batch.atoms.length === 0) return err({ kind: 'EmptyBatch', message: `batch ${batch.batchId} is empty` });

    const leaves = batchLeaves(batch);
    const root = merkleRoot(leaves);
    if (!root.ok) return err({ kind: 'EmptyBatch', message: 'no leaves' });
    const carrier = buildDataCarrier(encodeAnchorBlob(root.value, leaves.length, batch.batchId), this.carrierMax);
    if (!carrier.ok) return err({ kind: 'CarrierError', message: carrier.error.message });
    const rawTx = serializeTransaction(1, [], [{ amountMinorUnits: 0n, lockingScript: carrier.value.lockingScript }], 0);
    const submitted = await node.submit(rawTx);
    if (!submitted.ok) return err({ kind: 'SubmitFailed', message: 'node rejected', detail: submitted.error.message });
    const txid: Txid = submitted.value;

    const manifest: AnchorManifest = {
      batchId: batch.batchId,
      rootDisplay: HashOps.toDisplayHex(root.value),
      anchorTxidDisplay: TxidOps.toDisplayHex(txid),
      leafCount: leaves.length,
    };
    if (opts?.tier !== undefined) manifest.tier = opts.tier;
    if (opts?.schemaFingerprintHex !== undefined) manifest.schemaFingerprintHex = opts.schemaFingerprintHex;
    if (opts?.blockHeight !== undefined) manifest.blockHeight = opts.blockHeight;
    this.anchored.set(batch.batchId, { manifest, batch, root: root.value, rawTx });
    return ok(manifest);
  }

  referenceFor(batchId: string, vectorId: string): Result<ReferenceProof, AnchorError> {
    const rec = this.anchored.get(batchId);
    if (rec === undefined) return err({ kind: 'NotAnchored', message: `batch ${batchId} not anchored` });
    const index = rec.batch.atoms.findIndex((a) => a.vectorId === vectorId);
    if (index < 0) return err({ kind: 'UnknownVector', message: `vector ${vectorId} not in batch`, vectorId });
    const path = merkleProof(batchLeaves(rec.batch), index);
    if (!path.ok) return err({ kind: 'UnknownVector', message: 'index out of range', vectorId });
    const ref: ReferenceProof = { vectorId, merklePath: path.value, anchorTxidDisplay: rec.manifest.anchorTxidDisplay };
    if (rec.manifest.blockHeight !== undefined) ref.blockHeight = rec.manifest.blockHeight;
    if (rec.manifest.schemaFingerprintHex !== undefined) ref.schemaFingerprintHex = rec.manifest.schemaFingerprintHex;
    if (rec.manifest.tier !== undefined) ref.tier = rec.manifest.tier;
    return ok(ref);
  }

  rawTxOf(batchId: string): Uint8Array | undefined {
    return this.anchored.get(batchId)?.rawTx;
  }
}

// Verify a reference proof against the committed batch root.
export function verifyReference(ref: ReferenceProof, atomContentHash: Hash, root: Hash): VerifyResult<MerkleVerifyReason> {
  return verifyProof(atomContentHash, ref.merklePath, root);
}

// Extract the anchored root from a data-carrier transaction (for an auditor who
// holds the raw anchor transaction).
export function rootFromAnchorTx(rawTx: Uint8Array): Result<{ root: Hash; txidDisplay: string }, AnchorError> {
  const tx = parseTransaction(rawTx);
  if (!tx.ok) return err({ kind: 'CarrierError', message: 'unparseable transaction' });
  for (const out of tx.value.outputs) {
    const payload = parseDataCarrier(out.lockingScript);
    if (!payload.ok) continue;
    const decoded = decodeAnchorBlob(payload.value);
    if (decoded.ok) return ok({ root: decoded.value.root, txidDisplay: TxidOps.toDisplayHex(txidOf(rawTx)) });
  }
  return err({ kind: 'CarrierError', message: 'no anchor data carrier found' });
}
