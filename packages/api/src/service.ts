// The high-level AnchorChain workflow service. It orchestrates the full lifecycle
// of an AI memory: append → batch → anchor (OP_RETURN) → confirm in a block →
// verify inclusion header-only → cross-agent recall — through one object.
//
// CORRECT SPV. The batch Merkle root R is embedded in the anchor transaction's
// OP_RETURN; the anchor transaction is itself a leaf of the BLOCK's Merkle tree.
// So verifying that a memory is anchored is a TWO-tree proof:
//   1. the memory leaf is in the batch tree with root R (batch Merkle path);
//   2. R is present in the anchor transaction (parse its OP_RETURN);
//   3. the anchor transaction's txid is in the block (txid → block-Merkle branch);
//   4. the block's Merkle root is the one its header commits to, in the header chain.
// This service performs all four — it does not conflate the batch root with a block
// Merkle root.
import type { Hash, Txid, BlockHeader, NodeClient, VerifyResult, Result } from '@anchorchain/bsv';
import { ok, err, verifyOk, verifyFail, HeaderChain, HashOps, TxidOps, txidOf, headerHash, meetsTarget, OfflineNodeClient } from '@anchorchain/bsv';
import { memoryLeaf } from '@anchorchain/hashing';
import type { Batch, Tier } from '@anchorchain/memstore';
import { MemStore } from '@anchorchain/memstore';
import { Anchorer, rootFromAnchorTx } from '@anchorchain/anchor';
import { merkleRoot, merkleProof, reconstructRoot } from '@anchorchain/merkle';
import { ProvenanceGraph } from '@anchorchain/provenance';
import type { AnchorChainConfig } from './config.js';

export interface AppendMemoryInput {
  agentId: string;
  vector: number[];
  timestamp: bigint;
  agentStateId: string;
  vectorId?: string;
  tier?: Tier;
  sourceDocHash?: Uint8Array;
  promptChainRef?: string;
  memoryLayerRef?: string;
}

export type InclusionReason =
  | { kind: 'UnknownVector' }
  | { kind: 'NotAnchored' }
  | { kind: 'BatchRootNotInAnchorTx' }
  | { kind: 'NotConfirmed' }
  | { kind: 'BlockRootMismatch' }
  | { kind: 'NoHeaderAtHeight' };

export interface InclusionOk {
  vectorId: string;
  batchId: string;
  anchorTxidDisplay: string;
  blockHeight: number;
}

export type ServiceError =
  | { kind: 'Append'; message: string }
  | { kind: 'UnknownBatch'; message: string; batchId: string }
  | { kind: 'NotAnchored'; message: string; batchId: string }
  | { kind: 'AnchorFailed'; message: string };

function emptyNode(): NodeClient {
  return new OfflineNodeClient({ headersByHeight: new Map(), headerByHash: new Map(), branches: new Map(), submitted: new Set() });
}

export class AnchorChainService {
  readonly headers = new HeaderChain(0);
  private readonly mem: MemStore;
  private readonly anchorer = new Anchorer();
  private readonly graph = new ProvenanceGraph();
  private readonly node: NodeClient;
  private readonly closed = new Map<string, Batch>();
  private readonly vectorToBatch = new Map<string, string>();
  private readonly vectorLeaf = new Map<string, Hash>();
  private readonly branchByTxid = new Map<string, { branch: Hash[]; index: number; height: number }>();
  private tipHash: Hash = HashOps.zero();
  private nextHeight = 0;

  constructor(config: AnchorChainConfig, node?: NodeClient) {
    this.mem = new MemStore({ closeOnCount: config.batch.closeOnCount, closeOnLogicalInterval: BigInt(config.batch.closeOnLogicalIntervalMs), maxBatchSize: config.batch.maxBatchSize });
    this.node = node ?? emptyNode();
  }

  // Append a memory atom. Returns the assigned vector id and, if the batch policy
  // closed a batch, its id (ready to anchor).
  appendMemory(input: AppendMemoryInput): Result<{ vectorId: string; closedBatchId?: string }, ServiceError> {
    const vectorId = input.vectorId ?? globalThis.crypto.randomUUID();
    const leaf = memoryLeaf(
      { agentId: input.agentId, sourceDocHash: input.sourceDocHash ?? HashOps.toInternalBytes(HashOps.zero()), promptChainRef: input.promptChainRef ?? '', memoryLayerRef: input.memoryLayerRef ?? '' },
      input.vector,
      input.timestamp,
    );
    const r = this.mem.append({ vectorId, contentHash: leaf, logicalTimestamp: input.timestamp, agentStateId: input.agentStateId, tier: input.tier ?? 'critical' }, input.timestamp);
    if (!r.ok) return err({ kind: 'Append', message: r.error.message });
    this.vectorLeaf.set(vectorId, leaf);
    const out: { vectorId: string; closedBatchId?: string } = { vectorId };
    if (r.value.closed) {
      this.registerClosed(r.value.closed);
      out.closedBatchId = r.value.closed.batchId;
    }
    return ok(out);
  }

  // Force-close the open batch; returns its id (or undefined if it was empty).
  closeOpen(logicalNow: bigint): string | undefined {
    const batch = this.mem.closeBatch(logicalNow);
    if (batch.atoms.length === 0) return undefined;
    this.registerClosed(batch);
    return batch.batchId;
  }

  private registerClosed(batch: Batch): void {
    this.closed.set(batch.batchId, batch);
    for (const a of batch.atoms) this.vectorToBatch.set(a.vectorId, batch.batchId);
  }

  // Anchor a closed batch: embed its root in an OP_RETURN carrier transaction and
  // submit it. Idempotent per batch id.
  async anchor(batchId: string, opts?: { tier?: Tier; schemaFingerprintHex?: string }): Promise<Result<{ anchorTxidDisplay: string }, ServiceError>> {
    const batch = this.closed.get(batchId);
    if (batch === undefined) return err({ kind: 'UnknownBatch', message: `batch ${batchId} not closed`, batchId });
    const m = await this.anchorer.anchorBatch(batch, this.node, opts);
    if (!m.ok) return err({ kind: 'AnchorFailed', message: m.error.message });
    // record provenance: each atom -> object, anchored
    for (const a of batch.atoms) this.graph.addIdentity(a.agentStateId);
    return ok({ anchorTxidDisplay: m.value.anchorTxidDisplay });
  }

  // Confirm an anchor transaction's inclusion in a block. The block is modelled by
  // the anchor txid plus the other transaction ids in that block; the service builds
  // the block Merkle tree, links a header committing to its root, and records the
  // txid → block-Merkle branch. (In production these come from the node's merkle
  // branch + header; here they are supplied so the path is verifiable offline.)
  confirmInBlock(batchId: string, otherBlockTxidsDisplay: string[]): Result<{ blockHeight: number; blockMerkleRootDisplay: string }, ServiceError> {
    const raw = this.anchorer.rawTxOf(batchId);
    if (raw === undefined) return err({ kind: 'NotAnchored', message: `batch ${batchId} not anchored`, batchId });
    const txid: Txid = txidOf(raw);
    const anchorLeaf = TxidOps.asHash(txid);
    const others: Hash[] = [];
    for (const d of otherBlockTxidsDisplay) {
      const t = TxidOps.fromDisplayHex(d);
      if (!t.ok) return err({ kind: 'AnchorFailed', message: `bad txid ${d}` });
      others.push(TxidOps.asHash(t.value));
    }
    const leaves = [anchorLeaf, ...others]; // anchor tx at index 0
    const root = merkleRoot(leaves);
    if (!root.ok) return err({ kind: 'AnchorFailed', message: 'empty block' });
    const proof = merkleProof(leaves, 0);
    if (!proof.ok) return err({ kind: 'AnchorFailed', message: 'no branch' });

    const header = this.mineHeader(root.value);
    const added = this.headers.add(header);
    if (!added.ok) return err({ kind: 'AnchorFailed', message: 'header did not link: ' + added.error.message });
    const height = this.nextHeight;
    this.tipHash = headerHash(header);
    this.nextHeight += 1;
    this.branchByTxid.set(TxidOps.toDisplayHex(txid), { branch: proof.value.siblings, index: 0, height });
    return ok({ blockHeight: height, blockMerkleRootDisplay: HashOps.toDisplayHex(root.value) });
  }

  // Full SPV verification of a memory's inclusion, header-only (all four steps).
  verifyInclusion(vectorId: string): VerifyResult<InclusionReason> {
    const batchId = this.vectorToBatch.get(vectorId);
    const leaf = this.vectorLeaf.get(vectorId);
    if (batchId === undefined || leaf === undefined) return verifyFail({ kind: 'UnknownVector' });
    // (1) batch Merkle path -> batch root R
    const ref = this.anchorer.referenceFor(batchId, vectorId);
    if (!ref.ok) return verifyFail({ kind: 'NotAnchored' });
    const batchRoot = reconstructRoot(leaf, ref.value.merklePath);
    // (2) R is in the anchor transaction's OP_RETURN
    const raw = this.anchorer.rawTxOf(batchId);
    if (raw === undefined) return verifyFail({ kind: 'NotAnchored' });
    const fromTx = rootFromAnchorTx(raw);
    if (!fromTx.ok || !HashOps.equals(fromTx.value.root, batchRoot)) return verifyFail({ kind: 'BatchRootNotInAnchorTx' });
    // (3) txid -> block-Merkle branch -> block root
    const txidDisplay = TxidOps.toDisplayHex(txidOf(raw));
    const branch = this.branchByTxid.get(txidDisplay);
    if (branch === undefined) return verifyFail({ kind: 'NotConfirmed' });
    const blockRoot = reconstructRoot(TxidOps.asHash(txidOf(raw)), { index: branch.index, siblings: branch.branch });
    // (4) block root is what the header at that height commits to
    const committed = this.headers.merkleRootAtHeight(branch.height);
    if (committed === undefined) return verifyFail({ kind: 'NoHeaderAtHeight' });
    if (!HashOps.equals(blockRoot, committed)) return verifyFail({ kind: 'BlockRootMismatch' });
    return verifyOk();
  }

  inclusion(vectorId: string): Result<InclusionOk, ServiceError> {
    const v = this.verifyInclusion(vectorId);
    const batchId = this.vectorToBatch.get(vectorId);
    if (!v.ok || batchId === undefined) return err({ kind: 'NotAnchored', message: `vector ${vectorId} not verifiably anchored`, batchId: batchId ?? '' });
    const raw = this.anchorer.rawTxOf(batchId)!;
    const branch = this.branchByTxid.get(TxidOps.toDisplayHex(txidOf(raw)))!;
    return ok({ vectorId, batchId, anchorTxidDisplay: TxidOps.toDisplayHex(txidOf(raw)), blockHeight: branch.height });
  }

  provenance(): ProvenanceGraph {
    return this.graph;
  }

  private mineHeader(blockMerkleRoot: Hash): BlockHeader {
    for (let nonce = 0; nonce < 1_000_000; nonce++) {
      const header: BlockHeader = { version: 1, prevBlockHash: this.tipHash, merkleRoot: blockMerkleRoot, time: 1_700_000_000 + this.nextHeight, bits: 0x207fffff, nonce };
      if (meetsTarget(header)) return header; // links are checked at the real headers.add
    }
    throw new Error('could not mine a regtest header');
  }
}
