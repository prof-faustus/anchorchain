// The provenance graph binds three kinds of node:
//   - IDENTITY: an agent (UUID / public-key-bound identity from the identity layer).
//   - OBJECT:   an information object — a memory vector or a file — addressed by its
//               content hash (the Merkle leaf the anchor layer committed).
//   - ANCHOR:   a batch root anchored in a BSV transaction at a block height.
// and the edges between them: an identity PRODUCED an object, an object is ANCHORED
// in an anchor, and an object may be DERIVED FROM another object (e.g. one agent
// recalls another agent's memory and re-anchors a transformation of it). Every
// object carries a proof entity, so every claim in the graph is verifiable
// header-only and CROSS-AGENT RECALL is not merely a pointer but a checkable proof:
// agent B can recall agent A's object and confirm, against block headers alone,
// that the recalled content is the one A anchored. No vector or file content is
// stored or logged here — only content hashes and proofs.
import type { VerifyResult, HeaderChain, Hash } from '@anchorchain/bsv';
import { ok, err, HashOps, verifyOk, verifyFail } from '@anchorchain/bsv';
import type { Result } from '@anchorchain/bsv';
import type { ProofEntity } from '@anchorchain/proofentity';
import { verifyHeaderOnly, claimedRoot } from '@anchorchain/proofentity';

export type ObjectKind = 'memory' | 'file';

export interface IdentityNode {
  agentId: string;
}
export interface ObjectNode {
  objectId: string;
  contentHash: Hash;
  agentId: string;
  kind: ObjectKind;
}
export interface AnchorNode {
  anchorTxidDisplay: string;
  rootDisplay: string;
  blockHeight?: number;
}

export type ProvError =
  | { kind: 'UnknownObject'; message: string; objectId: string }
  | { kind: 'UnknownAgent'; message: string; agentId: string }
  | { kind: 'DuplicateObject'; message: string; objectId: string }
  | { kind: 'LeafMismatch'; message: string; objectId: string }
  | { kind: 'Cycle'; message: string; objectId: string };

export type RecallVerifyReason =
  | { kind: 'LeafNotObject' } // the proof entity's leaf is not the object's content hash
  | { kind: 'NotAnchored' } // header-only verification failed
  | { kind: 'HeightRootMismatch' };

export interface Provenance {
  identity: IdentityNode;
  object: ObjectNode;
  anchor: AnchorNode;
}

// A cross-agent recall: a (possibly different) agent recalls an object and carries
// the proof entity required to verify it header-only.
export interface RecallRecord {
  recallingAgent: string;
  object: ObjectNode;
  entity: ProofEntity;
}

interface ObjectRecord {
  object: ObjectNode;
  anchor: AnchorNode;
  entity: ProofEntity;
  derivedFrom?: string;
}

export class ProvenanceGraph {
  private readonly agents = new Map<string, IdentityNode>();
  private readonly objects = new Map<string, ObjectRecord>();
  private readonly byAgent = new Map<string, string[]>();

  addIdentity(agentId: string): IdentityNode {
    const existing = this.agents.get(agentId);
    if (existing !== undefined) return existing;
    const node: IdentityNode = { agentId };
    this.agents.set(agentId, node);
    this.byAgent.set(agentId, this.byAgent.get(agentId) ?? []);
    return node;
  }

  // Record that `agentId` produced `object`, anchored as attested by `entity`. The
  // entity's leaf MUST equal the object's content hash (the proof must prove THIS
  // object). The anchor node is derived from the entity (root + txid + height).
  addObject(object: ObjectNode, entity: ProofEntity, derivedFrom?: string): Result<Provenance, ProvError> {
    if (this.objects.has(object.objectId)) return err({ kind: 'DuplicateObject', message: `object ${object.objectId} already recorded`, objectId: object.objectId });
    if (!HashOps.equals(entity.leaf, object.contentHash)) return err({ kind: 'LeafMismatch', message: 'proof entity leaf is not the object content hash', objectId: object.objectId });
    if (derivedFrom !== undefined && !this.objects.has(derivedFrom)) return err({ kind: 'UnknownObject', message: `parent ${derivedFrom} not recorded`, objectId: derivedFrom });
    const identity = this.addIdentity(object.agentId);
    const anchor: AnchorNode = { anchorTxidDisplay: entity.anchorTxidDisplay, rootDisplay: HashOps.toDisplayHex(claimedRoot(entity)) };
    if (entity.blockHeight !== undefined) anchor.blockHeight = entity.blockHeight;
    const rec: ObjectRecord = { object, anchor, entity };
    if (derivedFrom !== undefined) rec.derivedFrom = derivedFrom;
    this.objects.set(object.objectId, rec);
    (this.byAgent.get(object.agentId) as string[]).push(object.objectId);
    return ok({ identity, object, anchor });
  }

  hasObject(objectId: string): boolean {
    return this.objects.has(objectId);
  }
  objectsByAgent(agentId: string): ObjectNode[] {
    return (this.byAgent.get(agentId) ?? []).map((id) => (this.objects.get(id) as ObjectRecord).object);
  }
  anchorOf(objectId: string): AnchorNode | undefined {
    return this.objects.get(objectId)?.anchor;
  }
  provenanceOf(objectId: string): Result<Provenance, ProvError> {
    const rec = this.objects.get(objectId);
    if (rec === undefined) return err({ kind: 'UnknownObject', message: `object ${objectId} not recorded`, objectId });
    return ok({ identity: this.agents.get(rec.object.agentId) as IdentityNode, object: rec.object, anchor: rec.anchor });
  }

  // Derivation lineage: the object followed by its ancestors, oldest last. Spans
  // agents — this is how a memory recalled across agents keeps a verifiable trail.
  lineage(objectId: string): Result<ObjectNode[], ProvError> {
    const out: ObjectNode[] = [];
    const seen = new Set<string>();
    let cur: string | undefined = objectId;
    while (cur !== undefined) {
      if (seen.has(cur)) return err({ kind: 'Cycle', message: 'derivation cycle', objectId: cur });
      const rec: ObjectRecord | undefined = this.objects.get(cur);
      if (rec === undefined) return err({ kind: 'UnknownObject', message: `object ${cur} not recorded`, objectId: cur });
      seen.add(cur);
      out.push(rec.object);
      cur = rec.derivedFrom;
    }
    return ok(out);
  }

  // CROSS-AGENT RECALL: any agent may recall any recorded object; the record bundles
  // the object with the proof entity needed to verify it independently. Recall does
  // not require the recalling agent to be the producer (no siloing).
  recall(recallingAgent: string, objectId: string): Result<RecallRecord, ProvError> {
    const rec = this.objects.get(objectId);
    if (rec === undefined) return err({ kind: 'UnknownObject', message: `object ${objectId} not recorded`, objectId });
    return ok({ recallingAgent, object: rec.object, entity: rec.entity });
  }
}

// Verify a recall header-only: the proof entity must prove the object's content
// hash is anchored, and its leaf must BE that content hash. This is the check a
// recalling agent (or any third party) runs against block headers alone.
export function verifyRecall(record: RecallRecord, headers: HeaderChain): VerifyResult<RecallVerifyReason> {
  if (!HashOps.equals(record.entity.leaf, record.object.contentHash)) return verifyFail({ kind: 'LeafNotObject' });
  const r = verifyHeaderOnly(record.entity, headers);
  if (r.ok) return verifyOk();
  return verifyFail(r.reason.kind === 'HeightRootMismatch' ? { kind: 'HeightRootMismatch' } : { kind: 'NotAnchored' });
}
