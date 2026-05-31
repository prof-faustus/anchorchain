// Append-only commit log over AI memory atoms. A batch closes on a count
// threshold or a logical-interval boundary (config defaults, not code constants).
// Anchoring is tiered (an ephemeral coarse tier and a critical fine tier),
// recorded per atom.
import type { Hash, Result } from '@anchorchain/bsv';
import { ok, err, HashOps } from '@anchorchain/bsv';

export type Tier = 'ephemeral' | 'critical';

export interface MemoryAtom {
  vectorId: string; // UUID
  contentHash: Hash; // the memory leaf (from @anchorchain/hashing)
  logicalTimestamp: bigint;
  agentStateId: string;
  tier: Tier;
}

export interface Batch {
  batchId: string;
  atoms: MemoryAtom[];
  closedAtLogical: bigint;
}

export interface BatchPolicy {
  closeOnCount: number;
  closeOnLogicalInterval: bigint;
  maxBatchSize: number;
}

export type MemError =
  | { kind: 'BatchFull'; message: string; max: number }
  | { kind: 'SchemaInvalid'; message: string; field: string };

export class MemStore {
  private readonly policy: BatchPolicy;
  private open: MemoryAtom[] = [];
  private openedAtLogical: bigint | undefined;
  private batchCounter = 0;
  private readonly log: MemoryAtom[] = []; // append-only full log

  constructor(policy: BatchPolicy) {
    this.policy = policy;
  }

  // Append an atom; returns a closed batch when the policy boundary is reached.
  append(atom: MemoryAtom, logicalNow: bigint): Result<{ closed?: Batch }, MemError> {
    if (atom.vectorId.length === 0) return err({ kind: 'SchemaInvalid', message: 'vectorId required', field: 'vectorId' });
    if (atom.agentStateId.length === 0) return err({ kind: 'SchemaInvalid', message: 'agentStateId required', field: 'agentStateId' });
    if (this.open.length >= this.policy.maxBatchSize) return err({ kind: 'BatchFull', message: `batch at max ${this.policy.maxBatchSize}`, max: this.policy.maxBatchSize });
    if (this.openedAtLogical === undefined) this.openedAtLogical = logicalNow;
    this.open.push(atom);
    this.log.push(atom);
    const reachedCount = this.open.length >= this.policy.closeOnCount;
    const reachedInterval = logicalNow - (this.openedAtLogical as bigint) >= this.policy.closeOnLogicalInterval;
    if (reachedCount || reachedInterval) return ok({ closed: this.closeBatch(logicalNow) });
    return ok({});
  }

  // Force-close the open batch (e.g. at shutdown). Empty open batch => undefined.
  closeBatch(logicalNow: bigint): Batch {
    const batch: Batch = { batchId: `batch-${this.batchCounter}`, atoms: this.open, closedAtLogical: logicalNow };
    this.batchCounter += 1;
    this.open = [];
    this.openedAtLogical = undefined;
    return batch;
  }

  openCount(): number {
    return this.open.length;
  }
  totalAppended(): number {
    return this.log.length;
  }

  // Durable snapshot: the full append-only log, the open batch, and the counters,
  // serialised to plain JSON-safe values (content hashes as display hex, logical
  // timestamps as decimal strings). restore() rebuilds an equivalent MemStore.
  snapshot(): MemSnapshot {
    return {
      policy: { closeOnCount: this.policy.closeOnCount, closeOnLogicalInterval: this.policy.closeOnLogicalInterval.toString(), maxBatchSize: this.policy.maxBatchSize },
      log: this.log.map(atomToDto),
      open: this.open.map(atomToDto),
      openedAtLogical: this.openedAtLogical === undefined ? null : this.openedAtLogical.toString(),
      batchCounter: this.batchCounter,
    };
  }

  static restore(snapshot: MemSnapshot): MemStore {
    const store = new MemStore({ closeOnCount: snapshot.policy.closeOnCount, closeOnLogicalInterval: BigInt(snapshot.policy.closeOnLogicalInterval), maxBatchSize: snapshot.policy.maxBatchSize });
    for (const dto of snapshot.log) store.log.push(dtoToAtom(dto));
    store.open = snapshot.open.map(dtoToAtom);
    store.openedAtLogical = snapshot.openedAtLogical === null ? undefined : BigInt(snapshot.openedAtLogical);
    store.batchCounter = snapshot.batchCounter;
    return store;
  }
}

export interface MemoryAtomDto {
  vectorId: string;
  contentHashHex: string;
  logicalTimestamp: string;
  agentStateId: string;
  tier: Tier;
}
export interface MemSnapshot {
  policy: { closeOnCount: number; closeOnLogicalInterval: string; maxBatchSize: number };
  log: MemoryAtomDto[];
  open: MemoryAtomDto[];
  openedAtLogical: string | null;
  batchCounter: number;
}

function atomToDto(a: MemoryAtom): MemoryAtomDto {
  return { vectorId: a.vectorId, contentHashHex: HashOps.toDisplayHex(a.contentHash), logicalTimestamp: a.logicalTimestamp.toString(), agentStateId: a.agentStateId, tier: a.tier };
}
function dtoToAtom(d: MemoryAtomDto): MemoryAtom {
  const h = HashOps.fromDisplayHex(d.contentHashHex);
  if (!h.ok) throw new Error('snapshot has a malformed content hash');
  return { vectorId: d.vectorId, contentHash: h.value, logicalTimestamp: BigInt(d.logicalTimestamp), agentStateId: d.agentStateId, tier: d.tier };
}

// The Merkle leaves for a batch are the atoms' content hashes (in append order).
export function batchLeaves(batch: Batch): Hash[] {
  return batch.atoms.map((a) => a.contentHash);
}
