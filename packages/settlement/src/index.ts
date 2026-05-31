// Settlement of metered usage. The same stream of operations can be settled two
// ways: PER-OP (one settlement record per operation, settling continuously) or
// PERIODICALLY (operations grouped into fixed logical-time periods, one record per
// agent per period). The EQUIVALENCE PROPERTY is that the two are
// indistinguishable in result: identical per-agent totals AND an identical
// aggregate Pedersen commitment. Because each record's commitment is a homomorphic
// sum of the same per-op commitments, equivalence is exact, not approximate — the
// choice of settlement cadence is purely operational and changes no balance.
import type { Scalar, Point } from '@anchorchain/bsv';
import { scalarAdd, pointAdd } from '@anchorchain/bsv';
import type { Commitment } from '@anchorchain/privacy';
import { commit, commitEq } from '@anchorchain/privacy';

export type SettlementMode = 'per-op' | 'periodic';

export interface Op {
  agentId: string;
  amount: bigint;
  blinding: Scalar; // the confidential blinding for this op's committed amount
  logicalTime: bigint;
}

export interface SettlementRecord {
  periodIndex: number;
  agentId: string;
  amount: bigint;
  commitment: Commitment;
  opCount: number;
}

export interface SettlementResult {
  mode: SettlementMode;
  records: SettlementRecord[];
  aggregateCommitment: Commitment;
  totalsByAgent: Map<string, bigint>;
  commitmentsByAgent: Map<string, Commitment>;
}

interface Bucket {
  periodIndex: number;
  agentId: string;
  amount: bigint;
  blinding: Scalar;
  opCount: number;
}

export function settle(ops: Op[], mode: SettlementMode, periodLength = 1n): SettlementResult {
  const buckets = new Map<string, Bucket>();
  let perOpCounter = 0;
  for (const op of ops) {
    const periodIndex = mode === 'per-op' ? perOpCounter++ : Number(op.logicalTime / periodLength);
    const key = mode === 'per-op' ? `${periodIndex}` : `${periodIndex}|${op.agentId}`;
    const existing = buckets.get(key);
    if (existing === undefined) {
      buckets.set(key, { periodIndex, agentId: op.agentId, amount: op.amount, blinding: op.blinding, opCount: 1 });
    } else {
      existing.amount += op.amount;
      existing.blinding = scalarAdd(existing.blinding, op.blinding);
      existing.opCount += 1;
    }
  }

  const records: SettlementRecord[] = [];
  const totalsByAgent = new Map<string, bigint>();
  const blindingByAgent = new Map<string, Scalar>();
  const amountByAgent = new Map<string, bigint>();
  let aggregate: Point | undefined;

  for (const b of buckets.values()) {
    const c = commit(b.amount, b.blinding);
    records.push({ periodIndex: b.periodIndex, agentId: b.agentId, amount: b.amount, commitment: c, opCount: b.opCount });
    totalsByAgent.set(b.agentId, (totalsByAgent.get(b.agentId) ?? 0n) + b.amount);
    amountByAgent.set(b.agentId, (amountByAgent.get(b.agentId) ?? 0n) + b.amount);
    blindingByAgent.set(b.agentId, scalarAdd(blindingByAgent.get(b.agentId) ?? 0n, b.blinding));
    aggregate = aggregate === undefined ? c : pointAdd(aggregate, c);
  }

  const commitmentsByAgent = new Map<string, Commitment>();
  for (const [agentId, amount] of amountByAgent) commitmentsByAgent.set(agentId, commit(amount, blindingByAgent.get(agentId) as Scalar));

  if (aggregate === undefined) throw new Error('cannot settle an empty operation stream');
  return { mode, records, aggregateCommitment: aggregate as Commitment, totalsByAgent, commitmentsByAgent };
}

// The equivalence check: two settlements of the same ops agree on every per-agent
// total, every per-agent confidential commitment, and the aggregate commitment.
export function equivalent(a: SettlementResult, b: SettlementResult): boolean {
  if (a.totalsByAgent.size !== b.totalsByAgent.size) return false;
  for (const [agentId, total] of a.totalsByAgent) {
    if (b.totalsByAgent.get(agentId) !== total) return false;
    const ca = a.commitmentsByAgent.get(agentId);
    const cb = b.commitmentsByAgent.get(agentId);
    if (ca === undefined || cb === undefined || !commitEq(ca, cb)) return false;
  }
  return commitEq(a.aggregateCommitment, b.aggregateCommitment);
}
