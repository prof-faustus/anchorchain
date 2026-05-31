// The AI credit / quota ledger. Each agent's balance is held as a CONFIDENTIAL
// Pedersen commitment, never as a cleartext number. An operation has a unique op id
// and is applied EXACTLY ONCE — replaying an op id is refused (no double-debit). A
// debit is authorised confidentially: the holder submits the new balance commitment
// together with (1) a homomorphic CONSERVATION proof that old_balance = new_balance
// + amount and (2) a RANGE proof that the new balance is non-negative (in
// [0, 2^bits)), so an overdraft is impossible — all without revealing any balance.
// Every applied op extends an anchorable hash-chained ledger. No balance, blinding,
// or proof witness is ever logged.
import type { Hash, Result } from '@anchorchain/bsv';
import { ok, err, doubleSha256, concat, writeVarInt, HashOps, pointMulG, pointToHex } from '@anchorchain/bsv';
import type { Commitment, RangeProof, SchnorrProof } from '@anchorchain/privacy';
import { verifyConservation, verifyRange } from '@anchorchain/privacy';

export type CreditError =
  | { kind: 'UnknownAccount'; message: string; agentId: string }
  | { kind: 'DuplicateAccount'; message: string; agentId: string }
  | { kind: 'ReplayedOp'; message: string; opId: string }
  | { kind: 'BadAmount'; message: string }
  | { kind: 'ConservationFailed'; message: string }
  | { kind: 'RangeFailed'; message: string };

export type LedgerKind = 'open' | 'debit' | 'credit';

export interface LedgerEntry {
  kind: LedgerKind;
  agentId: string;
  opId: string;
  amount: bigint; // the operation's price/grant (public); balances stay confidential
  balanceCommitmentHex: string;
  prevHashHex: string;
  hashHex: string;
}

// A confidential balance-change authorisation produced by the account holder, who
// alone knows the balance and blindings.
export interface BalanceChange {
  newCommitment: Commitment;
  conservation: SchnorrProof; // proves old = new + amount (debit) / old + amount = new (credit)
  rangeProof: RangeProof; // proves the new balance is in [0, 2^bits)
}

const enc = new TextEncoder();

function entryHash(kind: LedgerKind, agentId: string, opId: string, amount: bigint, commitmentHex: string, prev: Uint8Array): Hash {
  return doubleSha256(concat(enc.encode('credit/' + kind + '/'), enc.encode(agentId), enc.encode(opId), writeVarInt(amount), enc.encode(commitmentHex), prev));
}

export class CreditLedger {
  private readonly bits: number;
  private readonly balances = new Map<string, Commitment>();
  private readonly appliedOps = new Set<string>();
  private readonly entries: LedgerEntry[] = [];
  private lastHash: Hash = HashOps.zero();

  constructor(rangeBits = 32) {
    this.bits = rangeBits;
  }

  // Open an account at an initial confidential balance (the holder supplies the
  // commitment and a range proof that the opening balance is non-negative).
  open(agentId: string, opId: string, initial: Commitment, rangeProof: RangeProof): Result<LedgerEntry, CreditError> {
    if (this.balances.has(agentId)) return err({ kind: 'DuplicateAccount', message: `account ${agentId} exists`, agentId });
    if (this.appliedOps.has(opId)) return err({ kind: 'ReplayedOp', message: `op ${opId} already applied`, opId });
    if (rangeProof.bits !== this.bits || !verifyRange(initial, rangeProof)) return err({ kind: 'RangeFailed', message: 'opening balance is not a valid non-negative amount' });
    this.balances.set(agentId, initial);
    this.appliedOps.add(opId);
    return ok(this.append('open', agentId, opId, 0n, initial));
  }

  balanceCommitment(agentId: string): Commitment | undefined {
    return this.balances.get(agentId);
  }

  // Debit `amount` (public op price). old_balance == new_balance + amount, proven by
  // conservation over inputs=[old], outputs=[new, amount*G]; new balance proven in
  // range. Applied exactly once per op id.
  debit(agentId: string, opId: string, amount: bigint, change: BalanceChange): Result<LedgerEntry, CreditError> {
    const guard = this.preCheck(agentId, opId, amount);
    if (!guard.ok) return guard;
    const old = this.balances.get(agentId) as Commitment;
    const amountPoint = pointMulG(amount); // commit(amount, 0)
    if (!verifyConservation([old], [change.newCommitment, amountPoint], change.conservation)) return err({ kind: 'ConservationFailed', message: 'balance change does not conserve old = new + amount' });
    if (change.rangeProof.bits !== this.bits || !verifyRange(change.newCommitment, change.rangeProof)) return err({ kind: 'RangeFailed', message: 'new balance is not a valid non-negative amount' });
    return ok(this.applyChange('debit', agentId, opId, amount, change.newCommitment));
  }

  // Credit (grant) `amount`. old_balance + amount == new_balance: conservation over
  // inputs=[old, amount*G], outputs=[new].
  credit(agentId: string, opId: string, amount: bigint, change: BalanceChange): Result<LedgerEntry, CreditError> {
    const guard = this.preCheck(agentId, opId, amount);
    if (!guard.ok) return guard;
    const old = this.balances.get(agentId) as Commitment;
    const amountPoint = pointMulG(amount);
    if (!verifyConservation([old, amountPoint], [change.newCommitment], change.conservation)) return err({ kind: 'ConservationFailed', message: 'balance change does not conserve old + amount = new' });
    if (change.rangeProof.bits !== this.bits || !verifyRange(change.newCommitment, change.rangeProof)) return err({ kind: 'RangeFailed', message: 'new balance is not a valid non-negative amount' });
    return ok(this.applyChange('credit', agentId, opId, amount, change.newCommitment));
  }

  ledger(): LedgerEntry[] {
    return this.entries.map((e) => ({ ...e }));
  }
  headHash(): Hash {
    return this.lastHash;
  }

  private preCheck(agentId: string, opId: string, amount: bigint): Result<true, CreditError> {
    if (!this.balances.has(agentId)) return err({ kind: 'UnknownAccount', message: `unknown account ${agentId}`, agentId });
    if (this.appliedOps.has(opId)) return err({ kind: 'ReplayedOp', message: `op ${opId} already applied`, opId });
    if (amount <= 0n) return err({ kind: 'BadAmount', message: 'amount must be positive' });
    return ok(true);
  }

  private applyChange(kind: LedgerKind, agentId: string, opId: string, amount: bigint, next: Commitment): LedgerEntry {
    this.balances.set(agentId, next);
    this.appliedOps.add(opId);
    return this.append(kind, agentId, opId, amount, next);
  }

  private append(kind: LedgerKind, agentId: string, opId: string, amount: bigint, commitment: Commitment): LedgerEntry {
    const cHex = pointToHex(commitment);
    const h = entryHash(kind, agentId, opId, amount, cHex, HashOps.toInternalBytes(this.lastHash));
    const entry: LedgerEntry = { kind, agentId, opId, amount, balanceCommitmentHex: cHex, prevHashHex: HashOps.toDisplayHex(this.lastHash), hashHex: HashOps.toDisplayHex(h) };
    this.entries.push(entry);
    this.lastHash = h;
    return entry;
  }
}

// Verify the ledger hash chain links from genesis to head.
export function verifyLedger(entries: LedgerEntry[]): boolean {
  let prev: Hash = HashOps.zero();
  for (const e of entries) {
    if (e.prevHashHex !== HashOps.toDisplayHex(prev)) return false;
    const h = entryHash(e.kind, e.agentId, e.opId, e.amount, e.balanceCommitmentHex, HashOps.toInternalBytes(prev));
    if (HashOps.toDisplayHex(h) !== e.hashHex) return false;
    prev = h;
  }
  return true;
}
