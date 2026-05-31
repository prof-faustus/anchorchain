import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scalarSub, scalarAdd, pointMulG } from '@anchorchain/bsv';
import { commit, proveRange, proveConservation, randScalar } from '@anchorchain/privacy';
import type { BalanceChange } from '@anchorchain/credit';
import { CreditLedger, verifyLedger } from '@anchorchain/credit';

const BITS = 16;

// An account holder that knows its balance and blindings and can construct the
// confidential authorisations the ledger verifies.
function holder(initial: bigint) {
  let balance = initial;
  let blinding = randScalar();
  const openProof = proveRange(balance, blinding, BITS);
  if (!openProof.ok) throw new Error('bad opening');
  return {
    get commitment() {
      return commit(balance, blinding);
    },
    openRange: openProof.proof,
    debit(amount: bigint): BalanceChange {
      const newBalance = balance - amount;
      const newBlinding = randScalar();
      const rp = proveRange(newBalance, newBlinding, BITS);
      if (!rp.ok) throw new Error('debit out of range');
      // old = new + amount  =>  conservation over inputs=[old], outputs=[new, amount*G]
      const excess = scalarSub(blinding, newBlinding);
      const cp = proveConservation([commit(balance, blinding)], [commit(newBalance, newBlinding), pointMulG(amount)], excess);
      if (!cp.ok) throw new Error('conservation');
      balance = newBalance;
      blinding = newBlinding;
      return { newCommitment: rp.commitment, conservation: cp.proof, rangeProof: rp.proof };
    },
    credit(amount: bigint): BalanceChange {
      const newBalance = balance + amount;
      const newBlinding = randScalar();
      const rp = proveRange(newBalance, newBlinding, BITS);
      if (!rp.ok) throw new Error('credit out of range');
      // old + amount = new  =>  conservation over inputs=[old, amount*G], outputs=[new]
      const excess = scalarSub(scalarAdd(blinding, 0n), newBlinding);
      const cp = proveConservation([commit(balance, blinding), pointMulG(amount)], [commit(newBalance, newBlinding)], excess);
      if (!cp.ok) throw new Error('conservation');
      balance = newBalance;
      blinding = newBlinding;
      return { newCommitment: rp.commitment, conservation: cp.proof, rangeProof: rp.proof };
    },
  };
}

test('12.1 open + confidential debit conserves and stays non-negative', () => {
  const ledger = new CreditLedger(BITS);
  const h = holder(1000n);
  assert.equal(ledger.open('agent', 'op-open', h.commitment, h.openRange).ok, true);
  const change = h.debit(250n);
  const r = ledger.debit('agent', 'op-1', 250n, change);
  assert.equal(r.ok, true);
});

test('12.2 no double-debit: replaying an op id is refused', () => {
  const ledger = new CreditLedger(BITS);
  const h = holder(1000n);
  ledger.open('agent', 'op-open', h.commitment, h.openRange);
  const change = h.debit(100n);
  assert.equal(ledger.debit('agent', 'op-1', 100n, change).ok, true);
  // the SAME op id, even with a fresh valid change, is rejected
  const change2 = h.debit(100n);
  const replay = ledger.debit('agent', 'op-1', 100n, change2);
  assert.equal(replay.ok === false && replay.error.kind, 'ReplayedOp');
});

test('12.3 an overdraft is impossible: debiting more than the balance has no range proof', () => {
  const ledger = new CreditLedger(BITS);
  const h = holder(100n);
  ledger.open('agent', 'op-open', h.commitment, h.openRange);
  // the holder cannot even construct a debit that underflows (new balance negative)
  assert.throws(() => h.debit(200n)); // proveRange on a negative (wrapped) value fails
});

test('12.3 a forged conservation (wrong amount) is rejected by the ledger', () => {
  const ledger = new CreditLedger(BITS);
  const h = holder(1000n);
  ledger.open('agent', 'op-open', h.commitment, h.openRange);
  const change = h.debit(250n); // a valid change for amount 250
  // submit it claiming a different public amount -> conservation fails
  const r = ledger.debit('agent', 'op-x', 300n, change);
  assert.equal(r.ok === false && r.error.kind, 'ConservationFailed');
});

test('12.4 credit grants increase the confidential balance and chain into the ledger', () => {
  const ledger = new CreditLedger(BITS);
  const h = holder(500n);
  ledger.open('agent', 'op-open', h.commitment, h.openRange);
  assert.equal(ledger.credit('agent', 'op-grant', 250n, h.credit(250n)).ok, true);
  assert.equal(ledger.debit('agent', 'op-spend', 700n, h.debit(700n)).ok, true); // 750 - 700 ok
  const entries = ledger.ledger();
  assert.deepEqual(entries.map((e) => e.kind), ['open', 'credit', 'debit']);
  assert.equal(verifyLedger(entries), true);
  // tampering an amount breaks the chain
  const tampered = entries.map((e) => ({ ...e }));
  tampered[1] = { ...tampered[1]!, amount: 999n };
  assert.equal(verifyLedger(tampered), false);
});
