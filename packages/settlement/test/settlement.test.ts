import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randScalar, commitEq, commit, addCommit } from '@anchorchain/privacy';
import type { Op } from '@anchorchain/settlement';
import { settle, equivalent } from '@anchorchain/settlement';

// A deterministic op stream across two agents over several logical-time periods.
function ops(): Op[] {
  const out: Op[] = [];
  const amounts: Array<[string, bigint, bigint]> = [
    ['agent-A', 10n, 0n],
    ['agent-B', 5n, 1n],
    ['agent-A', 7n, 3n],
    ['agent-A', 2n, 4n],
    ['agent-B', 9n, 5n],
    ['agent-B', 1n, 9n],
  ];
  for (const [agentId, amount, logicalTime] of amounts) out.push({ agentId, amount, blinding: randScalar(), logicalTime });
  return out;
}

test('13.1 per-op and periodic settlement are equivalent in totals and commitments', () => {
  const stream = ops();
  const perOp = settle(stream, 'per-op');
  const periodic = settle(stream, 'periodic', 3n); // periods of length 3 in logical time
  assert.equal(perOp.records.length, 6); // one per op
  assert.ok(periodic.records.length < 6); // ops collapse within periods
  assert.equal(equivalent(perOp, periodic), true);
  // explicit totals
  assert.equal(perOp.totalsByAgent.get('agent-A'), 19n);
  assert.equal(perOp.totalsByAgent.get('agent-B'), 15n);
  assert.equal(periodic.totalsByAgent.get('agent-A'), 19n);
  assert.equal(periodic.totalsByAgent.get('agent-B'), 15n);
});

test('13.2 the aggregate commitment is the homomorphic sum of all op commitments', () => {
  const stream = ops();
  const periodic = settle(stream, 'periodic', 4n);
  // independently sum the per-op commitments and compare
  let acc = commit(stream[0]!.amount, stream[0]!.blinding);
  for (let i = 1; i < stream.length; i++) acc = addCommit(acc, commit(stream[i]!.amount, stream[i]!.blinding));
  assert.equal(commitEq(periodic.aggregateCommitment, acc), true);
});

test('13.3 a different period length still settles to the same result', () => {
  const stream = ops();
  const p1 = settle(stream, 'periodic', 2n);
  const p2 = settle(stream, 'periodic', 5n);
  const perOp = settle(stream, 'per-op');
  assert.equal(equivalent(p1, p2), true);
  assert.equal(equivalent(p1, perOp), true);
});

test('13.4 a tampered total breaks equivalence', () => {
  const stream = ops();
  const a = settle(stream, 'per-op');
  const b = settle(stream, 'periodic', 3n);
  b.totalsByAgent.set('agent-A', 999n); // corrupt one agent's total
  assert.equal(equivalent(a, b), false);
});
