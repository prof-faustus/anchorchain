import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runSelftest, runStudies, computeVectors } from '@anchorchain/api';

test('14.a the self-test passes for every layer', async () => {
  const report = await runSelftest();
  for (const l of report.layers) assert.equal(l.ok, true, `${l.layer}: ${l.detail}`);
  assert.equal(report.ok, true);
});

test('14.a studies are deterministic across calls', () => {
  assert.deepEqual(runStudies(), runStudies());
  // structural sanity: a 16-bit range proof has 16 bit commitments => 48 group elements, 64 scalars
  const r16 = runStudies().rangeProofSize.find((r) => r.bits === 16);
  assert.equal(r16?.groupElements, 48);
  assert.equal(r16?.scalars, 64);
  // selective disclosure saves bytes at every level
  for (const d of runStudies().selectiveDisclosure) assert.ok(d.savedBytes > 0);
  assert.equal(runStudies().settlementEquivalence.equivalent, true);
});

test('14.a computed vectors are deterministic', () => {
  assert.deepEqual(computeVectors(), computeVectors());
});
