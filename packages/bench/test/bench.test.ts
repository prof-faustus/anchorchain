import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runBench, formatReport } from '@anchorchain/bench';

test('14.b bench runs and reports deterministic sizes alongside host-dependent timings', () => {
  const r = runBench({ ci: true });
  assert.ok(r.timings.length >= 5);
  for (const t of r.timings) assert.ok(t.totalMs >= 0 && t.perOpMs >= 0);
  // sizes are deterministic structural counts
  const rangeBits = r.sizes.find((s) => s.name === 'range.proof.bitCommitments');
  assert.equal(rangeBits?.value, 16); // a 16-bit range proof has 16 bit commitments
  // selective disclosure is smaller than the full proof
  const full = r.sizes.find((s) => s.name === 'merkle.proof.full');
  const lower = r.sizes.find((s) => s.name === 'merkle.proof.disclosedLower');
  assert.ok(full && lower && lower.value < full.value);
  assert.ok(formatReport(r).includes('host:'));
});
