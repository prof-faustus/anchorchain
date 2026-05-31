import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randScalar, cleartextField, obfuscateField, obfuscateSetField, verifySetField, verifyRecord } from '@anchorchain/privacy';

test('9.6 a set-membership metadata field hides which element, and verifies', () => {
  const tiers = [1n, 2n, 3n]; // e.g. ephemeral / standard / critical encoded
  const f = obfuscateSetField('tier', 3n, randScalar(), tiers);
  assert.ok(f.ok);
  if (f.ok) {
    assert.equal(verifySetField(f.field), true);
    assert.equal('value' in f.field, false); // the element is not present
  }
  // a value outside the set cannot be obfuscated into it
  assert.equal(obfuscateSetField('tier', 9n, randScalar(), tiers).ok, false);
});

test('9.6 a mixed metadata record verifies as a whole and fails if any field is bad', () => {
  const r = randScalar();
  const bucket = obfuscateField('sizeBytes', 5000n, r, 4096n, 10);
  const setf = obfuscateSetField('tier', 2n, randScalar(), [1n, 2n, 3n]);
  assert.ok(bucket.ok && setf.ok);
  if (!bucket.ok || !setf.ok) return;
  const record = { fields: [cleartextField('schemaVersion', 1n), bucket.field, setf.field] };
  assert.equal(verifyRecord(record), true);
  // corrupt the set field's set so the membership proof no longer applies
  const broken = { fields: [...record.fields.slice(0, 2), { ...setf.field, set: [7n, 8n, 9n] }] };
  assert.equal(verifyRecord(broken), false);
});
