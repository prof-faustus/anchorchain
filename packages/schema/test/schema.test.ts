import { test } from 'node:test';
import assert from 'node:assert/strict';
import { toHexLower as toHex } from '@anchorchain/bsv';
import { canonicalObjectBytes, schemaFingerprintHex, validateSchema } from '@anchorchain/schema';
import type { SchemaDef, DataObject, Value } from '@anchorchain/schema';

const enc = (s: string) => new TextEncoder().encode(s);

function vecSchema(dim: number, fieldId = 'embedding'): SchemaDef {
  return { name: 'mem', fields: [{ fieldId, type: 'vector', dim }], timestampMode: 'logicalStep' };
}
function vecObject(dim: number, fieldId = 'embedding'): DataObject {
  const v = Array.from({ length: dim }, (_, i) => i * 0.5);
  return { schema: vecSchema(dim, fieldId), values: [{ type: 'vector', value: v, quantised: false }], timestamp: 7n };
}

test('3.3 canonicalisation is deterministic across calls', () => {
  const a = canonicalObjectBytes(vecObject(512));
  const b = canonicalObjectBytes(vecObject(512));
  assert.equal(a.ok && b.ok, true);
  if (a.ok && b.ok) assert.deepEqual(Array.from(a.value), Array.from(b.value));
});

test('3.3 a 512-d and a 768-d vector never collide (schema fingerprint + bytes differ)', () => {
  assert.notEqual(schemaFingerprintHex(vecSchema(512)), schemaFingerprintHex(vecSchema(768)));
  const a = canonicalObjectBytes(vecObject(512));
  const b = canonicalObjectBytes(vecObject(768));
  assert.equal(a.ok && b.ok, true);
  if (a.ok && b.ok) assert.notDeepEqual(Array.from(a.value), Array.from(b.value));
});

test('3.3 field context differentiates a point-cloud from a sentence embedding', () => {
  // same dimension, different field id => different fingerprint and bytes
  assert.notEqual(schemaFingerprintHex(vecSchema(512, 'pointCloud')), schemaFingerprintHex(vecSchema(512, 'sentence')));
});

test('3.3 a type/dimension mismatch is rejected', () => {
  const wrongType: DataObject = { schema: vecSchema(4), values: [{ type: 'int', value: 5n } as Value], timestamp: 0n };
  assert.equal(canonicalObjectBytes(wrongType).ok, false);
  const wrongDim: DataObject = { schema: vecSchema(4), values: [{ type: 'vector', value: [1, 2, 3], quantised: false }], timestamp: 0n };
  assert.equal(canonicalObjectBytes(wrongDim).ok, false);
});

test('3.3 mixed-field object canonicalises and validates', () => {
  const schema: SchemaDef = { name: 'rec', fields: [{ fieldId: 'id', type: 'string' }, { fieldId: 'score', type: 'float' }, { fieldId: 'flag', type: 'bool' }, { fieldId: 'blob', type: 'bytes' }], timestampMode: 'unixTime' };
  assert.equal(validateSchema(schema).ok, true);
  const obj: DataObject = { schema, values: [{ type: 'string', value: 'x' }, { type: 'float', value: 1.5 }, { type: 'bool', value: true }, { type: 'bytes', value: enc('z') }], timestamp: 1716000000n };
  const r = canonicalObjectBytes(obj);
  assert.equal(r.ok, true);
  if (r.ok) assert.ok(toHex(r.value).length > 0);
});
