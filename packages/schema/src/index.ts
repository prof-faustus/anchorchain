// Canonical object schema and fingerprinting. An object is a tuple of typed
// fields plus a timestamp; its canonical serialisation is deterministic so that
// a dimension, type, or field-context difference ALWAYS changes the hash (a
// 512-d and a 768-d vector never collide; a point-cloud field and a sentence
// embedding are differentiated by field id).
import type { Result } from '@anchorchain/bsv';
import { ok, err, sha256, concat, writeVarInt, toHexLower } from '@anchorchain/bsv';

export type FieldType = 'int' | 'float' | 'bool' | 'string' | 'bytes' | 'vector';

export interface SchemaField {
  fieldId: string;
  type: FieldType;
  dim?: number; // declared dimension for vector fields (512 vs 768 never collide)
}

export type TimestampMode = 'logicalStep' | 'unixTime';

export interface SchemaDef {
  name: string;
  fields: SchemaField[];
  timestampMode: TimestampMode;
}

export type Value =
  | { type: 'int'; value: bigint }
  | { type: 'float'; value: number }
  | { type: 'bool'; value: boolean }
  | { type: 'string'; value: string }
  | { type: 'bytes'; value: Uint8Array }
  | { type: 'vector'; value: number[]; quantised: boolean };

export interface DataObject {
  schema: SchemaDef;
  values: Value[];
  timestamp: bigint; // logical step counter OR Unix time, per schema.timestampMode
}

export type SchemaError =
  | { kind: 'SchemaInvalid'; message: string; field: string }
  | { kind: 'ValueMismatch'; message: string; index: number }
  | { kind: 'Truncated'; message: string };

const schemaInvalid = (field: string, m: string): SchemaError => ({ kind: 'SchemaInvalid', message: m, field });
const valueMismatch = (index: number, m: string): SchemaError => ({ kind: 'ValueMismatch', message: m, index });

const enc = new TextEncoder();
const TYPE_CODE: Record<FieldType, number> = { int: 1, float: 2, bool: 3, string: 4, bytes: 5, vector: 6 };

function vstr(s: string): Uint8Array {
  const b = enc.encode(s);
  return concat(writeVarInt(BigInt(b.length)), b);
}
function u64be(n: bigint): Uint8Array {
  const out = new Uint8Array(8);
  let v = ((n % (1n << 64n)) + (1n << 64n)) % (1n << 64n);
  for (let i = 7; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}
function f64be(n: number): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setFloat64(0, n, false);
  return out;
}

export function validateSchema(def: SchemaDef): Result<void, SchemaError> {
  if (def.name.length === 0) return err(schemaInvalid('name', 'schema name required'));
  const seen = new Set<string>();
  for (const f of def.fields) {
    if (f.fieldId.length === 0) return err(schemaInvalid('fieldId', 'empty field id'));
    if (seen.has(f.fieldId)) return err(schemaInvalid(f.fieldId, 'duplicate field id'));
    seen.add(f.fieldId);
    if (f.type === 'vector' && (f.dim === undefined || f.dim <= 0)) return err(schemaInvalid(f.fieldId, 'vector field needs a positive dim'));
  }
  return ok(undefined);
}

// Canonical, deterministic schema-definition bytes (versioned; fields in declared
// order). The schema fingerprint is sha256 of these bytes.
export function canonicalSchemaBytes(def: SchemaDef): Uint8Array {
  const parts: Uint8Array[] = [Uint8Array.of(0x01), vstr(def.name), Uint8Array.of(def.timestampMode === 'logicalStep' ? 0 : 1), writeVarInt(BigInt(def.fields.length))];
  for (const f of def.fields) {
    parts.push(vstr(f.fieldId), Uint8Array.of(TYPE_CODE[f.type]));
    parts.push(writeVarInt(BigInt(f.type === 'vector' ? (f.dim ?? 0) : 0)));
  }
  return concat(...parts);
}

export function schemaFingerprint(def: SchemaDef): Uint8Array {
  return sha256(canonicalSchemaBytes(def));
}
export function schemaFingerprintHex(def: SchemaDef): string {
  return toHexLower(schemaFingerprint(def));
}

function encodeValue(field: SchemaField, v: Value): Result<Uint8Array, SchemaError> {
  if (v.type !== field.type) return err(valueMismatch(0, `expected ${field.type}, got ${v.type}`));
  switch (v.type) {
    case 'int':
      return ok(u64be(v.value));
    case 'float':
      return ok(f64be(v.value));
    case 'bool':
      return ok(Uint8Array.of(v.value ? 1 : 0));
    case 'string':
      return ok(vstr(v.value));
    case 'bytes':
      return ok(concat(writeVarInt(BigInt(v.value.length)), v.value));
    case 'vector': {
      if (field.dim !== undefined && v.value.length !== field.dim) return err(valueMismatch(0, `vector dim ${v.value.length} != declared ${field.dim}`));
      const body: Uint8Array[] = [writeVarInt(BigInt(v.value.length)), Uint8Array.of(v.quantised ? 1 : 0)];
      if (v.quantised) {
        const q = new Uint8Array(v.value.length);
        for (let i = 0; i < v.value.length; i++) q[i] = Math.max(0, Math.min(255, Math.round((v.value[i] as number)))) & 0xff;
        body.push(q);
      } else {
        for (const x of v.value) body.push(f64be(x));
      }
      return ok(concat(...body));
    }
  }
}

// Canonical object bytes: schema fingerprint prefix, then each field's
// (id, type, value) in schema order, then the timestamp encoded per the mode.
export function canonicalObjectBytes(obj: DataObject): Result<Uint8Array, SchemaError> {
  const sv = validateSchema(obj.schema);
  if (!sv.ok) return sv;
  if (obj.values.length !== obj.schema.fields.length) return err(valueMismatch(obj.values.length, 'value count != field count'));
  const parts: Uint8Array[] = [schemaFingerprint(obj.schema)];
  for (let i = 0; i < obj.schema.fields.length; i++) {
    const field = obj.schema.fields[i] as SchemaField;
    const value = obj.values[i] as Value;
    parts.push(vstr(field.fieldId), Uint8Array.of(TYPE_CODE[field.type]));
    const encoded = encodeValue(field, value);
    if (!encoded.ok) return err(valueMismatch(i, encoded.error.message));
    parts.push(encoded.value);
  }
  parts.push(obj.schema.timestampMode === 'logicalStep' ? writeVarInt(obj.timestamp) : u64be(obj.timestamp));
  return ok(concat(...parts));
}
