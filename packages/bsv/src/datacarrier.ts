// Post-Genesis OP_RETURN data carrier: a provably-unspendable output carrying
// arbitrary data (no historic 520-byte push limit, no OP_RETURN size cap). The
// output locking script is OP_FALSE OP_RETURN <minimal pushdata of payload>. A
// configurable maximum bounds resource use (0.7); the protocol itself does not.
import type { Result } from './result.js';
import { ok, err } from './result.js';
import type { BsvError } from './errors.js';
import { carrierOversize, carrierNotRecognised } from './errors.js';
import type { Script } from './script.js';
import { OP_FALSE, OP_RETURN, fromBytes, toBytes, pushData, readPush } from './script.js';
import { concat } from './bytes.js';

// Generous default bound; the operator may lower it via config.
export const DEFAULT_MAX_CARRIER_BYTES = 100 * 1024 * 1024;

export function buildDataCarrier(payload: Uint8Array, maxBytes: number = DEFAULT_MAX_CARRIER_BYTES): Result<{ lockingScript: Script }, BsvError> {
  if (payload.length > maxBytes) return err(carrierOversize(maxBytes, payload.length));
  const bytes = concat(Uint8Array.of(OP_FALSE, OP_RETURN), pushData(payload));
  return ok({ lockingScript: fromBytes(bytes) });
}

export function parseDataCarrier(lockingScript: Script): Result<Uint8Array, BsvError> {
  const b = toBytes(lockingScript);
  if (b.length < 3 || b[0] !== OP_FALSE || b[1] !== OP_RETURN) return err(carrierNotRecognised());
  const push = readPush(b, 2);
  if (push === undefined || push.nextOffset !== b.length) return err(carrierNotRecognised());
  return ok(push.payload);
}
