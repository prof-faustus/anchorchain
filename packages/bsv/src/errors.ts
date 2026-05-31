// Typed error union for the bsv package.
export type BsvError =
  | { kind: 'HashBadLength'; message: string; got: number }
  | { kind: 'HashBadHex'; message: string; reason: 'length' | 'charset' }
  | { kind: 'BytesOutOfRange'; message: string; offset: number; length: number; bufferLength: number }
  | { kind: 'TxMalformed'; message: string; at: string }
  | { kind: 'TxTruncated'; message: string; neededBytes: number; gotBytes: number }
  | { kind: 'ScriptBadHex'; message: string }
  | { kind: 'HeaderBadLength'; message: string; got: number }
  | { kind: 'ChainNotLinked'; message: string; expectedPrev: string; gotPrev: string }
  | { kind: 'ChainBadPoW'; message: string; headerHashDisplay: string }
  | { kind: 'ChainNonMonotonic'; message: string; expectedHeight: number }
  | { kind: 'CarrierOversize'; message: string; maxBytes: number; gotBytes: number }
  | { kind: 'CarrierNotRecognised'; message: string }
  | { kind: 'CurveBadPoint'; message: string; detail: string }
  | { kind: 'NodeUnreachable'; message: string; detail: string }
  | { kind: 'NodeNotFound'; message: string; what: string }
  | { kind: 'NodeBadResponse'; message: string; detail: string };

export type BsvErrorKind = BsvError['kind'];

export function isBsvError(x: unknown): x is BsvError {
  return typeof x === 'object' && x !== null && 'kind' in x && typeof (x as { kind: unknown }).kind === 'string' && 'message' in x;
}

export const hashBadLength = (got: number): BsvError => ({ kind: 'HashBadLength', message: `hash must be 32 bytes, got ${got}`, got });
export const hashBadHex = (reason: 'length' | 'charset'): BsvError => ({ kind: 'HashBadHex', message: `bad hex (${reason})`, reason });
export const bytesOutOfRange = (offset: number, length: number, bufferLength: number): BsvError => ({ kind: 'BytesOutOfRange', message: `read of ${length} at ${offset} exceeds ${bufferLength}`, offset, length, bufferLength });
export const txMalformed = (at: string): BsvError => ({ kind: 'TxMalformed', message: `malformed transaction at ${at}`, at });
export const txTruncated = (neededBytes: number, gotBytes: number): BsvError => ({ kind: 'TxTruncated', message: `transaction truncated: needed ${neededBytes}, got ${gotBytes}`, neededBytes, gotBytes });
export const scriptBadHex = (): BsvError => ({ kind: 'ScriptBadHex', message: 'bad script hex' });
export const headerBadLength = (got: number): BsvError => ({ kind: 'HeaderBadLength', message: `header must be 80 bytes, got ${got}`, got });
export const chainNotLinked = (expectedPrev: string, gotPrev: string): BsvError => ({ kind: 'ChainNotLinked', message: `header prev ${gotPrev} != tip ${expectedPrev}`, expectedPrev, gotPrev });
export const chainBadPoW = (headerHashDisplay: string): BsvError => ({ kind: 'ChainBadPoW', message: `header ${headerHashDisplay} does not meet its target`, headerHashDisplay });
export const chainNonMonotonic = (expectedHeight: number): BsvError => ({ kind: 'ChainNonMonotonic', message: `non-monotonic height; expected ${expectedHeight}`, expectedHeight });
export const carrierOversize = (maxBytes: number, gotBytes: number): BsvError => ({ kind: 'CarrierOversize', message: `data-carrier payload ${gotBytes} exceeds configured max ${maxBytes}`, maxBytes, gotBytes });
export const carrierNotRecognised = (): BsvError => ({ kind: 'CarrierNotRecognised', message: 'output is not a recognised OP_RETURN data carrier' });
export const curveBadPoint = (detail: string): BsvError => ({ kind: 'CurveBadPoint', message: `invalid curve point: ${detail}`, detail });
export const nodeUnreachable = (detail: string): BsvError => ({ kind: 'NodeUnreachable', message: `node unreachable: ${detail}`, detail });
export const nodeNotFound = (what: string): BsvError => ({ kind: 'NodeNotFound', message: `not found: ${what}`, what });
export const nodeBadResponse = (detail: string): BsvError => ({ kind: 'NodeBadResponse', message: `bad node response: ${detail}`, detail });

export class BsvException extends Error {
  readonly error: BsvError;
  constructor(error: BsvError) {
    super(error.message);
    this.name = 'BsvException';
    this.error = error;
  }
}
export function throwBsv(error: BsvError): never {
  throw new BsvException(error);
}
