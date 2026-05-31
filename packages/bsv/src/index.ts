// Public surface of @anchorchain/bsv.
export type { Result, VerifyResult } from './result.js';
export { ok, err, verifyOk, verifyFail } from './result.js';

export type { BsvError, BsvErrorKind } from './errors.js';
export {
  isBsvError,
  BsvException,
  throwBsv,
  hashBadLength,
  hashBadHex,
  bytesOutOfRange,
  txMalformed,
  txTruncated,
  scriptBadHex,
  headerBadLength,
  chainNotLinked,
  chainBadPoW,
  chainNonMonotonic,
  carrierOversize,
  carrierNotRecognised,
  curveBadPoint,
  nodeUnreachable,
  nodeNotFound,
  nodeBadResponse,
} from './errors.js';

export type { VarInt } from './bytes.js';
export { readU32LE, writeU32LE, readVarInt, writeVarInt, reverseBytes, concat, toHexLower, fromHex } from './bytes.js';

export { doubleSha256, sha256 } from './hashing.js';

export * as HashOps from './hash.js';
export type { Hash } from './hash.js';
export { HASH_LEN } from './hash.js';

export * as TxidOps from './txid.js';
export type { Txid } from './txid.js';

export * as ScriptOps from './script.js';
export type { Script } from './script.js';

export type { Scalar, Point } from './curve.js';
export {
  CURVE_N,
  CURVE_P,
  CURVE_G,
  CURVE_H,
  scalarMod,
  scalarAdd,
  scalarMul,
  scalarSub,
  scalarInv,
  scalarIsZero,
  reduceScalar,
  pointMul,
  pointMulG,
  pointAdd,
  pointNeg,
  pointEq,
  encodePoint,
  pointToHex,
  decodePoint,
  pointFromHex,
} from './curve.js';

export type { TxInput, TxOutput, Transaction } from './transaction.js';
export { parseTransaction, serializeTransaction, txidOf } from './transaction.js';

export type { BlockHeader } from './header.js';
export { HEADER_LEN, parseHeader, serializeHeader, headerHash, targetFromBits, meetsTarget } from './header.js';

export { HeaderChain } from './headerchain.js';

export { DEFAULT_MAX_CARRIER_BYTES, buildDataCarrier, parseDataCarrier } from './datacarrier.js';

export type { NodeClient, MerkleBranch, OfflineDataset, Transport, TransportResult } from './nodeclient.js';
export { OfflineNodeClient, TeranodeClient } from './nodeclient.js';
