// Public surface of @anchorchain/api: typed config, the end-to-end self-test, the
// deterministic studies, and the reproduction/verification of committed vectors.
export type { AnchorChainConfig } from './config.js';
export { loadConfig, validateConfig } from './config.js';

export type { SelftestReport, LayerResult } from './selftest.js';
export { runSelftest } from './selftest.js';

export type { Studies, RangeSizeRow, RangeComparisonRow, DisclosureRow, EquivalenceRow } from './studies.js';
export { runStudies } from './studies.js';

export type { ReproVectors, ReproResult } from './reproduce.js';
export { computeVectors, reproduceAndCheck, vectorPath } from './reproduce.js';

export type { AppendMemoryInput, InclusionReason, InclusionOk, ServiceError } from './service.js';
export { AnchorChainService } from './service.js';

// Curated re-export façade: the whole public surface from one import.
export { HeaderChain, OfflineNodeClient, TeranodeClient, HashOps, TxidOps, ecdsaSign, ecdsaVerify, pubKeyOf } from '@anchorchain/bsv';
export { memoryLeaf } from '@anchorchain/hashing';
export { schemaFingerprintHex, validateSchema, canonicalObjectBytes } from '@anchorchain/schema';
export { hashLeaf, merkleRoot, merkleProof, verifyProof, proveAgainstChain } from '@anchorchain/merkle';
export { shardProof, proofAssistance, verifyWithAssistance } from '@anchorchain/shard';
export { MemStore, batchLeaves } from '@anchorchain/memstore';
export { Anchorer, verifyReference, rootFromAnchorTx } from '@anchorchain/anchor';
export { chunkFile, discloseChunk, discloseRange, verifyChunk, verifyWholeFile } from '@anchorchain/file';
export { makeProofEntity, verifyHeaderOnly } from '@anchorchain/proofentity';
export { ProofStore, InMemoryBackend, FileBackend } from '@anchorchain/proofstore';
export { ProvenanceGraph, verifyRecall } from '@anchorchain/provenance';
export { commit, proveRange, verifyRange, proveRangeBP, verifyRangeBP, proveMembership, verifyMembership, proveConservation, verifyConservation, obfuscateField, verifyObfuscatedField, randScalar } from '@anchorchain/privacy';
export { KeyCustodian, verifyLifecycle, ThresholdParty, verifyThresholdSchnorr, aggregate as aggregateThresholdSig, aggregatedR, verifyCommitments } from '@anchorchain/custody';
export { IdentityService, authMessage, bindingHash } from '@anchorchain/identity';
export { CreditLedger, verifyLedger } from '@anchorchain/credit';
export { settle, equivalent } from '@anchorchain/settlement';
