// Public surface of @anchorchain/api: typed config, the end-to-end self-test, the
// deterministic studies, and the reproduction/verification of committed vectors.
export type { AnchorChainConfig } from './config.js';
export { loadConfig, validateConfig } from './config.js';

export type { SelftestReport, LayerResult } from './selftest.js';
export { runSelftest } from './selftest.js';

export type { Studies, RangeSizeRow, DisclosureRow, EquivalenceRow } from './studies.js';
export { runStudies } from './studies.js';

export type { ReproVectors, ReproResult } from './reproduce.js';
export { computeVectors, reproduceAndCheck, vectorPath } from './reproduce.js';
