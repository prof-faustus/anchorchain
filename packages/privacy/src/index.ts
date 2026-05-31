// Public surface of @anchorchain/privacy.
//
// HONEST LABELLING. Every proof here is a Fiat-Shamir SIGMA-PROTOCOL zero-knowledge
// proof, sound under the discrete-log assumption in the random-oracle model. There
// is no trusted setup and no post-quantum security. These are NOT zk-STARKs and NOT
// Bulletproofs: the range and membership proofs are LINEAR in their statement
// (bit-width / set size), with no logarithmic aggregation and no inner-product
// argument. They are real, self-contained, and verifier-checked — not stubs — but
// they are exactly what they say they are and nothing more.
export type { Commitment } from './commit.js';
export { commit, addCommit, subCommit, commitEq, commitToHex, G, H } from './commit.js';

export type { SchnorrProof, OrProof } from './sigma.js';
export { proveDlog, verifyDlog, proveOneOfMany, verifyOneOfMany } from './sigma.js';

export type { RangeProof, RangeError } from './range.js';
export { proveRange, verifyRange } from './range.js';

export type { MembershipProof, MembershipError } from './membership.js';
export { proveMembership, verifyMembership } from './membership.js';

export { netCommitment, proveConservation, verifyConservation } from './conservation.js';

export type { MetadataMode, MetadataField, CleartextField, ObfuscatedField } from './metadata.js';
export { cleartextField, obfuscateField, verifyObfuscatedField } from './metadata.js';

export { randScalar, challenge, scalarBytes32 } from './transcript.js';
