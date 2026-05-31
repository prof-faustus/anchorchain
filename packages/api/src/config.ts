// Typed configuration. Every operational decision (network, batch policy, chunking,
// shard level, credit prices, custody threshold, identity expiry, rate limit) is a
// config value, not a code constant, so a deployment is reconfigured without a
// rebuild. The optional pkiRootPublicKeyHex names the root of the metering
// authority's identity PKI when one is in force.
import { readFileSync } from 'node:fs';

export interface AnchorChainConfig {
  network: 'mainnet' | 'testnet' | 'regtest';
  nodeEndpoint: string;
  timestampMode: 'logicalStep' | 'wallClock';
  batch: { closeOnCount: number; closeOnLogicalIntervalMs: number; maxBatchSize: number };
  anchor: { tier: 'ephemeral' | 'critical' };
  file: { chunkingRule: 'fixedSize'; chunkSizeBytes: number; maxFileBytes: number };
  shard: { predeterminedLevel: number };
  credit: { representation: 'quota' | 'onchain'; confidential: boolean; prices: Record<string, number> };
  settlement: { model: 'per-op' | 'periodic' };
  custody: { mode: 'reconstruction'; threshold: number; shares: number };
  identity: { nonceExpiryMs: number; pkiRootPublicKeyHex?: string };
  rateLimit: { perMinute: number };
  logLevel: 'silent' | 'info' | 'debug';
}

export function loadConfig(path: string): AnchorChainConfig {
  const raw = JSON.parse(readFileSync(path, 'utf8')) as AnchorChainConfig;
  validateConfig(raw);
  return raw;
}

export function validateConfig(c: AnchorChainConfig): void {
  if (c.custody.threshold < 1 || c.custody.threshold > c.custody.shares) throw new Error('custody threshold must be in [1, shares]');
  if (c.shard.predeterminedLevel < 1) throw new Error('shard predeterminedLevel must be >= 1');
  if (c.file.chunkSizeBytes <= 0 || c.file.maxFileBytes <= 0) throw new Error('file sizes must be positive');
  if (c.batch.closeOnCount <= 0 || c.batch.maxBatchSize <= 0) throw new Error('batch sizes must be positive');
}
