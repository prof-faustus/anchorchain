#!/usr/bin/env node
// AnchorChain CLI. Three subcommands, all of which exit non-zero on failure so they
// gate CI:
//   selftest   - run the end-to-end self-test over every layer
//   reproduce  - regenerate the deterministic vectors/studies and verify them against
//                the committed vector (any divergence fails)
//   bench      - run live micro-benchmarks (--ci for a fast smoke point)
import { resolve } from 'node:path';
import { runSelftest, reproduceAndCheck } from '@anchorchain/api';
import { runBench, formatReport } from '@anchorchain/bench';

function repoRoot(): string {
  // dist/index.js -> packages/cli/dist -> repo root is three levels up
  return resolve(import.meta.dirname, '..', '..', '..');
}

async function cmdSelftest(): Promise<number> {
  const report = await runSelftest();
  for (const l of report.layers) console.log(`${l.ok ? 'PASS' : 'FAIL'}  ${l.layer.padEnd(22)} ${l.detail}`);
  console.log(report.ok ? '\nselftest: all layers passed' : '\nselftest: FAILURES present');
  return report.ok ? 0 : 1;
}

function cmdReproduce(): number {
  const result = reproduceAndCheck(repoRoot());
  if (!result.committedFound) {
    console.error('reproduce: committed vector not found at vectors/anchorchain/repro_v1.json');
    return 1;
  }
  if (!result.ok) {
    console.error('reproduce: MISMATCH against committed vector:');
    for (const m of result.mismatches) console.error('  ' + m);
    return 1;
  }
  console.log('reproduce: all deterministic vectors and studies match the committed vector');
  return 0;
}

function cmdBench(ci: boolean): number {
  console.log(formatReport(runBench({ ci })));
  return 0;
}

async function main(): Promise<number> {
  const [cmd, ...rest] = process.argv.slice(2);
  switch (cmd) {
    case 'selftest':
      return cmdSelftest();
    case 'reproduce':
      return cmdReproduce();
    case 'bench':
      return cmdBench(rest.includes('--ci'));
    default:
      console.error('usage: anchorchain <selftest|reproduce|bench [--ci]>');
      return 2;
  }
}

main().then(
  (code) => process.exit(code),
  (e) => {
    console.error(e instanceof Error ? e.stack : String(e));
    process.exit(1);
  },
);
