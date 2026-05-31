// Test runner: discovers every *.test.ts under packages/*/test and runs them via
// Node's built-in test runner (type-stripped). Library code is consumed from each
// package's compiled dist via its workspace name, so `build` runs first.
import { readdirSync, statSync, existsSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

const root = resolve(import.meta.dirname, '..');
const packagesDir = join(root, 'packages');

function findTests(dir) {
  const out = [];
  if (!existsSync(dir)) return out;
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) out.push(...findTests(full));
    else if (entry.endsWith('.test.ts')) out.push(full);
  }
  return out;
}

const files = [];
for (const pkg of readdirSync(packagesDir)) files.push(...findTests(join(packagesDir, pkg, 'test')));
files.sort();

if (files.length === 0) {
  console.error('No test files found.');
  process.exit(1);
}

const result = spawnSync(process.execPath, ['--test', ...files], { stdio: 'inherit', cwd: root });
process.exit(result.status ?? 1);
