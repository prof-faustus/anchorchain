// Forbidden-token scan. BSV is the entire universe: nothing may name or imply any
// chain, protocol, asset, or ecosystem other than BSV; the ticker for the other
// fork appears nowhere; the on-chain unit is "minor units", never another unit
// name; and nothing names a build agent, assistant, or tooling provider.
//
// Patterns are assembled from fragments at runtime so this scanner file contains
// no literal forbidden token and needs no self-exemption. The token "bitcoin"
// alone is PERMITTED (BSV is Bitcoin); only the fork ticker and other-ecosystem
// names are forbidden.
import { readdirSync, statSync, readFileSync, existsSync } from 'node:fs';
import { join, resolve, relative } from 'node:path';
import { spawnSync } from 'node:child_process';

const root = resolve(import.meta.dirname, '..');
const f = (s) => s;
const word = (frag) => new RegExp('\\b' + frag + '\\b', 'i');
const phrase = (frag) => new RegExp(frag.replace(/ /g, '\\s+'), 'i');

const PATTERNS = [
  ['fork-ticker', word(f('b') + f('tc'))],
  ['fork-client', phrase(f('bitcoin ') + f('core'))],
  ['witness-segregation', word(f('seg') + f('wit'))],
  ['fork-script-upgrade', word(f('tap') + f('root'))],
  ['off-chain-network', word(f('light') + f('ning'))],
  ['ecosystem-vendor', word(f('block') + f('stream'))],
  ['altchain-a', word(f('ether') + f('eum'))],
  ['altchain-b', word(f('lite') + f('coin'))],
  ['altchain-c', word(f('doge') + f('coin'))],
  ['altchain-d', word(f('sol') + f('ana'))],
  ['altchain-e', word(f('mon') + f('ero'))],
  ['altchain-f', word(f('rip') + f('ple'))],
  ['unit-name', word(f('sato') + f('shi'))],
  ['tool-identity-a', word(f('cla') + f('ude'))],
  ['tool-identity-b', word(f('cop') + f('ilot'))],
  ['tool-identity-c', word(f('chat') + f('gpt'))],
  ['tool-identity-d', word(f('open') + f('ai'))],
  ['tool-identity-e', word(f('anthro') + f('pic'))],
];

const SKIP_DIRS = new Set(['.git', 'node_modules', 'dist']);
const findings = [];

function isProbablyText(buf) {
  const n = Math.min(buf.length, 8000);
  for (let i = 0; i < n; i++) if (buf[i] === 0) return false;
  return true;
}

function scan(rel, text) {
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    for (const [label, re] of PATTERNS) if (re.test(lines[i])) findings.push(`${rel}:${i + 1}: forbidden token (${label})`);
  }
}

function walk(dir) {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    const st = statSync(full);
    const rel = relative(root, full).split('\\').join('/');
    if (st.isDirectory()) {
      if (!SKIP_DIRS.has(entry)) walk(full);
      continue;
    }
    if (entry.endsWith('.tsbuildinfo')) continue;
    for (const [label, re] of PATTERNS) if (re.test(rel)) findings.push(`path ${rel}: forbidden token in filename (${label})`);
    const buf = readFileSync(full);
    if (!isProbablyText(buf)) continue;
    scan(rel, buf.toString('utf8'));
  }
}

walk(root);

if (existsSync(join(root, '.git'))) {
  const log = spawnSync('git', ['log', '--format=%H%n%B%n----'], { cwd: root, encoding: 'utf8' });
  if (log.status === 0 && typeof log.stdout === 'string') {
    const lines = log.stdout.split('\n');
    for (let i = 0; i < lines.length; i++) {
      for (const [label, re] of PATTERNS) if (re.test(lines[i])) findings.push(`commit-message: forbidden token (${label}) near "${lines[i].slice(0, 60)}"`);
    }
  }
}

if (findings.length > 0) {
  console.error('Forbidden-token scan FAILED:');
  for (const x of findings) console.error('  ' + x);
  process.exit(1);
}
console.log('Forbidden-token scan passed: BSV only; no fork ticker, altcoin/ecosystem, foreign unit name, or tool identity.');
