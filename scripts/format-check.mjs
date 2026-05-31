// Format check (no third-party formatter): LF line endings, final newline, no
// trailing whitespace, no tab indentation. Exits non-zero on any violation.
import { readdirSync, statSync, readFileSync } from 'node:fs';
import { join, resolve, relative, extname } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const SKIP_DIRS = new Set(['.git', 'node_modules', 'dist']);
const CHECK_EXT = new Set(['.ts', '.mjs', '.js', '.json', '.md', '.yml', '.yaml']);
const ALLOW_TRAILING_WS_EXT = new Set(['.md']);
const problems = [];

function walk(dir) {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    const st = statSync(full);
    if (st.isDirectory()) {
      if (!SKIP_DIRS.has(entry)) walk(full);
      continue;
    }
    if (entry.endsWith('.tsbuildinfo')) continue;
    if (!CHECK_EXT.has(extname(entry))) continue;
    check(full);
  }
}

function check(path) {
  const rel = relative(root, path);
  const text = readFileSync(path, 'utf8');
  if (text.includes('\r')) problems.push(`${rel}: contains CR (must be LF only)`);
  if (text.length > 0 && !text.endsWith('\n')) problems.push(`${rel}: missing final newline`);
  const allowTrailing = ALLOW_TRAILING_WS_EXT.has(extname(path));
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (!allowTrailing && /[ \t]+$/.test(lines[i])) problems.push(`${rel}:${i + 1}: trailing whitespace`);
    if (/^\t/.test(lines[i])) problems.push(`${rel}:${i + 1}: tab indentation (use spaces)`);
  }
}

walk(root);

if (problems.length > 0) {
  console.error('Format check failed:');
  for (const p of problems) console.error('  ' + p);
  process.exit(1);
}
console.log('Format check passed.');
