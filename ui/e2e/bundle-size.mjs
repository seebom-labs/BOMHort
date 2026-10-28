// Bundle-size gate: fails when the production build grows past the checked-in
// baseline by more than the tolerance. Update the baseline deliberately
// (`node e2e/bundle-size.mjs --update`) when a size change is intended.
import { readdirSync, statSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const dir = join(import.meta.dirname, '..', 'dist', 'ui', 'browser');
const baselineFile = join(import.meta.dirname, 'bundle-size.baseline.json');
const tolerance = 0.1;

const js = readdirSync(dir).filter((f) => f.endsWith('.js'));
// Initial = every script index.html loads eagerly (main, polyfills, shared chunks).
const initial = [
  ...readFileSync(join(dir, 'index.html'), 'utf8').matchAll(/<script[^>]+src="([^"]+\.js)"/g),
].map((m) => m[1]);
const actual = {
  initialBytes: initial.reduce((n, f) => n + statSync(join(dir, f)).size, 0),
  totalBytes: js.reduce((n, f) => n + statSync(join(dir, f)).size, 0),
  chunks: js.length,
};

if (process.argv.includes('--update')) {
  writeFileSync(baselineFile, JSON.stringify(actual, null, 2) + '\n');
  console.log('baseline updated', actual);
  process.exit(0);
}

const baseline = JSON.parse(readFileSync(baselineFile, 'utf8'));
const failures = ['initialBytes', 'totalBytes']
  .filter((k) => actual[k] > baseline[k] * (1 + tolerance))
  .map((k) => `${k}: ${actual[k]} > ${baseline[k]} +${tolerance * 100}%`);

console.log('bundle', actual, 'baseline', baseline);
if (failures.length) {
  console.error('bundle size regression:\n  ' + failures.join('\n  '));
  process.exit(1);
}
