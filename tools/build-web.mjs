// Bundles the web component into public/verifier.js (single ES module, no external requests).
import { build } from 'esbuild';
const common = {
  bundle: true,
  format: 'esm',
  target: ['es2022', 'safari16', 'chrome110', 'firefox115'],
  minify: process.argv.includes('--minify'),
  sourcemap: true,
  legalComments: 'eof',
  logLevel: 'info',
};
await build({ ...common, entryPoints: ['src/web/verifier-element.ts'], outfile: 'public/verifier.js' });
await build({ ...common, entryPoints: ['src/web/compat.ts'], outfile: 'public/compat.js' });
