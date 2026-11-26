// Bundles the browser code into public/verifier.js and public/compat.js (single ES modules, no external requests),
// and copies the self-hosted Archivo font used by the site pages (public/site.css) into public/fonts/.
//
// Third-party code inside the bundles must carry its license notice. Minification strips ordinary
// comments, so the notices are added as a /*! ... */ banner, and the build fails if a bundle contains
// a third-party package that has no notice registered in THIRD_PARTY below.
import { copyFile, mkdir, readFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { build } from 'esbuild';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

const MIT_PERMISSION = `Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.`;

/** Notices for third-party packages that may end up in the browser bundles. */
const THIRD_PARTY = {
  'qrcode-generator': async () => {
    const pkg = JSON.parse(await readFile(join(ROOT, 'node_modules/qrcode-generator/package.json'), 'utf8'));
    // The package ships no LICENSE file; the copyright line comes from its source header.
    const source = await readFile(join(ROOT, 'node_modules/qrcode-generator/dist/qrcode.mjs'), 'utf8');
    const copyright = /Copyright \(c\)[^\n]+/.exec(source)?.[0].trim();
    if (!copyright || pkg.license !== 'MIT') throw new Error('qrcode-generator: license or copyright line changed; review the notice');
    return `qrcode-generator ${pkg.version} (QR Code Generator for JavaScript)\n${copyright}\nhttps://github.com/kazuhikoarase/qrcode-generator\nLicensed under the MIT license:\n\n${MIT_PERMISSION}`;
  },
};

const ENTRIES = [
  ['src/web/verifier-element.ts', 'verifier.js'],
  ['src/web/compat.ts', 'compat.js'],
];

// Archivo (SIL Open Font License 1.1) stands in for Findynet's display face. Only the width-axis
// variable files for Latin and Latin Extended are needed; the licence travels with them.
const ARCHIVO = 'node_modules/@fontsource-variable/archivo';
const FONT_FILES = [
  [`${ARCHIVO}/files/archivo-latin-wdth-normal.woff2`, 'fonts/archivo/archivo-latin-wdth-normal.woff2'],
  [`${ARCHIVO}/files/archivo-latin-ext-wdth-normal.woff2`, 'fonts/archivo/archivo-latin-ext-wdth-normal.woff2'],
  [`${ARCHIVO}/LICENSE`, 'fonts/archivo/OFL.txt'],
];

async function copyFonts(outdir) {
  await mkdir(join(outdir, 'fonts/archivo'), { recursive: true });
  await Promise.all(FONT_FILES.map(([from, to]) => copyFile(join(ROOT, from), join(outdir, to))));
}

function packageOf(inputPath) {
  const m = /node_modules\/((?:@[^/]+\/)?[^/]+)/.exec(inputPath);
  return m?.[1];
}

/** Builds the bundles into outdir and returns the third-party packages included in each. */
export async function buildWeb({ outdir = join(ROOT, 'public'), minify = false, log = true } = {}) {
  const included = {};
  for (const [entry, outName] of ENTRIES) {
    // First pass: find which third-party packages the bundle contains.
    const probe = await build({ entryPoints: [join(ROOT, entry)], bundle: true, format: 'esm', write: false, metafile: true, logLevel: 'silent' });
    const packages = [...new Set(Object.keys(probe.metafile.inputs).map(packageOf).filter(Boolean))].sort();
    const missing = packages.filter((p) => !THIRD_PARTY[p]);
    if (missing.length) throw new Error(`${outName} bundles ${missing.join(', ')} without a registered license notice; add it to THIRD_PARTY in tools/build-web.mjs`);

    const notices = await Promise.all(packages.map((p) => THIRD_PARTY[p]()));
    const banner = notices.length
      ? `/*! ${outName} includes third-party software:\n *\n${notices
          .join('\n\n')
          .split('\n')
          .map((l) => (l ? ` * ${l}` : ' *'))
          .join('\n')}\n */`
      : undefined;

    await build({
      entryPoints: [join(ROOT, entry)],
      outfile: join(outdir, outName),
      bundle: true,
      format: 'esm',
      target: ['es2022', 'safari16', 'chrome110', 'firefox115'],
      minify,
      sourcemap: true,
      legalComments: 'eof',
      ...(banner ? { banner: { js: banner } } : {}),
      logLevel: log ? 'info' : 'silent',
    });

    // Guard: the notice must survive into the written file.
    const written = await readFile(join(outdir, outName), 'utf8');
    if (banner && !written.startsWith(banner)) throw new Error(`${outName}: license banner missing from output`);
    included[outName] = packages;
  }
  await copyFonts(outdir);
  return included;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  await buildWeb({ minify: process.argv.includes('--minify') });
}
