import { mkdtemp, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
// @ts-expect-error -- plain ESM build script without type declarations
import { buildWeb } from '../tools/build-web.mjs';

describe('browser bundles', () => {
  it('carry the MIT notice of the bundled QR code library, also when minified', async () => {
    const outdir = await mkdtemp(join(tmpdir(), 'web-build-'));
    const included = (await buildWeb({ outdir, minify: true, log: false })) as Record<string, string[]>;
    expect(included).toEqual({ 'verifier.js': ['qrcode-generator'], 'compat.js': ['qrcode-generator'] });

    for (const file of ['verifier.js', 'compat.js']) {
      const js = await readFile(join(outdir, file), 'utf8');
      expect(js.startsWith('/*!')).toBe(true);
      expect(js).toContain('Copyright (c) 2009 Kazuhiko Arase');
      expect(js).toContain('Permission is hereby granted, free of charge');
      expect(js).toContain('The above copyright notice and this permission notice shall be included');
    }
  }, 30000);
});
