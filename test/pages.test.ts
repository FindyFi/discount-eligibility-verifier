import { readFile } from 'node:fs/promises';
import { serveStatic } from '@hono/node-server/serve-static';
import { Hono } from 'hono';
import { describe, expect, it } from 'vitest';
import { fillPublicUrl } from '../src/server/pages.js';

const publicUrl = 'https://verifier.example.com';
const app = new Hono().use('/*', fillPublicUrl(publicUrl), serveStatic({ root: 'public' }));

describe('site pages', () => {
  for (const [path, url] of [['/', `${publicUrl}/`], ['/integration.html', `${publicUrl}/integration.html`], ['/kiosk.html', `${publicUrl}/kiosk.html`]] as const) {
    it(`${path} has link preview metadata with absolute URLs`, async () => {
      const res = await app.request(path);
      expect(res.status).toBe(200);
      const html = await res.text();
      expect(html).not.toContain('%PUBLIC_URL%');
      expect(html).toContain(`<meta property="og:url" content="${url}">`);
      expect(html).toContain(`<meta property="og:image" content="${publicUrl}/og-image.png">`);
      expect(html).toMatch(/<meta property="og:title" content="[^"]+">/);
      expect(html).toMatch(/<meta property="og:description" content="[^"]+">/);
      expect(html).toContain('<meta name="twitter:card" content="summary_large_image">');
    });
  }

  it('serves the preview image unchanged', async () => {
    const res = await app.request('/og-image.png');
    expect(res.headers.get('content-type')).toBe('image/png');
    expect(Buffer.from(await res.arrayBuffer()).equals(await readFile('public/og-image.png'))).toBe(true);
  });
});
