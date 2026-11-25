// @vitest-environment happy-dom
import { readFile } from 'node:fs/promises';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { beforeAll, describe, expect, it, vi } from 'vitest';
import { createTestService, PUBLIC_URL } from './helpers/service.js';

const TOKEN = 'compat-tester-token-0123456789';

async function until<T>(fn: () => T | undefined | null | false, timeoutMs = 4000): Promise<T> {
  const end = Date.now() + timeoutMs;
  for (;;) {
    const v = fn();
    if (v) return v;
    if (Date.now() > end) throw new Error('timed out waiting for condition');
    await new Promise((r) => setTimeout(r, 10));
  }
}

let svc: Awaited<ReturnType<typeof createTestService>>;

beforeAll(async () => {
  const resultsFile = join(await mkdtemp(join(tmpdir(), 'compat-page-')), 'results.json');
  svc = await createTestService({ compat: { enabled: true, token: TOKEN, resultsFile } });
  (window as any).happyDOM?.setURL(`${PUBLIC_URL}/compat.html`);
  vi.stubGlobal('fetch', (input: RequestInfo | URL, init?: RequestInit) => svc.app.request(new URL(String(input), PUBLIC_URL).toString(), init));
  const html = await readFile(join(import.meta.dirname, '../public/compat.html'), 'utf8');
  document.body.innerHTML = /<body>([\s\S]*)<\/body>/.exec(html)![1]!;
  sessionStorage.setItem('compat-token', TOKEN);
  await import('../src/web/compat.js');
});

describe('compatibility page', () => {
  it('keeps the tester notes while the run updates, and saves them with the result', async () => {
    const run = await until(() => document.querySelector<HTMLButtonElement>('[data-variant="0"]'));
    run.click();
    const notes = await until(() => document.querySelector<HTMLTextAreaElement>('#notes'));
    notes.value = 'Heidi showed the verifier domain';
    notes.dispatchEvent(new Event('input'));

    // The wallet responds: the status changes and the run panel re-renders.
    const link = document.querySelector<HTMLAnchorElement>('#run a.qr')!.getAttribute('href')!;
    await svc.wallet(link);
    await until(() => document.querySelector('[data-save=""]'));
    expect(document.querySelector<HTMLTextAreaElement>('#notes')!.value).toBe('Heidi showed the verifier domain');

    document.querySelector<HTMLButtonElement>('[data-save=""]')!.click();
    await until(() => document.querySelector('#records')?.textContent?.includes('Heidi showed the verifier domain'));
  });
});
