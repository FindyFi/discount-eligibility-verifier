import type { MiddlewareHandler } from 'hono';

/** Placeholder in the static HTML pages for the public base URL (link previews need absolute og:url and og:image). */
export const PUBLIC_URL_PLACEHOLDER = '%PUBLIC_URL%';

/** Fills %PUBLIC_URL% in HTML responses with the configured public URL. Other responses pass through untouched. */
export function fillPublicUrl(publicUrl: string): MiddlewareHandler {
  return async (c, next) => {
    await next();
    if (!c.res.ok || !c.res.headers.get('content-type')?.startsWith('text/html')) return;
    const html = await c.res.text();
    const headers = new Headers(c.res.headers);
    headers.delete('content-length');
    c.res = new Response(html.replaceAll(PUBLIC_URL_PLACEHOLDER, publicUrl), { status: c.res.status, headers });
  };
}
