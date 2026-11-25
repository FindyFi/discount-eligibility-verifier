import qrcode from 'qrcode-generator';

/** Renders text as a crisp, scalable SVG QR code (a single path, quiet zone included). */
export function qrSvg(text: string, opts: { margin?: number; title?: string } = {}): string {
  // Low error correction keeps long OpenID4VP links at a scannable module size on screens.
  const qr = qrcode(0, text.length > 600 ? 'L' : 'M');
  qr.addData(text, 'Byte');
  qr.make();
  const n = qr.getModuleCount();
  const m = opts.margin ?? 4;
  let d = '';
  for (let r = 0; r < n; r++) {
    for (let c = 0; c < n; c++) {
      if (qr.isDark(r, c)) d += `M${c + m} ${r + m}h1v1h-1z`;
    }
  }
  const size = n + 2 * m;
  const title = opts.title ? `<title>${escapeXml(opts.title)}</title>` : '';
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" shape-rendering="crispEdges" role="img">${title}<rect width="100%" height="100%" fill="#fff"/><path d="${d}" fill="#000"/></svg>`;
}

function escapeXml(s: string): string {
  return s.replace(/[<>&"]/g, (ch) => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;' })[ch]!);
}
