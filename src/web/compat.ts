/**
 * Wallet compatibility tester (compat.html). Runs each request variant against a wallet, records the
 * outcome and protocol diagnostics on the server, and shows a wallet × variant matrix.
 */
import { qrSvg } from './qr.js';

interface Variant {
  clientIdPrefix: 'redirect_uri' | 'openid_federation' | 'decentralized_identifier' | 'legacy_redirect_uri';
  requestMode: 'value' | 'reference';
}
interface Info {
  wallets: string[];
  credentialTypes: { id: string; label?: Record<string, string> }[];
  variants: Variant[];
}
interface CompatRecord {
  id: string;
  at: string;
  wallet: string;
  walletVersion?: string;
  platform?: string;
  credentialType: string;
  variant: Variant;
  status: string;
  outcome?: string;
  verdict: string;
  credentialAccepted?: boolean;
  failedCheck?: string;
  reasons?: string[];
  walletError?: { error: string; error_description?: string };
  diagnostics?: Record<string, unknown>;
  notes?: string;
}
interface Run {
  variant: Variant;
  sessionId: string;
  token: string;
  walletUrl: string;
  status: string;
  outcome?: string;
  reason?: string;
  abort: AbortController;
  /** Kept outside the DOM so re-rendering never loses what the tester typed. */
  notes: string;
}

const TOKEN_KEY = 'compat-token';
const $ = <T extends Element = HTMLElement>(sel: string) => document.querySelector<T>(sel)!;
const esc = (s: unknown) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);
const variantKey = (v: Variant) => `${v.clientIdPrefix}/${v.requestMode}`;
const variantLabel = (v: Variant) => {
  const how = v.requestMode === 'value' ? 'in QR' : 'by reference';
  if (v.clientIdPrefix === 'openid_federation') return 'openid_federation (signed, by reference)';
  if (v.clientIdPrefix === 'decentralized_identifier') return 'decentralized_identifier (did:web, signed, by reference)';
  if (v.clientIdPrefix === 'legacy_redirect_uri') return `legacy redirect_uri (client_id_scheme, pre-1.0) · ${how}`;
  return `redirect_uri · ${how}`;
};
const TERMINAL = new Set(['completed', 'failed', 'expired']);

let token = '';
let info: Info | undefined;
let run: Run | undefined;
let records: CompatRecord[] = [];

async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const res = await fetch(path, { ...init, headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json', ...(init.headers ?? {}) } });
  if (res.status === 401) throw new Error('unauthorized');
  if (!res.ok) throw new Error(`${res.status} ${await res.text()}`);
  return res.status === 204 ? (undefined as T) : res.json();
}

// ---------- sign-in ----------

async function signIn(t: string) {
  token = t;
  try {
    info = await api<Info>('/api/compat/info');
  } catch (e) {
    $('#signin-error').textContent = (e as Error).message === 'unauthorized' ? 'Wrong token.' : `Cannot load: ${(e as Error).message}`;
    $('#signin').hidden = false;
    $('#app').hidden = true;
    return;
  }
  try {
    sessionStorage.setItem(TOKEN_KEY, t);
  } catch {
    /* storage blocked */
  }
  $('#signin').hidden = true;
  $('#app').hidden = false;
  renderSetup();
  await loadRecords();
}

// ---------- setup and runs ----------

function renderSetup() {
  const wallets = info!.wallets;
  $('#wallet').innerHTML = wallets.map((w) => `<option>${esc(w)}</option>`).join('') + '<option value="__other">Other…</option>';
  $('#credential').innerHTML = info!.credentialTypes.map((c) => `<option value="${esc(c.id)}">${esc(c.label?.en ?? c.id)}</option>`).join('');
  $('#variants').innerHTML = info!.variants
    .map((v, i) => `<li><button type="button" data-variant="${i}">Run</button> <span>${esc(variantLabel(v))}</span></li>`)
    .join('');
  for (const p of ['openid_federation', 'decentralized_identifier'] as const) {
    if (!info!.variants.some((v) => v.clientIdPrefix === p)) {
      $('#variants').insertAdjacentHTML('beforeend', `<li class="muted">${p} is not configured on this verifier</li>`);
    }
  }
}

function currentWallet(): string {
  const sel = $<HTMLSelectElement>('#wallet').value;
  return sel === '__other' ? $<HTMLInputElement>('#wallet-other').value.trim() : sel;
}

async function startRun(variant: Variant) {
  run?.abort.abort();
  const s = await api<Record<string, string>>('/api/compat/sessions', {
    method: 'POST',
    body: JSON.stringify({ variant, credential_type: $<HTMLSelectElement>('#credential').value }),
  });
  run = { variant, sessionId: s.session_id!, token: s.browser_token!, walletUrl: s.wallet_url!, status: 'pending', abort: new AbortController(), notes: '' };
  renderRun();
  void poll(run);
}

async function poll(r: Run) {
  while (!r.abort.signal.aborted && !TERMINAL.has(r.status)) {
    try {
      const res = await fetch(`/public/sessions/${encodeURIComponent(r.sessionId)}?wait=25&since=${r.status}`, { headers: { 'x-session-token': r.token }, signal: r.abort.signal });
      const v = await res.json();
      // Long-polls also return unchanged after their timeout: re-render only on real changes.
      const changed = v.status !== r.status || v.outcome !== r.outcome || v.reason !== r.reason;
      r.status = v.status;
      r.outcome = v.outcome;
      r.reason = v.reason;
      if (changed && run === r) renderRun();
    } catch {
      if (r.abort.signal.aborted) return;
      await new Promise((ok) => setTimeout(ok, 2000));
    }
  }
}

const STATUS_TEXT: Record<string, string> = {
  pending: 'Waiting for the wallet to scan…',
  request_retrieved: 'The wallet fetched the request. Waiting for the response…',
  processing: 'Verifying the response…',
  completed: 'The wallet responded.',
  failed: 'The wallet reported an error.',
  expired: 'The session expired without a response.',
};

function renderRun() {
  const r = run;
  const el = $('#run');
  if (!r) {
    el.hidden = true;
    return;
  }
  el.hidden = false;
  const done = TERMINAL.has(r.status);
  const active = document.activeElement as HTMLTextAreaElement | null;
  const hadFocus = active?.id === 'notes';
  const caret = hadFocus ? [active!.selectionStart, active!.selectionEnd] : undefined;
  el.innerHTML = `
    <h3>${esc(variantLabel(r.variant))}</h3>
    <div class="run-grid">
      <div>
        <a class="qr" href="${esc(r.walletUrl)}">${qrSvg(r.walletUrl)}</a>
        <p class="muted small">Link length ${r.walletUrl.length} characters · <button type="button" class="link" data-copy>Copy link</button></p>
      </div>
      <div>
        <p class="status-line" data-status="${esc(r.status)}">${esc(STATUS_TEXT[r.status] ?? r.status)}</p>
        ${r.outcome ? `<p>Credential outcome: <strong>${esc(r.outcome)}</strong>${r.reason ? `<br><span class="muted small">${esc(r.reason)}</span>` : ''}</p>` : ''}
        <label>Notes<textarea id="notes" rows="3" placeholder="What did the wallet show? Did it display the verifier name?">${esc(r.notes)}</textarea></label>
        <div class="buttons">
          ${done ? '<button type="button" class="primary" data-save="">Save result</button>' : ''}
          <button type="button" data-save="wallet_refused">Wallet refused the request</button>
          <button type="button" data-save="no_response">No response</button>
          <button type="button" data-save="other">Other problem</button>
        </div>
        <p class="muted small">${done ? 'The verdict is derived from the server-side checks; the buttons above override it.' : 'If the wallet gets stuck, record what happened with one of the buttons.'}</p>
      </div>
    </div>`;
  const notes = el.querySelector<HTMLTextAreaElement>('#notes')!;
  notes.addEventListener('input', () => {
    r.notes = notes.value;
  });
  if (hadFocus) {
    notes.focus();
    notes.setSelectionRange(caret![0] ?? notes.value.length, caret![1] ?? notes.value.length);
  }
}

async function saveRun(verdict: string) {
  const r = run;
  if (!r) return;
  const wallet = currentWallet();
  if (!wallet) {
    alert('Choose a wallet first.');
    return;
  }
  r.abort.abort();
  await api('/api/compat/results', {
    method: 'POST',
    body: JSON.stringify({
      session_id: r.sessionId,
      wallet,
      wallet_version: $<HTMLInputElement>('#wallet-version').value.trim() || undefined,
      platform: $<HTMLSelectElement>('#platform').value || undefined,
      notes: r.notes.trim() || undefined,
      verdict: verdict || undefined,
    }),
  });
  run = undefined;
  renderRun();
  await loadRecords();
}

// ---------- results ----------

async function loadRecords() {
  records = await api<CompatRecord[]>('/api/compat/results');
  renderResults();
}

const VERDICT_ICON: Record<string, string> = { works: '✅', failed: '❌', wallet_refused: '⛔', no_response: '⌛', other: '❓' };

function latestByCell(): Map<string, CompatRecord[]> {
  const m = new Map<string, CompatRecord[]>();
  for (const r of [...records].sort((a, b) => b.at.localeCompare(a.at))) {
    const key = `${r.wallet}|${variantKey(r.variant)}`;
    const list = m.get(key) ?? [];
    // Latest record per credential type in each cell
    if (!list.some((x) => x.credentialType === r.credentialType)) list.push(r);
    m.set(key, list);
  }
  return m;
}

function cellText(list: CompatRecord[] | undefined, html: boolean): string {
  if (!list?.length) return html ? '<span class="muted">not tested</span>' : '—';
  return list
    .map((r) => {
      const detail = r.verdict === 'failed' ? (r.failedCheck ?? r.walletError?.error ?? '') : '';
      const s = `${VERDICT_ICON[r.verdict] ?? ''} ${r.verdict}${detail ? ` (${detail})` : ''} · ${r.credentialType}`;
      return html ? `<span class="v-${esc(r.verdict)}">${esc(s)}</span>` : s;
    })
    .join(html ? '<br>' : '; ');
}

function renderResults() {
  const variants = info!.variants;
  const wallets = [...new Set([...info!.wallets, ...records.map((r) => r.wallet)])];
  const cells = latestByCell();
  $('#matrix').innerHTML = `
    <table>
      <thead><tr><th>Wallet</th>${variants.map((v) => `<th>${esc(variantLabel(v))}</th>`).join('')}</tr></thead>
      <tbody>${wallets
        .map((w) => `<tr><th scope="row">${esc(w)}</th>${variants.map((v) => `<td>${cellText(cells.get(`${w}|${variantKey(v)}`), true)}</td>`).join('')}</tr>`)
        .join('')}</tbody>
    </table>`;
  $('#records').innerHTML = records.length
    ? `<table class="records">
        <thead><tr><th>Time</th><th>Wallet</th><th>Variant</th><th>Credential</th><th>Verdict</th><th>Diagnostics</th><th></th></tr></thead>
        <tbody>${[...records]
          .reverse()
          .map(
            (r) => `<tr>
              <td>${esc(new Date(r.at).toLocaleString())}</td>
              <td>${esc(r.wallet)}${r.walletVersion ? ` ${esc(r.walletVersion)}` : ''}${r.platform ? `<br><span class="muted small">${esc(r.platform)}</span>` : ''}</td>
              <td>${esc(variantLabel(r.variant))}</td>
              <td>${esc(r.credentialType)}${r.outcome ? `<br><span class="muted small">${esc(r.outcome)}${r.failedCheck ? `: ${esc(r.failedCheck)}` : ''}</span>` : ''}</td>
              <td class="v-${esc(r.verdict)}">${VERDICT_ICON[r.verdict] ?? ''} ${esc(r.verdict)}${r.notes ? `<br><span class="small">${esc(r.notes)}</span>` : ''}</td>
              <td class="small">${diagnosticsHtml(r)}</td>
              <td><button type="button" class="link" data-delete="${esc(r.id)}">Delete</button></td>
            </tr>`,
          )
          .join('')}</tbody></table>`
    : '<p class="muted">No results yet.</p>';
}

function diagnosticsHtml(r: CompatRecord): string {
  const d = r.diagnostics ?? {};
  const rows: [string, unknown][] = [
    ['request fetched', d.requestFetchedAt ? 'yes' : r.variant.requestMode === 'reference' ? 'no' : 'n/a'],
    ['vp_token', d.vpTokenShape],
    ['KB aud', d.kbJwtAud],
    ['KB typ', d.kbJwtTyp],
    ['wallet error', r.walletError ? `${r.walletError.error}${r.walletError.error_description ? `: ${r.walletError.error_description}` : ''}` : undefined],
    ['reason', r.reasons?.[0]],
    ['user agent', d.responseUserAgent ?? d.requestUserAgent],
  ];
  return rows
    .filter(([, v]) => v !== undefined && v !== '')
    .map(([k, v]) => `<div><span class="muted">${esc(k)}:</span> ${esc(v)}</div>`)
    .join('');
}

function markdown(): string {
  const variants = info!.variants;
  const wallets = [...new Set([...info!.wallets, ...records.map((r) => r.wallet)])];
  const cells = latestByCell();
  const pipe = (s: string) => s.replace(/\|/g, '\\|');
  const lines = [
    `# Wallet compatibility (${new Date().toISOString().slice(0, 10)})`,
    '',
    'Verdict "works" means the wallet completed the protocol (format and key binding checks passed); the credential itself may still have been rejected, e.g. by issuer trust.',
    '',
    `| Wallet | ${variants.map((v) => pipe(variantLabel(v))).join(' | ')} |`,
    `| --- | ${variants.map(() => '---').join(' | ')} |`,
    ...wallets.map((w) => `| ${pipe(w)} | ${variants.map((v) => pipe(cellText(cells.get(`${w}|${variantKey(v)}`), false))).join(' | ')} |`),
    '',
    '## Details',
    '',
    ...[...records].map(
      (r) =>
        `- ${r.at.slice(0, 16).replace('T', ' ')} · **${r.wallet}${r.walletVersion ? ` ${r.walletVersion}` : ''}**${r.platform ? ` (${r.platform})` : ''} · ${variantLabel(r.variant)} · ${r.credentialType}: ${r.verdict}` +
        `${r.failedCheck ? ` (failed check: ${r.failedCheck})` : ''}${r.diagnostics?.kbJwtAud ? ` · KB aud \`${String(r.diagnostics.kbJwtAud)}\`` : ''}` +
        `${r.walletError ? ` · wallet error \`${r.walletError.error}\`` : ''}${r.notes ? ` · ${r.notes}` : ''}`,
    ),
  ];
  return lines.join('\n') + '\n';
}

function download(name: string, text: string, type: string) {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([text], { type }));
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

// ---------- wiring ----------

document.addEventListener('click', async (e) => {
  const t = e.target as HTMLElement;
  const variantBtn = t.closest<HTMLElement>('[data-variant]');
  try {
    if (variantBtn) await startRun(info!.variants[Number(variantBtn.dataset.variant)]!);
    else if (t.closest('[data-save]')) await saveRun(t.closest<HTMLElement>('[data-save]')!.dataset.save!);
    else if (t.closest('[data-copy]') && run) await navigator.clipboard.writeText(run.walletUrl);
    else if (t.closest('[data-delete]')) {
      if (confirm('Delete this result?')) {
        await api(`/api/compat/results/${encodeURIComponent(t.closest<HTMLElement>('[data-delete]')!.dataset.delete!)}`, { method: 'DELETE' });
        await loadRecords();
      }
    } else if (t.id === 'export-md') download('wallet-compatibility.md', markdown(), 'text/markdown');
    else if (t.id === 'export-json') download('wallet-compatibility.json', JSON.stringify(records, null, 2), 'application/json');
    else if (t.id === 'refresh') await loadRecords();
  } catch (err) {
    alert((err as Error).message);
  }
});

$('#wallet').addEventListener('change', () => {
  $('#wallet-other').hidden = $<HTMLSelectElement>('#wallet').value !== '__other';
});

$('#signin-form').addEventListener('submit', (e) => {
  e.preventDefault();
  void signIn($<HTMLInputElement>('#token').value.trim());
});

let saved: string | null = null;
try {
  saved = sessionStorage.getItem(TOKEN_KEY);
} catch {
  /* storage blocked */
}
if (saved) void signIn(saved);
