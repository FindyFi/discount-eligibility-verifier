/**
 * Wallet compatibility testing: records how each wallet handles each request variant.
 * Results are kept in a JSON file so they survive restarts and can be committed or shared.
 */
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import { randomToken, type Session } from './sessions.js';
import type { ClientIdPrefix } from './config.js';

export interface Variant {
  clientIdPrefix: ClientIdPrefix;
  requestMode: 'value' | 'reference';
}

/** Protocol diagnostics captured from wallet traffic (never claim values). */
export interface WalletDiagnostics {
  requestFetchedAt?: string;
  requestUserAgent?: string;
  responseAt?: string;
  responseUserAgent?: string;
  responseContentType?: string;
  vpTokenShape?: string;
  presentationCount?: number;
  kbJwtAud?: string;
  kbJwtTyp?: string;
  hasKeyBinding?: boolean;
}

/**
 * - works: the presentation passed all protocol checks (format, key binding), whatever the credential's own outcome
 * - failed: the wallet responded but the protocol was wrong, or it reported an error
 * - no_response / other manual verdicts: set by the tester (e.g. the wallet could not open the QR code)
 */
export type Verdict = 'works' | 'failed' | 'no_response' | 'wallet_refused' | 'other';

export interface CompatRecord {
  id: string;
  at: string;
  wallet: string;
  walletVersion?: string;
  platform?: string;
  credentialType: string;
  variant: Variant;
  sessionId: string;
  status: string;
  outcome?: string;
  verdict: Verdict;
  /** The credential's own result, separate from protocol compatibility. */
  credentialAccepted?: boolean;
  failedCheck?: string;
  reasons?: string[];
  walletError?: { error: string; error_description?: string };
  diagnostics?: WalletDiagnostics;
  notes?: string;
}

const PROTOCOL_CHECKS = ['format', 'key_binding'];

export function deriveVerdict(s: Session): { verdict: Verdict; failedCheck?: string } {
  if (s.walletError) return { verdict: 'failed' };
  const r = s.result;
  if (!r) return { verdict: 'no_response' };
  const failed = r.checks.find((c) => c.ok === false);
  if (r.outcome === 'accepted') return { verdict: 'works' };
  if (!failed) return { verdict: 'failed', failedCheck: undefined };
  if (PROTOCOL_CHECKS.includes(failed.id) || r.reasons.some((x) => /no presentation/i.test(x))) return { verdict: 'failed', failedCheck: failed.id };
  // The wallet spoke the protocol correctly; the credential itself was rejected (e.g. issuer trust, eligibility).
  return { verdict: 'works', failedCheck: failed.id };
}

export class CompatStore {
  private records: CompatRecord[] = [];
  private loaded = false;
  private writing: Promise<void> = Promise.resolve();

  constructor(private readonly file: string) {}

  async all(): Promise<CompatRecord[]> {
    await this.load();
    return [...this.records];
  }

  async add(rec: Omit<CompatRecord, 'id' | 'at'>): Promise<CompatRecord> {
    await this.load();
    const full: CompatRecord = { id: randomToken(9), at: new Date().toISOString(), ...rec };
    this.records.push(full);
    await this.persist();
    return full;
  }

  async remove(id: string): Promise<boolean> {
    await this.load();
    const before = this.records.length;
    this.records = this.records.filter((r) => r.id !== id);
    if (this.records.length === before) return false;
    await this.persist();
    return true;
  }

  private async load() {
    if (this.loaded) return;
    try {
      const parsed = JSON.parse(await readFile(this.file, 'utf8'));
      this.records = Array.isArray(parsed) ? parsed : [];
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== 'ENOENT') throw new Error(`Cannot read compatibility results ${this.file}: ${(e as Error).message}`);
    }
    this.loaded = true;
  }

  /** Serialised, atomic writes (write to a temp file, then rename). */
  private persist(): Promise<void> {
    this.writing = this.writing.then(async () => {
      await mkdir(dirname(this.file), { recursive: true });
      const tmp = `${this.file}.${process.pid}.tmp`;
      await writeFile(tmp, JSON.stringify(this.records, null, 2) + '\n');
      await rename(tmp, this.file);
    });
    return this.writing;
  }
}

/** Describes the vp_token structure without revealing content, e.g. "object{pension:array[1]}". */
export function describeVpToken(v: unknown): string {
  if (typeof v === 'string') {
    const t = v.trim();
    if (t.startsWith('{') || t.startsWith('[')) {
      try {
        return `json-string(${describeVpToken(JSON.parse(t))})`;
      } catch {
        /* fall through */
      }
    }
    return t ? 'string' : 'empty';
  }
  if (Array.isArray(v)) return `array[${v.length}]`;
  if (v && typeof v === 'object') {
    return `object{${Object.entries(v)
      .map(([k, x]) => `${k}:${Array.isArray(x) ? `array[${x.length}]` : typeof x}`)
      .join(',')}}`;
  }
  return typeof v;
}

/** Reads the KB-JWT header/payload fields useful for diagnosing audience problems (unverified, diagnostics only). */
export function keyBindingDiagnostics(presentation: string | undefined): Pick<WalletDiagnostics, 'kbJwtAud' | 'kbJwtTyp' | 'hasKeyBinding'> {
  if (!presentation) return {};
  const last = presentation.trim().split('~').pop() ?? '';
  const parts = last.split('.');
  if (parts.length !== 3) return { hasKeyBinding: false };
  try {
    const header = JSON.parse(Buffer.from(parts[0]!, 'base64url').toString());
    const payload = JSON.parse(Buffer.from(parts[1]!, 'base64url').toString());
    return { hasKeyBinding: true, kbJwtTyp: String(header.typ ?? ''), kbJwtAud: typeof payload.aud === 'string' ? payload.aud : JSON.stringify(payload.aud) };
  } catch {
    return { hasKeyBinding: false };
  }
}
