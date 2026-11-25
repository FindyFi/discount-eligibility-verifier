/**
 * Verification sessions. The in-memory store is enough for a single instance; the interface
 * leaves room for a shared store (e.g. Redis) when running several instances.
 */
import { randomBytes } from 'node:crypto';
import { EventEmitter } from 'node:events';
import type { VerificationResult } from '../core/index.js';
import type { ClientIdPrefix } from './config.js';
import type { WalletDiagnostics } from './compat.js';

export type SessionStatus = 'pending' | 'request_retrieved' | 'processing' | 'completed' | 'failed' | 'expired';
export type Flow = 'cross_device' | 'same_device' | 'dc_api';

export interface Session {
  id: string;
  /** Secret given to the browser that displays the session; required for public status calls. */
  browserToken: string;
  /** OID4VP `state`, used to correlate the wallet response. */
  state: string;
  nonce: string;
  apiClientId?: string;
  /** Free-form reference from the service provider, echoed in results. */
  reference?: string;
  acceptedTypes: string[];
  /** How the verifier identifies itself to the wallet in this session. */
  clientIdPrefix: ClientIdPrefix;
  createdAt: number;
  expiresAt: number;
  status: SessionStatus;
  flow?: Flow;
  returnUrl?: string;
  /** Same-device flow: code appended to the return URL; proves the result reached the browser that started the session. */
  responseCode?: string;
  responseCodeConfirmed?: boolean;
  dcApiOrigin?: string;
  result?: VerificationResult;
  resultJwt?: string;
  walletError?: { error: string; error_description?: string };
  /** Overrides oid4vp.requestMode for this session (compatibility testing). */
  requestMode?: 'value' | 'reference';
  diagnostics?: WalletDiagnostics;
}

export interface SessionStore {
  create(init: Omit<Session, 'id' | 'browserToken' | 'state' | 'nonce' | 'createdAt' | 'status'>): Promise<Session>;
  get(id: string): Promise<Session | undefined>;
  getByState(state: string): Promise<Session | undefined>;
  update(id: string, patch: Partial<Session>): Promise<Session | undefined>;
  /** Resolves when the session changes or the timeout passes. */
  waitForChange(id: string, timeoutMs: number): Promise<void>;
}

export const randomToken = (bytes = 24) => randomBytes(bytes).toString('base64url');

const TERMINAL: SessionStatus[] = ['completed', 'failed', 'expired'];
export const isTerminal = (s: SessionStatus) => TERMINAL.includes(s);

export class MemorySessionStore implements SessionStore {
  private readonly sessions = new Map<string, Session>();
  private readonly byState = new Map<string, string>();
  private readonly events = new EventEmitter();
  private readonly sweeper: NodeJS.Timeout;

  constructor(private readonly retainSeconds = 600) {
    this.events.setMaxListeners(0);
    this.sweeper = setInterval(() => this.sweep(), 30_000);
    this.sweeper.unref();
  }

  async create(init: Parameters<SessionStore['create']>[0]): Promise<Session> {
    const s: Session = { ...init, id: randomToken(16), browserToken: randomToken(), state: randomToken(), nonce: randomToken(), createdAt: Date.now(), status: 'pending' };
    this.sessions.set(s.id, s);
    this.byState.set(s.state, s.id);
    return s;
  }

  async get(id: string) {
    return this.expireIfDue(this.sessions.get(id));
  }

  async getByState(state: string) {
    const id = this.byState.get(state);
    return id ? this.get(id) : undefined;
  }

  async update(id: string, patch: Partial<Session>) {
    const s = this.sessions.get(id);
    if (!s) return undefined;
    Object.assign(s, patch);
    this.events.emit(id);
    return s;
  }

  waitForChange(id: string, timeoutMs: number): Promise<void> {
    return new Promise((resolve) => {
      const done = () => {
        clearTimeout(timer);
        this.events.off(id, done);
        resolve();
      };
      const timer = setTimeout(done, timeoutMs);
      this.events.once(id, done);
    });
  }

  close() {
    clearInterval(this.sweeper);
  }

  private expireIfDue(s: Session | undefined): Session | undefined {
    if (s && !isTerminal(s.status) && s.status !== 'processing' && Date.now() > s.expiresAt) {
      s.status = 'expired';
      this.events.emit(s.id);
    }
    return s;
  }

  private sweep() {
    const cutoff = Date.now() - this.retainSeconds * 1000;
    for (const [id, s] of this.sessions) {
      this.expireIfDue(s);
      if (s.expiresAt < cutoff) {
        this.sessions.delete(id);
        this.byState.delete(s.state);
      }
    }
  }
}
