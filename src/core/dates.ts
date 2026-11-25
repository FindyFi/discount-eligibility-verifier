/** Lenient date handling for claim values from different issuers. */

export interface ParsedDate {
  /** Instant in epoch milliseconds (for date-only values: start of that day in the configured time zone). */
  start: number;
  /** For date-only values: the last millisecond of that day; otherwise equal to start. */
  end: number;
  dateOnly: boolean;
}

/**
 * Accepts ISO 8601 dates and date-times, Finnish/European `d.m.yyyy`, and epoch seconds or milliseconds.
 */
export function parseClaimDate(value: unknown, timeZone: string): ParsedDate | undefined {
  if (typeof value === 'number' && Number.isFinite(value)) {
    const ms = value > 1e11 ? value : value * 1000;
    return { start: ms, end: ms, dateOnly: false };
  }
  if (typeof value !== 'string') return undefined;
  const s = value.trim();

  let ymd: [number, number, number] | undefined;
  let m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(s);
  if (m) ymd = [+m[1]!, +m[2]!, +m[3]!];
  m = /^(\d{1,2})\.(\d{1,2})\.(\d{4})$/.exec(s);
  if (m) ymd = [+m[3]!, +m[2]!, +m[1]!];
  if (/^\d{9,13}$/.test(s)) return parseClaimDate(Number(s), timeZone);

  if (ymd) {
    const [y, mo, d] = ymd;
    if (mo < 1 || mo > 12 || d < 1 || d > 31) return undefined;
    const start = zonedTimeToUtc(y, mo, d, 0, 0, 0, timeZone);
    const next = zonedTimeToUtc(y, mo, d + 1, 0, 0, 0, timeZone);
    return { start, end: next - 1, dateOnly: true };
  }
  if (/^\d{4}-\d{2}-\d{2}T/.test(s)) {
    const ms = Date.parse(s);
    if (!Number.isNaN(ms)) return { start: ms, end: ms, dateOnly: false };
  }
  return undefined;
}

/** Converts a wall-clock time in an IANA time zone to epoch milliseconds. */
function zonedTimeToUtc(y: number, mo: number, d: number, h: number, mi: number, s: number, timeZone: string): number {
  const guess = Date.UTC(y, mo - 1, d, h, mi, s);
  const offset = tzOffsetMs(guess, timeZone);
  const first = guess - offset;
  // Second pass handles DST transitions between guess and result.
  return guess - tzOffsetMs(first, timeZone);
}

function tzOffsetMs(utcMs: number, timeZone: string): number {
  const parts = new Intl.DateTimeFormat('en-US', {
    timeZone,
    hourCycle: 'h23',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  }).formatToParts(new Date(utcMs));
  const get = (t: string) => Number(parts.find((p) => p.type === t)?.value);
  const asUtc = Date.UTC(get('year'), get('month') - 1, get('day'), get('hour'), get('minute'), get('second'));
  return asUtc - Math.floor(utcMs / 1000) * 1000;
}

/** Subtracts an ISO 8601 duration (years, months, weeks, days, hours, minutes, seconds) from an instant. */
export function subtractDuration(fromMs: number, duration: string): number {
  const m = /^P(?:(\d+)Y)?(?:(\d+)M)?(?:(\d+)W)?(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?$/.exec(duration.trim().toUpperCase());
  if (!m || duration.trim().toUpperCase() === 'P') throw new Error(`Invalid ISO 8601 duration "${duration}"`);
  const [, y, mo, w, d, h, mi, s] = m.map((x) => (x ? Number(x) : 0)) as number[];
  const dt = new Date(fromMs);
  dt.setUTCFullYear(dt.getUTCFullYear() - y!, dt.getUTCMonth() - mo!, dt.getUTCDate() - (w! * 7 + d!));
  return dt.getTime() - ((h! * 60 + mi!) * 60 + s!) * 1000;
}
