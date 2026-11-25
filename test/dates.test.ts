import { describe, expect, it } from 'vitest';
import { parseClaimDate, subtractDuration } from '../src/core/dates.js';

const TZ = 'Europe/Helsinki';

describe('parseClaimDate', () => {
  it('parses ISO dates as whole days in the configured time zone', () => {
    const d = parseClaimDate('2026-12-31', TZ)!;
    expect(new Date(d.start).toISOString()).toBe('2026-12-30T22:00:00.000Z'); // EET = UTC+2
    expect(new Date(d.end).toISOString()).toBe('2026-12-31T21:59:59.999Z');
  });

  it('handles summer time', () => {
    expect(new Date(parseClaimDate('2026-07-01', TZ)!.start).toISOString()).toBe('2026-06-30T21:00:00.000Z');
  });

  it('parses Finnish d.m.yyyy dates', () => {
    expect(parseClaimDate('25.11.2026', TZ)!.start).toBe(parseClaimDate('2026-11-25', TZ)!.start);
    expect(parseClaimDate('1.2.2026', TZ)!.start).toBe(parseClaimDate('2026-02-01', TZ)!.start);
  });

  it('parses epoch seconds, milliseconds and ISO date-times', () => {
    expect(parseClaimDate(1795600368, TZ)!.start).toBe(1795600368000);
    expect(parseClaimDate(1795600368000, TZ)!.start).toBe(1795600368000);
    expect(parseClaimDate('2026-11-25T10:00:00Z', TZ)!.start).toBe(Date.parse('2026-11-25T10:00:00Z'));
  });

  it('rejects unrecognisable values', () => {
    expect(parseClaimDate('soon', TZ)).toBeUndefined();
    expect(parseClaimDate('2026-13-01', TZ)).toBeUndefined();
    expect(parseClaimDate(true, TZ)).toBeUndefined();
  });
});

describe('subtractDuration', () => {
  const now = Date.parse('2026-11-25T12:00:00Z');
  it('supports months, years and days', () => {
    expect(new Date(subtractDuration(now, 'P3M')).toISOString()).toBe('2026-08-25T12:00:00.000Z');
    expect(new Date(subtractDuration(now, 'P3Y')).toISOString()).toBe('2023-11-25T12:00:00.000Z');
    expect(new Date(subtractDuration(now, 'P90D')).toISOString()).toBe('2026-08-27T12:00:00.000Z');
  });
  it('rejects invalid durations', () => {
    expect(() => subtractDuration(now, '3 months')).toThrow();
    expect(() => subtractDuration(now, 'P')).toThrow();
  });
});
