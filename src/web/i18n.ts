export type Lang = 'fi' | 'sv' | 'en';

const STRINGS = {
  en: {
    start: 'Tap to start',
    loading: 'Preparing…',
    scan: 'Scan with your wallet app',
    accepted_types: 'Accepted credentials: {types}',
    open_wallet: 'Open wallet app',
    dc_api: 'Use a wallet on this device',
    waiting: 'Waiting for approval in the wallet…',
    verifying: 'Checking the credential…',
    accepted: 'Accepted',
    valid_until: 'valid until {date}',
    issued_by: 'Issued by {issuer}',
    rejected: 'Not accepted',
    rejected_hint: 'The credential could not be accepted.',
    error: 'Could not check right now',
    error_hint: 'Please try again in a moment.',
    wallet_error: 'Cancelled in the wallet',
    expired: 'The code has expired',
    awaiting_return: 'Finish in the browser window where you started.',
    try_again: 'Try again',
    details: 'Details',
    connection_error: 'Cannot reach the verification service.',
  },
  fi: {
    start: 'Aloita napauttamalla',
    loading: 'Valmistellaan…',
    scan: 'Skannaa lompakkosovelluksella',
    accepted_types: 'Hyväksytyt todisteet: {types}',
    open_wallet: 'Avaa lompakkosovellus',
    dc_api: 'Käytä tämän laitteen lompakkoa',
    waiting: 'Odotetaan hyväksyntää lompakossa…',
    verifying: 'Tarkistetaan todistetta…',
    accepted: 'Hyväksytty',
    valid_until: 'voimassa {date} asti',
    issued_by: 'Myöntäjä: {issuer}',
    rejected: 'Ei hyväksytty',
    rejected_hint: 'Todistetta ei voitu hyväksyä.',
    error: 'Tarkistus ei juuri nyt onnistu',
    error_hint: 'Yritä hetken kuluttua uudelleen.',
    wallet_error: 'Peruttu lompakossa',
    expired: 'Koodi on vanhentunut',
    awaiting_return: 'Viimeistele siinä selainikkunassa, josta aloitit.',
    try_again: 'Yritä uudelleen',
    details: 'Lisätietoja',
    connection_error: 'Tarkistuspalveluun ei saada yhteyttä.',
  },
  sv: {
    start: 'Tryck för att börja',
    loading: 'Förbereder…',
    scan: 'Skanna med plånboksappen',
    accepted_types: 'Godkända intyg: {types}',
    open_wallet: 'Öppna plånboksappen',
    dc_api: 'Använd en plånbok på den här enheten',
    waiting: 'Väntar på godkännande i plånboken…',
    verifying: 'Kontrollerar intyget…',
    accepted: 'Godkänt',
    valid_until: 'giltigt till {date}',
    issued_by: 'Utfärdare: {issuer}',
    rejected: 'Inte godkänt',
    rejected_hint: 'Intyget kunde inte godkännas.',
    error: 'Kontrollen kan inte göras just nu',
    error_hint: 'Försök igen om en stund.',
    wallet_error: 'Avbrutet i plånboken',
    expired: 'Koden har gått ut',
    awaiting_return: 'Slutför i det webbläsarfönster där du började.',
    try_again: 'Försök igen',
    details: 'Detaljer',
    connection_error: 'Verifieringstjänsten kan inte nås.',
  },
} as const;

export type MessageKey = keyof (typeof STRINGS)['en'];

export function pickLang(...candidates: (string | null | undefined)[]): Lang {
  for (const c of candidates) {
    const base = c?.toLowerCase().split(/[-_]/)[0];
    if (base === 'fi' || base === 'sv' || base === 'en') return base;
  }
  return 'en';
}

export function t(lang: Lang, key: MessageKey, vars: Record<string, string> = {}): string {
  return STRINGS[lang][key].replace(/\{(\w+)\}/g, (_, k: string) => vars[k] ?? '');
}

export function label(labels: Record<string, string> | undefined, lang: Lang, fallback: string): string {
  return labels?.[lang] ?? labels?.en ?? fallback;
}

export function formatDate(iso: string, lang: Lang, timeZone = 'Europe/Helsinki'): string {
  const locale = { fi: 'fi-FI', sv: 'sv-FI', en: 'en-GB' }[lang];
  return new Intl.DateTimeFormat(locale, { day: 'numeric', month: 'numeric', year: 'numeric', timeZone }).format(new Date(iso));
}
