/**
 * Shadow DOM styles. Host pages can theme the component with these custom properties:
 *   --cv-accepted, --cv-rejected, --cv-error, --cv-surface, --cv-text, --cv-accent, --cv-font, --cv-radius
 */
export const STYLES = `
:host {
  --_accepted: var(--cv-accepted, #1a7f37);
  --_rejected: var(--cv-rejected, #c62828);
  --_error: var(--cv-error, #b45309);
  --_surface: var(--cv-surface, #ffffff);
  --_text: var(--cv-text, #1b1f24);
  --_muted: color-mix(in srgb, var(--_text) 65%, transparent);
  --_accent: var(--cv-accent, #003680);
  --_radius: var(--cv-radius, 16px);
  display: block;
  font-family: var(--cv-font, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif);
  color: var(--_text);
  container-type: inline-size;
}
:host([data-mode="kiosk"]) { height: 100%; }

.card {
  box-sizing: border-box;
  height: 100%;
  min-height: 320px;
  padding: clamp(16px, 4cqi, 48px);
  border-radius: var(--_radius);
  background: var(--_surface);
  display: flex;
  align-items: center;
  justify-content: center;
  text-align: center;
  transition: background-color 200ms ease-out, color 200ms ease-out;
}
:host([data-mode="kiosk"]) .card { border-radius: 0; }
.card[data-state="accepted"] { background: var(--_accepted); color: #fff; }
.card[data-state="rejected"] { background: var(--_rejected); color: #fff; }
.card[data-state="error"], .card[data-state="wallet_error"], .card[data-state="expired"] { background: var(--_error); color: #fff; }
.card:not([data-state="neutral"]) { --_muted: rgba(255,255,255,.85); }

.live { display: flex; flex-direction: column; align-items: center; gap: 12px; width: 100%; max-width: 560px; }
h2 { margin: 0; font-size: clamp(1.15rem, 4.5cqi, 2rem); line-height: 1.2; }
p { margin: 0; }
.hint, .status, .issuer { color: var(--_muted); }
.status { font-size: 1.05rem; }
.big-text { font-size: clamp(1.1rem, 4cqi, 1.6rem); }
.notice { color: var(--_rejected); font-size: .9rem; }

.qr { display: block; width: min(100%, 360px); aspect-ratio: 1; line-height: 0; border-radius: 8px; overflow: hidden; }
.qr svg { width: 100%; height: 100%; }
:host([data-mode="kiosk"]) .qr { width: min(70vmin, 640px); }

.buttons { display: flex; flex-wrap: wrap; gap: 8px; justify-content: center; }
button, .button {
  font: inherit; font-size: 1rem; font-weight: 600;
  padding: 12px 20px; min-height: 48px;
  border-radius: 999px; border: 2px solid currentColor;
  background: transparent; color: inherit; cursor: pointer; text-decoration: none;
  display: inline-flex; align-items: center; justify-content: center;
}
.primary { background: var(--_accent); border-color: var(--_accent); color: #fff; }
.card:not([data-state="neutral"]) button, .card:not([data-state="neutral"]) .button { border-color: #fff; color: #fff; }
button:disabled { opacity: .6; cursor: progress; }
button:focus-visible, .button:focus-visible, .qr:focus-visible { outline: 3px solid var(--_accent); outline-offset: 3px; }
.big { font-size: clamp(1.2rem, 5cqi, 2rem); padding: 24px 48px; }

.icon {
  width: clamp(72px, 22cqi, 200px); aspect-ratio: 1;
  border-radius: 50%; border: clamp(4px, 1cqi, 10px) solid currentColor;
  display: grid; place-items: center;
  font-size: clamp(40px, 13cqi, 120px); font-weight: 700; line-height: 1;
  animation: pop 260ms cubic-bezier(.2,1.4,.5,1);
}
.result-title { font-size: clamp(1.6rem, 9cqi, 4.5rem); }
.result-type { font-size: clamp(1.1rem, 4.5cqi, 2.2rem); font-weight: 600; }
.valid-until { font-size: clamp(1rem, 3.2cqi, 1.6rem); }
details { color: var(--_muted); font-size: .9rem; max-width: 100%; }
summary { cursor: pointer; }
.reason { margin-top: 6px; overflow-wrap: anywhere; text-align: left; }

.spinner {
  width: 48px; height: 48px; border-radius: 50%;
  border: 5px solid color-mix(in srgb, var(--_accent) 20%, transparent);
  border-top-color: var(--_accent);
  animation: spin 900ms linear infinite;
}
@keyframes spin { to { transform: rotate(360deg); } }
@keyframes pop { from { transform: scale(.6); } to { transform: scale(1); } }
@media (prefers-reduced-motion: reduce) {
  .icon, .spinner, .card { animation: none; transition: none; }
}
`;
