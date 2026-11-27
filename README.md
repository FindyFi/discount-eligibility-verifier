# Discount eligibility verifier

A lightweight verifier for SD-JWT VC credentials (pensioner and student status) presented from
EUDI-compatible wallets over OpenID4VP. Issuers must belong to a configured OpenID Federation.

## Run

```sh
npm ci
cp config/verifier.example.yaml config/verifier.yaml   # then edit
npm run build && npm start                             # or: npm run dev
```

With Docker:

```sh
docker build -t discount-eligibility-verifier .
docker run -p 8374:8374 \
  -e PUBLIC_URL=https://verifier.example.com \
  -e DEMO_SHOP_API_KEY=... -e RESULT_SIGNING_KEY="$(npm run -s keygen)" \
  -v $PWD/config/verifier.yaml:/app/config/verifier.yaml:ro \
  discount-eligibility-verifier
```

With [pm2](https://pm2.keymetrics.io/):

```sh
npm ci && npm run build
cp config/verifier.example.yaml config/verifier.yaml   # then edit
cp .env.example .env                                   # then fill in the secrets
pm2 start ecosystem.config.cjs                         # listens on port 8374
pm2 save && pm2 startup                                # keep it running across reboots
```

After an update, run `npm ci && npm run build && pm2 reload discount-verifier`.
[ecosystem.config.cjs](ecosystem.config.cjs) runs exactly one instance, because sessions are kept in memory: don't use cluster mode.
Secrets belong in `.env`, which is git-ignored, not in the ecosystem file.

Wallets must reach `PUBLIC_URL`, so put the service behind HTTPS in anything but local tests.
When using a reverse proxy, allow read timeouts of at least 35 seconds for the long-polling endpoints.
Sessions are kept in memory: run one instance, or use sticky sessions.

## Configuration

See [config/verifier.example.yaml](config/verifier.example.yaml). Credential types and eligibility rules
live in [config/credential-types.json](config/credential-types.json):

| Field | Meaning |
| --- | --- |
| `vct` | Accepted credential type identifiers |
| `require` | Claims that must be disclosed with one of the given values, e.g. `{ "Voimassa": true }` |
| `validUntilClaim` | Date claim after which the credential no longer qualifies (date-only values are inclusive) |
| `maxAge` | Optional, e.g. `{ "claim": "Muodostettu", "duration": "P3M" }` |
| `disclose` | Extra claims to request and return |

`exp` is enforced when a credential has one; credentials without `exp` are accepted indefinitely.

## Integration API

Authenticate with `Authorization: Bearer <apiKey>`.

### Create a session

```http
POST /api/sessions
{ "accepted_types": ["pension", "student"], "reference": "order-42", "return_url": "https://shop.example/checkout", "client_id_prefix": "openid_federation" }
```

All fields are optional. `return_url` must match one of the client's `allowedReturnUrls` prefixes.

```json
{
  "session_id": "…",
  "browser_token": "…",
  "wallet_url": "openid4vp://?…",
  "same_device_wallet_url": "openid4vp://?…",
  "accepted_types": ["pension", "student"],
  "expires_at": "2026-11-25T10:05:00.000Z"
}
```

Show `wallet_url` as a QR code (cross-device). Offer `same_device_wallet_url` as a button on mobile;
it is only present when `return_url` was given. Pass `session_id` and `browser_token` to the browser
that displays the session. Never expose the API key to browsers.

### Get the result

```http
GET /api/sessions/{id}?wait=25
```

`wait` long-polls up to 30 s until the session finishes. Alternatively configure a `webhookUrl`:
the service POSTs the signed result (`application/jwt`) when the session finishes.

```json
{
  "session_id": "…", "reference": "order-42", "status": "completed",
  "outcome": "accepted",
  "credential_type": "student",
  "credential_issuer": { "entityId": "https://…", "organizationName": "…", "trustAnchor": "https://findy.trustregistry.eu" },
  "claims": { "enrolment_status": "enrolled", "expiry_date": "2026-12-31" },
  "valid_until": "2026-12-31T21:59:59.999Z",
  "flow": "cross_device",
  "result_jwt": "eyJ…"
}
```

`outcome` is `accepted`, `rejected`, `error` (temporary failure, such as an unreachable federation:
let the user retry), `wallet_error`, `expired` or `pending`.

`result_jwt` is signed by the verifier (`typ: eligibility-result+jwt`, `aud`: your client id). Its keys are at
`/.well-known/jwks.json`. Verify it whenever the result reaches you through a browser.

For the same-device flow, rely on the result only when `same_device_confirmed` is `true`. That means the
browser that started the session received the response code, which defeats session fixation.

## OpenID Federation client identifier (`openid_federation`)

With `redirect_uri` (the default when `didWeb` is not configured), wallets cannot authenticate the verifier. With `openid_federation`, the verifier is itself a federation entity:
wallets resolve its trust chain, show its registered name, and check that the request is signed by a key from its metadata.

1. Generate two keys: `npm run keygen` for `FEDERATION_KEY` and again for `REQUEST_SIGNING_KEY`.
2. Uncomment the `federation` section in the configuration. `publicUrl` (the entity identifier) must be https.
3. Start the service. It logs whether the verifier is registered, and if not, the entity identifier and federation key to register.
4. Register the verifier at the trust anchor as a subordinate with that key.
5. Choose the prefix per session with `"client_id_prefix": "openid_federation"` in `POST /api/sessions`, or make it the default with `oid4vp.clientIdPrefix`.

The entity configuration is served at `/.well-known/openid-federation`.

- Federation requests are always signed and passed by reference (`request_uri`), so the QR code stays small.
- The request object carries the verifier's trust chain in its `trust_chain` JWS header, and `aud` is `https://self-issued.me/v2`.
- OpenID4VP 1.0 does not say which entity type holds verifier metadata, so the same metadata, including the request signing key in `jwks`, is published under each type in `metadataEntityTypes`. The default is `openid_credential_verifier` and `openid_relying_party`.
- Key binding must name the full client ID, `openid_federation:<entity id>`; the bare entity ID is also accepted.

## did:web client identifier (`decentralized_identifier`)

The recommended setup: the verifier has a `did:web` identity and signs its requests with a key from the DID document.
In wallet testing this was the only variant that Heidi, Hovi, Paradym and Toppan all accepted; several of them reject unsigned requests.

1. Generate a key with `npm run keygen` and set `DID_WEB_KEY`.
2. Uncomment the `didWeb` section in the configuration. `publicUrl` must be https and have no path; the DID is `did:web:<host>`.
3. The DID document is served at `/.well-known/did.json`. Requests are signed (`kid` is `<did>#key-1`) and passed by reference.
4. With `didWeb` configured, `decentralized_identifier` is the default prefix unless `oid4vp.clientIdPrefix` says otherwise. API clients can still pick another one per session with `client_id_prefix` in `POST /api/sessions`.

Key binding must name `decentralized_identifier:<did>`; the bare DID is also accepted.

## Trusting did:web issuers directly

Some issuers, such as Procivis, identify themselves with a `did:web` instead of a federation entity ID, so no trust chain can vouch for them.
List the ones you trust in `trustedDidIssuers`:

```yaml
trustedDidIssuers:
  - did: did:web:issuer.example:ssi:did-web:v1:7816b6a8
    name: Kela demo issuer
```

For a listed issuer the verifier skips the federation check, fetches its DID document over HTTPS and verifies the credential signature with the keys under `assertionMethod`.
An issuer that is not listed is still rejected. Treat the list as a trust anchor of its own: a listed issuer is accepted on the strength of your list and TLS for its domain, not of a registry.

## Wallet compatibility tester

`/compat.html` helps test which wallets work with which request variants:
`redirect_uri` with the request in the QR code and by reference, and `openid_federation` and `decentralized_identifier` when they are configured.
Enable it with `compat.enabled` and a `compat.token`, which the tester enters on the page.

1. Choose the wallet, its version and platform, and the credential the wallet holds.
2. Press **Run** for a variant and scan the QR code with the wallet.
3. Save the result when the wallet has responded. If the wallet gets stuck, record that with **Wallet refused**, **No response** or **Other**.

The server records the outcome and protocol diagnostics:

- whether the wallet fetched the request, and its User-Agent
- the `vp_token` shape
- the key binding `aud` and `typ`
- any wallet error

Claim values are never recorded.

The verdict separates protocol compatibility from the credential's own result. **works** means the presentation
passed the format and key binding checks, even if the credential was then rejected, for example by issuer trust.

Results are stored in `compat.resultsFile`; in Docker, mount a volume at `/app/data`.
They appear as a wallet × variant matrix and can be exported as Markdown or JSON.

## Web component and kiosk page

The service serves a dependency-free web component at `/verifier.js`, plus these pages:

- `/` (`index.html`): live demo of the component, with its events. It starts sessions from the kiosk endpoint, so it needs `kiosk.enabled`.
- `/integration.html`: how to embed the component and integrate a backend, for service providers.
- `/kiosk.html`: full-screen kiosk. Use `?lang=fi|sv|en`, and `?sound=off` to skip the "tap to start" step that unlocks audio.

The demo and integration pages share `public/site.css`, which follows the Findynet visual style. Its display font,
Archivo (SIL Open Font License), is copied into `public/fonts/` by `npm run build:web`.

The pages carry Open Graph and Twitter card tags for link previews. Their absolute URLs use a `%PUBLIC_URL%`
placeholder that the server replaces with `publicUrl` when it serves the HTML. The preview image
`public/og-image.png` is rendered from `tools/og-image.svg` (see the command at the top of that file).

```html
<script type="module" src="https://verifier.example.com/verifier.js"></script>
<credential-verifier session-id="…" session-token="…" lang="fi"></credential-verifier>
```

| Attribute | |
| --- | --- |
| `session-id`, `session-token` | A session created by your backend (`session_id`, `browser_token`) |
| `start-url` | Or: a URL the component POSTs to and that returns `{ session_id, browser_token }` |
| `mode` | `embedded` (default) or `kiosk`: full screen, loops, never offers same-device options |
| `lang` | `fi`, `sv` or `en` (default: page language) |
| `sound` | `on`/`off`: success and failure tones (default on in kiosk mode) |
| `page-feedback` | `on`/`off`: turn the whole page green or red (default on in kiosk mode) |
| `reset-after` | Seconds before starting over after a result (kiosk default from the configuration) |
| `server` | Verifier base URL (default: where `verifier.js` was loaded from) |

Outside kiosk mode, the component offers "Use a wallet on this device" when the browser supports the Digital
Credentials API, and "Open wallet app" when the session has a same-device link. After a same-device flow, it
picks the result up from the return URL by itself.

It emits `verification-status` and `verification-result` events (`event.detail` is the display state).
Treat them as UI signals: grant the discount from the result your backend receives.

You can theme it with CSS custom properties: `--cv-accepted`, `--cv-rejected`, `--cv-error`,
`--cv-surface`, `--cv-text`, `--cv-accent`, `--cv-font` and `--cv-radius`.

## Browser endpoints

These are used by the web component and the kiosk page. Pass the session token in the `x-session-token`
header or as `?token=`.

- `GET /public/sessions/{id}?wait=25&since=<status>` gives the display state, long-polled.
  Add `&response_code=…` from the return URL fragment after a same-device flow.
- `POST /public/sessions/{id}/dc-api/request` returns the request for
  `navigator.credentials.get({ digital: { requests: [request] } })`. The calling page's origin must be allowed.
- `POST /public/sessions/{id}/dc-api/response` takes the wallet's `DigitalCredential.data`.
- `POST /public/kiosk/sessions` creates a kiosk session, when `kiosk.enabled` is set.

## Development

```sh
npm test                 # unit and service tests (in-memory federation, issuer and wallet)
npm run redeem-offer -- '<openid-credential-offer://…>' <name>   # get a live test credential
npm run verify-live -- <name>                                     # verify it against the real trust anchor
npm run wallet -- '<openid4vp://…>' <name>                        # answer a running verifier's request
```

Live credentials and the test wallet's key are stored in `test/fixtures/live/`, which is git-ignored.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
