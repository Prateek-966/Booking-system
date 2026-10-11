# Google sign-in setup

The guest and owner login pages support Google Identity Services using its popup
button and server-side ID token verification. Existing password sign-in remains
available. No client secret, service account, redirect endpoint, or paid Google
API is required by this integration.

## 1. Create the Google web client

A Google Cloud project administrator must do this in their own account:

1. Open https://console.cloud.google.com/auth/overview and select or create the
   project for Colonel's Paradise.
2. Complete Google Auth Platform's Branding and Audience settings. Use External
   audience if guests outside your organization should sign in. Enter the support
   email and app/domain information Google requests; use `colonelsparadisebir.com`
   as the authorized domain.
3. In Clients, create an OAuth client of type **Web application**.
4. Set these **Authorized JavaScript origins**, with no trailing path:
   - `https://www.colonelsparadisebir.com`
   - `https://colonelsparadisebir.com` if you serve the app at the bare domain too.
5. Leave **Authorized redirect URIs** empty for this popup/callback integration.
6. Copy the client ID ending in `.apps.googleusercontent.com`. It is public.
   Do not put a client secret into this application or send it in chat.
7. While the Google app is in Testing, add the owner and guest testers under
   Audience > Test users. Publish the Google app to Production when ready for
   public guest sign-in, completing any checks requested by Google.

For local development, use a separate web client with
`http://localhost:3000` as an authorized JavaScript origin and open the site at
that exact origin. Origins, ports, and client IDs must match.

## 2. Configure Render

On the existing web service, add this environment variable and save/redeploy:

```text
GOOGLE_CLIENT_ID=<your Web application client ID>
```

Keep `DATA_DIR=/data`, the attached persistent disk, `NODE_ENV=production`, and
`TRUST_PROXY=1`. No existing data needs to be reset. The two Google identity/login
attempt tables are created additively on startup.

Until `GOOGLE_CLIENT_ID` is configured, the Google button remains hidden and
password sign-in continues to work. Do not add placeholder client IDs to production.
A missing setting makes `/api/auth/google/config` return `enabled: false`.

The server must reach `www.googleapis.com` over HTTPS for Google's public signing
certificates. Browsers must reach `accounts.google.com` for the sign-in button and
popup. The application allows Google's specific GSI paths in its Content Security
Policy and allows popup communication on its two login pages.

## Account behavior

- A new Google guest with a verified email gets a guest account. It is Google-only;
  no local password is assigned. This app does not yet provide a password-setting
  or Google-account-unlinking flow for those new accounts.
- An existing password account must enter its current password once to link Google
  with the same email address. This prevents unsafe automatic linking of an
  unverified local account. Pre-link sessions are revoked at successful linking.
- The owner must already have an owner account, use a Google account with that
  account's email, and enter the existing owner password once. Google cannot
  create an owner, promote a guest, or cross the owner/guest portal boundary.
- Once linked, the immutable Google account ID identifies the account, rather
  than trusting later email changes. Each account supports one Google identity.
- Enabled local owner 2FA remains required on every Google login, including first
  linking. Authenticator and single-use recovery codes are supported.
- Browser-bound nonces expire after ten minutes and are consumed once. Refresh
  an idle sign-in page if it reports an expired attempt. Multiple login tabs may
  invalidate an earlier attempt; refresh the tab you intend to use.
- Account lockouts, secure HttpOnly sessions, CSRF checks, login auditing, and
  separate owner rate limits also apply to Google sign-in.

## Verify after deployment

1. Open the guest login page. Confirm the Google button appears and a test Google
   guest can sign in and open their bookings page.
2. Sign out. Open the owner login page and sign in with the existing owner's Google
   account. Supply the local password on first linking and the authenticator code
   if 2FA is enabled. Confirm the owner dashboard opens.
3. Confirm a guest Google account cannot sign in to the owner portal.
4. Confirm password login still works for existing password accounts.

`npm test` includes signed JWT verification tests with a local test key, including
invalid signatures, issuer/audience/expiry checks, nonce binding/replay, safe account
linking, portal isolation, lockout and owner 2FA. These offline tests do not replace
one real Google sign-in after the actual client and authorized origins are set.
