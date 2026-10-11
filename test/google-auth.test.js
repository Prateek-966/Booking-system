'use strict';

const { test, before, after, mock } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const bcrypt = require('bcryptjs');
const { OAuth2Client } = require('google-auth-library');

process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'booking-google-test-'));
process.env.NODE_ENV = 'production';
process.env.GOOGLE_CLIENT_ID = 'test-client.apps.googleusercontent.com';
process.env.SEED_DEMO = '0';
process.env.AUTH_RATE_LIMIT = '1000';
process.env.OWNER_RATE_LIMIT = '1000';
const app = require('../src/app');
const db = require('../src/db');
const totp = require('../src/totp');
const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const cert = publicKey.export({ type: 'spki', format: 'pem' });
let server, base;
let serial = 0;
const password = 'Existing-test-password-123';

before(async () => {
  // Keep the real Google JWT verifier: replace only remote certificate fetching.
  mock.method(OAuth2Client.prototype, 'getFederatedSignonCertsAsync', async () => ({ certs: { test: cert } }));
  await new Promise(resolve => { server = app.listen(0, '127.0.0.1', resolve); });
  base = `http://127.0.0.1:${server.address().port}`;
});
after(async () => {
  mock.restoreAll();
  await new Promise(resolve => server.close(resolve));
  db.close();
  fs.rmSync(process.env.DATA_DIR, { recursive: true, force: true });
});
function person() { const id = ++serial; return { sub: `google-${id}`, email: `google-${id}@example.com`, name: 'Google Guest' }; }
function existing(identity, role = 'guest') {
  return Number(db.prepare('INSERT INTO users(email,name,password_hash,role) VALUES (?,?,?,?)')
    .run(identity.email, identity.name, bcrypt.hashSync(password, 4), role).lastInsertRowid);
}
function jwt(nonce, identity, overrides = {}) {
  const now = Math.floor(Date.now() / 1000);
  const header = Buffer.from(JSON.stringify({ alg: 'RS256', kid: 'test' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({ iss: 'https://accounts.google.com', aud: process.env.GOOGLE_CLIENT_ID,
    iat: now, exp: now + 3600, nonce, email_verified: true, ...identity, ...overrides })).toString('base64url');
  const unsigned = `${header}.${payload}`;
  return `${unsigned}.${crypto.sign('RSA-SHA256', Buffer.from(unsigned), privateKey).toString('base64url')}`;
}
async function post(endpoint, body, cookie) {
  const response = await fetch(base + '/api/auth/google' + endpoint, {
    method: 'POST', headers: { 'Content-Type': 'application/json', ...(cookie ? { Cookie: cookie } : {}) },
    body: JSON.stringify(body),
  });
  return { status: response.status, body: await response.json(), headers: response.headers };
}
async function start(portal = 'guest') {
  const result = await post('/start', { portal });
  assert.equal(result.status, 200);
  const cookie = result.headers.getSetCookie()[0];
  assert.match(cookie, /HttpOnly/); assert.match(cookie, /Secure/); assert.match(cookie, /SameSite=Strict/);
  return { nonce: result.body.nonce, cookie: cookie.split(';')[0] };
}
function login(attempt, identity, fields = {}, claims = {}) {
  return post('', { credential: jwt(attempt.nonce, identity, claims), ...fields }, attempt.cookie);
}

test('Google stays unavailable without configuration; existing password sign-in remains available', async () => {
  const id = process.env.GOOGLE_CLIENT_ID;
  delete process.env.GOOGLE_CLIENT_ID;
  try {
    const config = await fetch(base + '/api/auth/google/config');
    assert.deepEqual(await config.json(), { enabled: false, clientId: '' });
    assert.equal((await post('/start', { portal: 'guest' })).status, 503);
    assert.equal((await fetch(base + '/login.html')).status, 200);
  } finally { process.env.GOOGLE_CLIENT_ID = id; }
});

test('verified Google guest creates one account and receives a secure session; nonce cannot replay', async () => {
  const identity = person();
  const attempt = await start();
  const result = await login(attempt, identity, { portal: 'owner', role: 'owner' });
  assert.equal(result.status, 200);
  assert.equal(result.body.user.role, 'guest');
  assert.match(result.headers.getSetCookie().join(';'), /__Host-session=.*Secure/);
  assert.equal(result.headers.get('cache-control'), 'no-store');
  assert.equal(db.prepare('SELECT user_id FROM google_identities WHERE subject = ?').get(identity.sub).user_id, result.body.user.id);
  assert.equal((await login(attempt, identity)).status, 401);
  const next = await login(await start(), identity);
  assert.equal(next.status, 200);
  assert.equal(next.body.user.id, result.body.user.id);
});

test('bad signature, audience, issuer, expiry, nonce, subject and unverified email are rejected', async () => {
  const identity = person();
  const attempt = await start();
  const now = Math.floor(Date.now() / 1000);
  for (const claims of [
    { aud: 'different-client' }, { iss: 'https://attacker.example' },
    { iat: now - 7200, exp: now - 3600 }, { nonce: 'different-nonce' },
    { email_verified: false }, { email_verified: 'true' }, { sub: '' }, { email: 'not-an-email' },
  ]) assert.equal((await login(attempt, identity, {}, claims)).status, 401, JSON.stringify(claims));
  const signed = jwt(attempt.nonce, identity);
  const parts = signed.split('.'); parts[1] = Buffer.from(JSON.stringify({ email: identity.email })).toString('base64url');
  assert.equal((await post('', { credential: parts.join('.') }, attempt.cookie)).status, 401);
  assert.equal(db.prepare('SELECT id FROM users WHERE email = ?').get(identity.email), undefined);
});

test('login requires its initiating browser cookie and an unexpired attempt', async () => {
  const identity = person();
  const attempt = await start();
  assert.equal((await post('', { credential: jwt(attempt.nonce, identity) })).status, 401);
  const other = await start();
  assert.equal((await post('', { credential: jwt(attempt.nonce, identity) }, other.cookie)).status, 401);
  db.prepare('UPDATE google_login_attempts SET expires_at = 0').run();
  assert.equal((await login(attempt, identity)).status, 401);
});

test('existing guests require their password once to link and old sessions are revoked', async () => {
  const identity = person();
  const id = existing(identity);
  db.prepare('INSERT INTO sessions(token_hash,user_id,expires_at) VALUES (?,?,?)').run('old-session', id, Date.now() + 100000);
  const attempt = await start();
  const challenge = await login(attempt, identity);
  assert.equal(challenge.status, 401); assert.equal(challenge.body.linkRequired, true);
  assert.equal((await login(attempt, identity, { password: 'wrong' })).status, 401);
  assert.equal(db.prepare('SELECT * FROM google_identities WHERE user_id = ?').get(id), undefined);
  const linked = await login(attempt, identity, { password });
  assert.equal(linked.status, 200); assert.equal(linked.body.user.id, id);
  assert.equal(db.prepare("SELECT * FROM sessions WHERE token_hash = 'old-session'").get(), undefined);
  assert.equal((await login(await start(), identity)).status, 200);
});

test('Google never creates an owner or promotes a guest, and portal cannot be overridden on completion', async () => {
  const unknown = person();
  assert.equal((await login(await start('owner'), unknown, { portal: 'guest' })).status, 403);
  assert.equal(db.prepare('SELECT * FROM users WHERE email = ?').get(unknown.email), undefined);
  const guest = person(); existing(guest);
  assert.equal((await login(await start('owner'), guest, { password })).status, 403);
  const owner = person(); existing(owner, 'owner');
  assert.equal((await login(await start(), owner, { password, portal: 'owner' })).status, 403);
});

test('owner linking and every later Google sign-in retain local two-factor protection', async () => {
  const identity = person();
  const id = existing(identity, 'owner');
  const secret = totp.generateSecret();
  db.prepare('UPDATE users SET totp_enabled = 1, totp_secret = ? WHERE id = ?').run(secret, id);
  const attempt = await start('owner');
  assert.equal((await login(attempt, identity)).body.linkRequired, true);
  const challenge = await login(attempt, identity, { password });
  assert.equal(challenge.status, 401); assert.equal(challenge.body.totpRequired, true);
  assert.equal(db.prepare('SELECT * FROM google_identities WHERE user_id = ?').get(id), undefined);
  const code = totp.codeForStep(secret, totp.currentStep());
  assert.equal((await login(attempt, identity, { password, totpCode: code })).status, 200);
  const next = await start('owner');
  assert.equal((await login(next, identity)).body.totpRequired, true);
  assert.equal((await login(next, identity, { totpCode: code })).status, 401);
  const recoveryCode = 'ABCD-EFGH-IJKL';
  db.prepare('INSERT INTO recovery_codes(user_id,code_hash) VALUES (?,?)').run(id, bcrypt.hashSync(recoveryCode, 4));
  assert.equal((await login(next, identity, { recoveryCode })).status, 200);
  assert.equal((await login(await start('owner'), identity, { recoveryCode })).status, 401);
});

test('linked identities use subject, cannot be rebound by email, and respect account lockout', async () => {
  const identity = person();
  const first = await login(await start(), identity);
  assert.equal(first.status, 200);
  assert.equal((await login(await start(), { ...identity, sub: 'different-subject' }, { password })).status, 403);
  const renamed = await login(await start(), { ...identity, email: 'renamed@example.com' });
  assert.equal(renamed.status, 200); assert.equal(renamed.body.user.id, first.body.user.id);
  db.prepare('UPDATE users SET locked_until = ? WHERE id = ?').run(Date.now() + 60000, first.body.user.id);
  assert.equal((await login(await start(), identity)).status, 429);
});

test('concurrent Google callbacks consume a nonce only once', async () => {
  const identity = person();
  const attempt = await start();
  const results = await Promise.all([login(attempt, identity), login(attempt, identity)]);
  assert.deepEqual(results.map(x => x.status).sort(), [200, 401]);
  const user = db.prepare('SELECT id FROM users WHERE email = ?').get(identity.email);
  assert.equal(db.prepare('SELECT count(*) AS n FROM sessions WHERE user_id = ?').get(user.id).n, 1);
});

test('login pages allow Google popup communication without allowing arbitrary script origins', async () => {
  const response = await fetch(base + '/owner-login.html');
  assert.equal(response.headers.get('cross-origin-opener-policy'), 'same-origin-allow-popups');
  const csp = response.headers.get('content-security-policy');
  assert.match(csp, /accounts\.google\.com\/gsi\/client/);
  assert.ok(!csp.includes("'unsafe-inline'"));
  assert.match(await response.text(), /google-button/);
});
