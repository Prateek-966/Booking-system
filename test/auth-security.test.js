'use strict';

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const bcrypt = require('bcryptjs');

process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'booking-auth-security-'));
process.env.NODE_ENV = 'production';
process.env.SEED_DEMO = '0';
process.env.AUTH_RATE_LIMIT = '500';
process.env.OWNER_RATE_LIMIT = '500';

const app = require('../src/app');
const db = require('../src/db');
const totp = require('../src/totp');
const auth = require('../src/auth');

let server;
let baseUrl;
let nextAccount = 0;
const password = 'security-Test-password-123';

before(async () => {
  await new Promise((resolve) => { server = app.listen(0, '127.0.0.1', resolve); });
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  await new Promise((resolve) => server.close(resolve));
  db.close();
  fs.rmSync(process.env.DATA_DIR, { recursive: true, force: true });
});

function account() {
  const email = `security-${++nextAccount}@example.com`;
  const result = db.prepare(
    "INSERT INTO users (email, name, password_hash, role) VALUES (?, 'Owner', ?, 'owner')"
  ).run(email, bcrypt.hashSync(password, 4));
  return { id: Number(result.lastInsertRowid), email, role: 'owner' };
}

function cookieFor(user) {
  let cookie;
  auth.createSession({ headers: {}, ip: '127.0.0.1' }, {
    cookie(name, value) { cookie = `${name}=${value}`; },
  }, user);
  return cookie;
}

async function post(endpoint, body, headers = {}) {
  const response = await fetch(`${baseUrl}/api/auth${endpoint}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...headers },
    body: JSON.stringify(body),
  });
  return { status: response.status, headers: response.headers, body: await response.json() };
}

function login(user, fields = {}) {
  return post('/login', { email: user.email, password, portal: 'owner', ...fields });
}

// Pause after real password comparisons to deterministically exercise requests
// that read account state before another request changes it.
function pauseComparisons(t, count) {
  const original = bcrypt.compare;
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  let ready;
  const started = new Promise((resolve) => { ready = resolve; });
  let completed = 0;
  t.mock.method(bcrypt, 'compare', async (...args) => {
    const result = await original(...args);
    if (++completed === count) ready();
    await gate;
    return result;
  });
  t.after(release);
  return { started, release };
}

test('2FA setup cannot disable or replace an existing second factor', async () => {
  const user = account();
  const secret = totp.generateSecret();
  db.prepare('UPDATE users SET totp_enabled = 1, totp_secret = ?, totp_last_step = 123 WHERE id = ?')
    .run(secret, user.id);
  const result = await post('/2fa/setup', {}, { Cookie: cookieFor(user) });
  assert.equal(result.status, 409);
  assert.deepEqual(db.prepare('SELECT totp_enabled, totp_secret, totp_last_step FROM users WHERE id = ?').get(user.id), {
    totp_enabled: 1, totp_secret: secret, totp_last_step: 123,
  });
  const noCode = await login(user);
  assert.equal(noCode.status, 401);
  assert.equal(noCode.body.totpRequired, true);
});

test('simultaneous sign-ins cannot reuse one TOTP code', { timeout: 10000 }, async (t) => {
  const user = account();
  const secret = totp.generateSecret();
  db.prepare('UPDATE users SET totp_enabled = 1, totp_secret = ? WHERE id = ?').run(secret, user.id);
  const totpCode = totp.codeForStep(secret, totp.currentStep());
  const barrier = pauseComparisons(t, 2);
  const requests = [login(user, { totpCode }), login(user, { totpCode })];
  await barrier.started;
  barrier.release();
  const results = await Promise.all(requests);
  assert.deepEqual(results.map((r) => r.status).sort(), [200, 401]);
  assert.equal(db.prepare('SELECT count(*) AS n FROM sessions WHERE user_id = ?').get(user.id).n, 1);
});

test('parallel failed logins still trigger account lockout', { timeout: 10000 }, async (t) => {
  const user = account();
  const barrier = pauseComparisons(t, 6);
  const requests = Array.from({ length: 6 }, () => login(user, { password: 'incorrect' }));
  await barrier.started;
  barrier.release();
  const results = await Promise.all(requests);
  assert.equal(results.filter((r) => r.status === 401).length, 5);
  assert.equal(results.filter((r) => r.status === 429).length, 1);
  const row = db.prepare('SELECT failed_attempts, locked_until FROM users WHERE id = ?').get(user.id);
  assert.equal(row.failed_attempts, 5);
  assert.ok(row.locked_until > Date.now());
});

test('a login already in progress cannot bypass password rotation', { timeout: 10000 }, async (t) => {
  const user = account();
  const barrier = pauseComparisons(t, 1);
  const request = login(user);
  await barrier.started;
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(bcrypt.hashSync('new-Password-123', 4), user.id);
  barrier.release();
  assert.equal((await request).status, 401);
  assert.equal(db.prepare('SELECT count(*) AS n FROM sessions WHERE user_id = ?').get(user.id).n, 0);
});

test('a login already in progress honors newly enabled 2FA', { timeout: 10000 }, async (t) => {
  const user = account();
  const barrier = pauseComparisons(t, 1);
  const request = login(user);
  await barrier.started;
  db.prepare('UPDATE users SET totp_enabled = 1, totp_secret = ? WHERE id = ?').run(totp.generateSecret(), user.id);
  barrier.release();
  const result = await request;
  assert.equal(result.status, 401);
  assert.equal(result.body.totpRequired, true);
});

test('turning 2FA off revokes other sessions', async () => {
  const user = account();
  db.prepare('UPDATE users SET totp_enabled = 1, totp_secret = ? WHERE id = ?').run(totp.generateSecret(), user.id);
  const current = cookieFor(user);
  const other = cookieFor(user);
  assert.equal((await post('/2fa/disable', { password }, { Cookie: current })).status, 200);
  assert.equal((await post('/sessions/revoke-others', {}, { Cookie: other })).status, 401);
  assert.equal((await post('/sessions/revoke-others', {}, { Cookie: current })).status, 200);
});

test('production logout clears the Secure __Host cookie correctly', async () => {
  const user = account();
  const cookie = cookieFor(user);
  const result = await post('/logout', {}, { Cookie: cookie });
  assert.equal(result.status, 200);
  const cleared = result.headers.getSetCookie().find((value) => value.startsWith('__Host-session='));
  assert.ok(cleared);
  assert.match(cleared, /; Secure(?:;|$)/);
  assert.match(cleared, /; Path=\/(?:;|$)/);
  assert.match(cleared, /Expires=Thu, 01 Jan 1970/);
  assert.equal((await post('/sessions/revoke-others', {}, { Cookie: cookie })).status, 401);
});

test('CSRF checks reject a different scheme and explicit cross-site requests', async () => {
  const user = account();
  const Cookie = cookieFor(user);
  assert.equal((await post('/sessions/revoke-others', {}, { Cookie, Origin: baseUrl })).status, 200);
  assert.equal((await post('/sessions/revoke-others', {}, {
    Cookie, Origin: baseUrl.replace('http:', 'https:'),
  })).status, 403);
  assert.equal((await post('/sessions/revoke-others', {}, { Cookie, 'Sec-Fetch-Site': 'cross-site' })).status, 403);
});
