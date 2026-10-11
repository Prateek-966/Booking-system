'use strict';

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');

process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'booking-cache-'));
process.env.NODE_ENV = 'test';
process.env.SEED_DEMO = '0';
const app = require('../src/app');
const db = require('../src/db');
let server, base;
const token = crypto.randomBytes(32).toString('base64url');
const hash = crypto.createHash('sha256').update(token).digest('hex');
const previousSeen = Date.now() - 60000;

before(async () => {
  const user = db.prepare("INSERT INTO users(email,name,password_hash) VALUES ('cache@example.com','Cache test','unused')").run();
  db.prepare(`INSERT INTO sessions(token_hash,user_id,expires_at,absolute_expires_at,last_seen_at)
    VALUES (?,?,?,?,?)`).run(hash, user.lastInsertRowid, Date.now() + 60000, Date.now() + 3600000, previousSeen);
  await new Promise(resolve => { server = app.listen(0, '127.0.0.1', resolve); });
  base = `http://127.0.0.1:${server.address().port}`;
});
after(async () => {
  await new Promise(resolve => server.close(resolve));
  db.close();
  fs.rmSync(process.env.DATA_DIR, { recursive: true, force: true });
});

test('public assets avoid session writes while authenticated API responses cannot be cached', async () => {
  const headers = { Cookie: `session=${token}` };
  const page = await fetch(base + '/styles.css', { headers });
  assert.equal(page.status, 200);
  await page.text();
  assert.equal(db.prepare('SELECT last_seen_at FROM sessions WHERE token_hash = ?').get(hash).last_seen_at, previousSeen);
  const response = await fetch(base + '/api/auth/me', { headers });
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('cache-control'), 'no-store');
  assert.equal((await response.json()).user.email, 'cache@example.com');
  assert.ok(db.prepare('SELECT last_seen_at FROM sessions WHERE token_hash = ?').get(hash).last_seen_at > previousSeen);
  const denied = await fetch(base + '/api/owner/rooms');
  assert.equal(denied.status, 401);
  assert.equal(denied.headers.get('cache-control'), 'no-store');
  await denied.text();
});
