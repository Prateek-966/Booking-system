'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

// Browser helpers are ES modules in an otherwise CommonJS application. A data
// URL lets Node import the actual source without changing the package type.
const helpers = import('data:text/javascript;base64,' + fs.readFileSync(
  path.join(__dirname, '..', 'public', 'js', 'common.js')
).toString('base64'));
const origin = 'https://booking.example';
const fallback = '/bookings.html';

test('login redirects reject external and malformed destinations after URL normalization', async () => {
  const { safeNextPath } = await helpers;
  for (const next of [
    null, '', 'https://evil.example', 'javascript:alert(1)',
    '//evil.example', '/\\evil.example', '/\t/evil.example', '/\n/evil.example',
    '/\\booking.example@evil.example', '/\\[invalid',
  ]) {
    assert.equal(safeNextPath(next, fallback, origin), fallback, JSON.stringify(next));
  }
});

test('login redirects preserve local destinations without reinterpreting normalized paths', async () => {
  const { safeNextPath } = await helpers;
  assert.equal(
    safeNextPath('/room.html?id=3&checkIn=2026-12-01#booking', fallback, origin),
    `${origin}/room.html?id=3&checkIn=2026-12-01#booking`
  );
  // Dot segment removal can produce a leading // in the pathname. Navigating
  // to the helper result must still keep the visitor on the booking site.
  const normalized = safeNextPath('/safe/..//evil.example', fallback, origin);
  assert.equal(new URL(normalized, origin).origin, origin);
  assert.equal(new URL(normalized, origin).pathname, '//evil.example');
});
