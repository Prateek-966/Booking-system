'use strict';

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'booking-route-security-'));
process.env.NODE_ENV = 'test';
process.env.SEED_DEMO = '0';
process.env.GLOBAL_RATE_LIMIT = '2000';
for (const name of ['SMTP_HOST', 'SMTP_USER', 'SMTP_PASS', 'WHATSAPP_TOKEN', 'WHATSAPP_PHONE_NUMBER_ID']) {
  delete process.env[name];
}

const app = require('../src/app');
const db = require('../src/db');
const { createSession } = require('../src/auth');
const validators = require('../src/validators');
const notify = require('../src/notify');
const nodemailer = require('nodemailer');

let server;
let baseUrl;
let ownerCookie;
let guestCookie;
let guestId;

const PNG = Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==',
  'base64'
);

function sessionFor(role) {
  const user = { id: db.prepare(
    'INSERT INTO users (email, name, password_hash, role) VALUES (?, ?, ?, ?)'
  ).run(`${role}@example.com`, role, 'not-used-for-login', role).lastInsertRowid, role };
  let cookie;
  createSession({ headers: {}, ip: '127.0.0.1' }, {
    cookie(name, value) { cookie = `${name}=${value}`; },
  }, user);
  return { cookie, id: user.id };
}

before(async () => {
  ({ cookie: ownerCookie } = sessionFor('owner'));
  ({ cookie: guestCookie, id: guestId } = sessionFor('guest'));
  await new Promise((resolve) => { server = app.listen(0, '127.0.0.1', resolve); });
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  await new Promise((resolve) => server.close(resolve));
  db.close();
  fs.rmSync(process.env.DATA_DIR, { recursive: true, force: true });
});

function room(published = 1) {
  return db.prepare(
    'INSERT INTO rooms (name, price_per_night, max_guests, published) VALUES (?, ?, ?, ?)'
  ).run('Private room', 1200, 2, published).lastInsertRowid;
}

function photo(roomId) {
  return db.prepare('INSERT INTO images (room_id, mime_type, bytes) VALUES (?, ?, ?)')
    .run(roomId, 'image/png', PNG).lastInsertRowid;
}

async function request(url, { cookie, body, ...options } = {}) {
  const headers = { ...options.headers, ...(cookie ? { Cookie: cookie } : {}) };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  return fetch(baseUrl + url, {
    ...options,
    headers,
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
}

async function withEnv(values, run) {
  const originals = Object.fromEntries(Object.keys(values).map((key) => [key, process.env[key]]));
  Object.assign(process.env, values);
  try {
    return await run();
  } finally {
    for (const [key, value] of Object.entries(originals)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
}

test('unpublishing a room also hides its photos from guests and conditional requests', async () => {
  const roomId = room();
  const imageId = photo(roomId);
  const publicImage = await request(`/api/images/${imageId}`);
  assert.equal(publicImage.status, 200);
  assert.match(publicImage.headers.get('cache-control'), /max-age=0, must-revalidate/);
  const etag = publicImage.headers.get('etag');
  assert.ok(etag);
  await publicImage.arrayBuffer();

  const unpublished = await request(`/api/owner/rooms/${roomId}`, {
    cookie: ownerCookie, method: 'PATCH', body: { published: false },
  });
  assert.equal(unpublished.status, 200);
  for (const cookie of [undefined, guestCookie]) {
    const hidden = await request(`/api/images/${imageId}`, { cookie, headers: { 'If-None-Match': etag } });
    assert.equal(hidden.status, 404);
  }
  const ownerImage = await request(`/api/images/${imageId}`, { cookie: ownerCookie });
  assert.equal(ownerImage.status, 200);
  assert.equal(ownerImage.headers.get('cache-control'), 'private, no-store');
  assert.deepEqual(Buffer.from(await ownerImage.arrayBuffer()), PNG);
  const propertyPhoto = await request(`/api/images/${photo(null)}`);
  assert.equal(propertyPhoto.status, 200);
  await propertyPhoto.arrayBuffer();
});

test('owner galleries retain all photos in upload order, including unpublished and empty rooms', async () => {
  const withImages = room(0);
  const noImages = room();
  const ids = [photo(withImages), photo(withImages)];
  const response = await request('/api/owner/rooms', { cookie: ownerCookie });
  assert.equal(response.status, 200);
  const { rooms } = await response.json();
  assert.deepEqual(rooms.find((entry) => entry.id === withImages).imageIds, ids);
  assert.equal(rooms.find((entry) => entry.id === withImages).published, false);
  assert.deepEqual(rooms.find((entry) => entry.id === noImages).imageIds, []);
});

test('numeric validators reject type coercion and accept decimal inputs', () => {
  for (const validate of [validators.isValidPrice, validators.isValidGuestCount, validators.isValidId]) {
    for (const value of [true, false, [1], [], {}, { toString: null }, null, '0x1', '1e0', '1.5', 0, -1]) {
      assert.equal(validate(value), false, JSON.stringify(value));
    }
    for (const value of [1, '1', ' 2 ']) assert.equal(validate(value), true);
  }
});

test('malformed numeric API input returns validation errors without creating records', async () => {
  const roomCount = db.prepare('SELECT COUNT(*) AS n FROM rooms').get().n;
  for (const value of [true, [1], { toString: null }]) {
    const create = await request('/api/owner/rooms', {
      cookie: ownerCookie, method: 'POST', body: { name: 'Invalid', pricePerNight: value, maxGuests: 2 },
    });
    assert.equal(create.status, 400);
    const booking = await request('/api/bookings', {
      cookie: guestCookie, method: 'POST', body: { roomId: value },
    });
    assert.equal(booking.status, 400);
  }
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM rooms').get().n, roomCount);
  const query = await request('/api/rooms?guests[toString]=1');
  assert.equal(query.status, 400);
});

test('email validation rejects address-list syntax while accepting ordinary mailbox addresses', async () => {
  for (const address of ['guest@example.com,other', 'guest@example.com;', '<guest@example.com>', 'guest(comment)@example.com']) {
    assert.equal(validators.isValidEmail(address), false, address);
    const response = await request('/api/owner/property', {
      cookie: ownerCookie, method: 'PATCH', body: { contactEmail: address },
    });
    assert.equal(response.status, 400);
  }
  assert.equal(validators.isValidEmail('guest+stay@example.com'), true);
});

test('notification storage failures do not turn a completed booking into a failed request', async () => {
  const roomId = room();
  const checkIn = new Date(Date.now() + 86400000).toISOString().slice(0, 10);
  const checkOut = new Date(Date.now() + 2 * 86400000).toISOString().slice(0, 10);
  db.exec("CREATE TEMP TRIGGER notification_failure BEFORE INSERT ON notifications BEGIN SELECT RAISE(FAIL, 'notification storage unavailable'); END;");
  try {
    const response = await request('/api/bookings', {
      cookie: guestCookie, method: 'POST', body: { roomId, checkIn, checkOut },
    });
    assert.equal(response.status, 201);
    const { booking } = await response.json();
    assert.equal(db.prepare('SELECT guest_id FROM bookings WHERE id = ?').get(booking.id).guest_id, guestId);

    const approved = await request(`/api/owner/bookings/${booking.id}/approve`, {
      cookie: ownerCookie, method: 'POST', body: {},
    });
    assert.equal(approved.status, 200);
    assert.equal(db.prepare('SELECT status FROM bookings WHERE id = ?').get(booking.id).status, 'approved');
  } finally {
    db.exec('DROP TRIGGER notification_failure');
  }
});

test('SMTP messages require TLS remotely, have timeouts, and use one structured recipient', async (t) => {
  const transport = nodemailer.createTransport({ streamTransport: true, buffer: true });
  const configurations = [];
  let mailInfo;
  t.mock.method(nodemailer, 'createTransport', (options) => {
    configurations.push(options);
    return { async sendMail(mail) {
      assert.deepEqual(mail.to, { address: 'guest+receipt@example.com' });
      mailInfo = await transport.sendMail(mail);
    } };
  });
  await withEnv({ SMTP_HOST: 'smtp.example.com', SMTP_USER: 'sender@example.com', SMTP_PASS: 'test-password', SMTP_PORT: '587' }, async () => {
    await notify.notifyGuestOfDecision({
      id: null, room: 'Room', guestEmail: 'guest+receipt@example.com',
      checkIn: '2030-01-01', checkOut: '2030-01-02', totalPrice: 1200,
    }, true);
    assert.deepEqual(mailInfo.envelope.to, ['guest+receipt@example.com']);
    const options = configurations[0];
    assert.equal(options.requireTLS, true);
    assert.equal(options.secure, false);
    assert.equal(options.connectionTimeout, 10_000);
    assert.equal(options.greetingTimeout, 10_000);
    assert.equal(options.socketTimeout, 20_000);

    process.env.SMTP_HOST = '127.0.0.1';
    await notify.notifyGuestOfDecision({ id: null, guestEmail: 'guest+receipt@example.com' }, false);
    assert.equal(configurations[1].requireTLS, false, 'explicit local relay supports offline development');

    await notify.notifyGuestOfDecision({ id: null, guestEmail: 'guest@example.com,other' }, false);
    assert.equal(configurations.length, 2, 'legacy address-list values are blocked before delivery');
    assert.deepEqual(db.prepare('SELECT status, detail FROM notifications ORDER BY id DESC LIMIT 1').get(), {
      status: 'failed', detail: 'invalid recipient address',
    });
  });
});

test('WhatsApp delivery has a deadline and never follows a redirect with credentials', async (t) => {
  let requestOptions;
  t.mock.method(global, 'fetch', async (url, options) => {
    assert.match(url, /^https:\/\/graph\.facebook\.com\//);
    requestOptions = options;
    return new Response('', { status: 200 });
  });
  await withEnv({ WHATSAPP_TOKEN: 'test-token', WHATSAPP_PHONE_NUMBER_ID: '123', NOTIFY_PHONE: '+91 90000 00000' }, async () => {
    await notify.notifyOwnerOfRequest({ id: null, room: 'Room', guestName: 'Guest', totalPrice: 1200 });
    assert.ok(requestOptions.signal instanceof AbortSignal);
    assert.equal(requestOptions.redirect, 'error');
  });
});
