'use strict';

const fs = require('fs');
const path = require('path');
const express = require('express');
const db = require('../db');
const { requireOwner } = require('../auth');
const notify = require('../notify');
const v = require('../validators');

const router = express.Router();

// Bookings in these states occupy their dates. A declined or cancelled
// request releases them again.
const HOLDING_STATUSES = "('pending', 'approved')";

function imageIdsForRoom(roomId) {
  return db
    .prepare('SELECT id FROM images WHERE room_id = ? ORDER BY id')
    .all(roomId)
    .map((r) => r.id);
}

function propertyImageIds() {
  return db
    .prepare('SELECT id FROM images WHERE room_id IS NULL ORDER BY id')
    .all()
    .map((r) => r.id);
}

// An optional hero artwork bundled into /public. Reported by the API so the
// page never has to probe for it and take 404s on every load.
const PUBLIC_DIR = path.join(__dirname, '..', '..', 'public');
const HERO_CANDIDATES = ['hero.webp', 'hero.jpg', 'hero.png'];

function heroImagePath() {
  for (const name of HERO_CANDIDATES) {
    if (fs.existsSync(path.join(PUBLIC_DIR, name))) {
      return `/${name}`;
    }
  }
  return null;
}

// --- Public: the guesthouse and its rooms ---

router.get('/property', (req, res) => {
  const p = db
    .prepare(
      `SELECT name, tagline, about, location, address,
              contact_name AS contactName, contact_email AS contactEmail,
              contact_phone AS contactPhone, check_in_time AS checkInTime,
              check_out_time AS checkOutTime, house_rules AS houseRules
         FROM property WHERE id = 1`
    )
    .get();
  res.json({ property: p, imageIds: propertyImageIds(), heroImage: heroImagePath() });
});

// Room list, optionally filtered to those free for a given stay.
router.get('/rooms', (req, res) => {
  const { checkIn, checkOut, guests } = req.query;
  const clauses = ['r.published = 1'];
  const params = [];
  let nights = null;

  const wantsDates = (checkIn ?? '') !== '' || (checkOut ?? '') !== '';
  if (wantsDates) {
    if ((checkIn ?? '') === '' || (checkOut ?? '') === '') {
      return res.status(400).json({ error: 'Provide both a check-in and a check-out date' });
    }
    const stay = v.validateStay(checkIn, checkOut);
    if (stay.error) {
      return res.status(400).json({ error: stay.error });
    }
    nights = stay.nights;
    // Exclude rooms already held for any part of the stay.
    clauses.push(`NOT EXISTS (
      SELECT 1 FROM bookings b
       WHERE b.room_id = r.id AND b.status IN ${HOLDING_STATUSES}
         AND b.check_in < ? AND b.check_out > ?
    )`);
    params.push(checkOut, checkIn);
  }
  if (guests !== undefined && guests !== '') {
    if (!v.isValidGuestCount(guests)) {
      return res.status(400).json({ error: 'Invalid guest count' });
    }
    clauses.push('r.max_guests >= ?');
    params.push(Number(guests));
  }

  const rooms = db
    .prepare(
      `SELECT r.id, r.name, r.description, r.price_per_night AS pricePerNight,
              r.max_guests AS maxGuests,
              (SELECT id FROM images WHERE room_id = r.id ORDER BY id LIMIT 1) AS coverImageId
         FROM rooms r
        WHERE ${clauses.join(' AND ')}
        ORDER BY r.price_per_night, r.id`
    )
    .all(...params);

  if (nights !== null) {
    for (const room of rooms) {
      room.nights = nights;
      room.stayTotal = room.pricePerNight * nights;
    }
  }

  res.json({ rooms, nights });
});

router.get('/rooms/:id', (req, res) => {
  if (!v.isValidId(req.params.id)) {
    return res.status(400).json({ error: 'Invalid room id' });
  }
  const room = db
    .prepare(
      `SELECT id, name, description, price_per_night AS pricePerNight,
              max_guests AS maxGuests, published
         FROM rooms WHERE id = ?`
    )
    .get(Number(req.params.id));

  // Unpublished rooms are visible only to the owner.
  if (!room || (!room.published && !(req.user && ['owner', 'admin'].includes(req.user.role)))) {
    return res.status(404).json({ error: 'Room not found' });
  }

  const booked = db
    .prepare(
      `SELECT check_in AS checkIn, check_out AS checkOut
         FROM bookings
        WHERE room_id = ? AND status IN ${HOLDING_STATUSES} AND check_out >= date('now')
        ORDER BY check_in`
    )
    .all(room.id);

  delete room.published;
  res.json({ room, imageIds: imageIdsForRoom(room.id), booked });
});

// Public image delivery. The Content-Type is the value sniffed from magic
// bytes at upload time, never anything the uploader declared.
router.get('/images/:id', (req, res) => {
  if (!v.isValidId(req.params.id)) {
    return res.status(400).json({ error: 'Invalid image id' });
  }
  const isOwner = Boolean(req.user && ['owner', 'admin'].includes(req.user.role));
  const image = db.prepare(
    `SELECT i.mime_type, i.bytes FROM images i
       LEFT JOIN rooms r ON r.id = i.room_id
      WHERE i.id = ? AND (i.room_id IS NULL OR r.published = 1 OR ? = 1)`
  ).get(Number(req.params.id), Number(isOwner));
  if (!image) {
    return res.status(404).json({ error: 'Image not found' });
  }
  res.set('Content-Type', image.mime_type);
  res.set('Content-Disposition', 'inline');
  // Revalidate visibility after a room is unpublished or a photo is deleted.
  // Owner-only previews must never enter a shared cache.
  res.set('Cache-Control', isOwner ? 'private, no-store' : 'public, max-age=0, must-revalidate');
  res.send(image.bytes);
});

// --- Owner: the guesthouse ---

router.patch('/owner/property', requireOwner, (req, res) => {
  const body = req.body ?? {};
  const checks = [
    ['name', v.isValidTitle, 'Name is required (max 120 characters)', 'name'],
    ['tagline', v.isValidTagline, 'Tagline is too long (max 160 characters)', 'tagline'],
    ['about', v.isValidAbout, 'About is too long (max 4000 characters)', 'about'],
    ['location', v.isValidLocation, 'Location is required (max 120 characters)', 'location'],
    ['address', v.isValidAddress, 'Address is too long (max 300 characters)', 'address'],
    ['contactName', v.isValidName, 'Contact name is too long (max 100 characters)', 'contact_name'],
    ['contactEmail', v.isValidEmail, 'Contact email is not valid', 'contact_email'],
    ['contactPhone', v.isValidPhone, 'Contact phone is not valid', 'contact_phone'],
    ['checkInTime', v.isValidTime, 'Check-in time must be HH:MM', 'check_in_time'],
    ['checkOutTime', v.isValidTime, 'Check-out time must be HH:MM', 'check_out_time'],
    ['houseRules', v.isValidHouseRules, 'House rules are too long (max 2000 characters)', 'house_rules'],
  ];

  const sets = [];
  const params = [];
  for (const [key, valid, message, column] of checks) {
    if (body[key] === undefined) continue;
    // Optional text fields may be cleared; required ones may not.
    const isBlank = typeof body[key] === 'string' && body[key].trim() === '';
    const required = ['name', 'location'].includes(key);
    if (isBlank && !required) {
      sets.push(`${column} = ?`);
      params.push('');
      continue;
    }
    if (!valid(body[key])) {
      return res.status(400).json({ error: message });
    }
    sets.push(`${column} = ?`);
    params.push(String(body[key]).trim());
  }

  if (sets.length === 0) {
    return res.status(400).json({ error: 'No changes supplied' });
  }
  db.prepare(`UPDATE property SET ${sets.join(', ')} WHERE id = 1`).run(...params);
  res.json({ ok: true });
});

// --- Owner: rooms ---

router.get('/owner/rooms', requireOwner, (req, res) => {
  const imagesByRoom = new Map();
  for (const image of db.prepare('SELECT id, room_id FROM images WHERE room_id IS NOT NULL ORDER BY id').all()) {
    if (!imagesByRoom.has(image.room_id)) imagesByRoom.set(image.room_id, []);
    imagesByRoom.get(image.room_id).push(image.id);
  }
  const rooms = db
    .prepare(
      `SELECT id, name, description, price_per_night AS pricePerNight,
              max_guests AS maxGuests, published
         FROM rooms ORDER BY id`
    )
    .all()
    .map((r) => ({ ...r, published: Boolean(r.published), imageIds: imagesByRoom.get(r.id) || [] }));
  res.json({ rooms });
});

function validateRoomFields(body, { partial = false } = {}) {
  const fields = {};
  const specs = [
    ['name', v.isValidRoomName, 'Room name is required (max 80 characters)', true],
    ['pricePerNight', v.isValidPrice, 'Price must be a whole number of at least 1', true],
    ['maxGuests', v.isValidGuestCount, 'Maximum guests must be between 1 and 50', true],
    ['description', v.isValidDescription, 'Description is too long (max 2000 characters)', false],
  ];
  for (const [key, valid, message, required] of specs) {
    if (body[key] === undefined) {
      if (!partial && required) return { error: message };
      if (!partial && !required) fields[key] = '';
      continue;
    }
    if (!valid(body[key])) return { error: message };
    fields[key] = typeof body[key] === 'string' ? body[key].trim() : Number(body[key]);
  }
  if (body.published !== undefined) {
    if (typeof body.published !== 'boolean') {
      return { error: 'Published must be true or false' };
    }
    fields.published = body.published ? 1 : 0;
  }
  return { fields };
}

router.post('/owner/rooms', requireOwner, (req, res) => {
  const { error, fields } = validateRoomFields(req.body ?? {});
  if (error) return res.status(400).json({ error });

  if (db.prepare('SELECT COUNT(*) AS n FROM rooms').get().n >= 60) {
    return res.status(409).json({ error: 'A guesthouse can have at most 60 rooms' });
  }

  const result = db
    .prepare(
      'INSERT INTO rooms (name, description, price_per_night, max_guests, published) VALUES (?, ?, ?, ?, ?)'
    )
    .run(fields.name, fields.description ?? '', fields.pricePerNight, fields.maxGuests, fields.published ?? 1);
  res.status(201).json({ room: { id: result.lastInsertRowid, name: fields.name } });
});

router.patch('/owner/rooms/:id', requireOwner, (req, res) => {
  if (!v.isValidId(req.params.id)) {
    return res.status(400).json({ error: 'Invalid room id' });
  }
  const room = db.prepare('SELECT id FROM rooms WHERE id = ?').get(Number(req.params.id));
  if (!room) return res.status(404).json({ error: 'Room not found' });

  const { error, fields } = validateRoomFields(req.body ?? {}, { partial: true });
  if (error) return res.status(400).json({ error });

  const columns = {
    name: 'name',
    description: 'description',
    pricePerNight: 'price_per_night',
    maxGuests: 'max_guests',
    published: 'published',
  };
  const sets = [];
  const params = [];
  for (const [key, column] of Object.entries(columns)) {
    if (fields[key] !== undefined) {
      sets.push(`${column} = ?`);
      params.push(fields[key]);
    }
  }
  if (sets.length === 0) {
    return res.status(400).json({ error: 'No changes supplied' });
  }
  params.push(room.id);
  db.prepare(`UPDATE rooms SET ${sets.join(', ')} WHERE id = ?`).run(...params);
  res.json({ ok: true });
});

router.delete('/owner/rooms/:id', requireOwner, (req, res) => {
  if (!v.isValidId(req.params.id)) {
    return res.status(400).json({ error: 'Invalid room id' });
  }
  const room = db.prepare('SELECT id FROM rooms WHERE id = ?').get(Number(req.params.id));
  if (!room) return res.status(404).json({ error: 'Room not found' });

  // Guests' upcoming stays are protected: unpublish hides a room without
  // destroying bookings people are relying on.
  const upcoming = db
    .prepare(
      `SELECT COUNT(*) AS n FROM bookings
        WHERE room_id = ? AND status IN ${HOLDING_STATUSES} AND check_out >= date('now')`
    )
    .get(room.id).n;
  if (upcoming > 0) {
    return res.status(409).json({
      error: `This room has ${upcoming} live booking(s). Unpublish it instead, or settle those stays first.`,
    });
  }
  db.prepare('DELETE FROM rooms WHERE id = ?').run(room.id);
  res.json({ ok: true });
});

// --- Owner: photos ---

const rawImage = express.raw({
  type: ['image/jpeg', 'image/png', 'image/webp'],
  limit: v.MAX_IMAGE_BYTES,
});

function storeImage(req, res, roomId) {
  if (!Buffer.isBuffer(req.body) || req.body.length === 0) {
    return res.status(400).json({ error: 'Send the image as a JPEG, PNG or WebP file' });
  }
  // The real type is decided here, by content — a lying Content-Type gains
  // nothing, and SVG (which can carry script) is not in the accepted set.
  const mime = v.sniffImageType(req.body);
  if (!mime) {
    return res.status(400).json({ error: 'That file is not a valid JPEG, PNG or WebP image' });
  }
  const scope = roomId === null ? 'room_id IS NULL' : 'room_id = ?';
  const countArgs = roomId === null ? [] : [roomId];
  const count = db.prepare(`SELECT COUNT(*) AS n FROM images WHERE ${scope}`).get(...countArgs).n;
  if (count >= 20) {
    return res.status(409).json({ error: 'That gallery already has 20 photos' });
  }
  const caption = typeof req.query.caption === 'string' ? req.query.caption : '';
  if (!v.isValidCaption(caption)) {
    return res.status(400).json({ error: 'Caption is too long (max 140 characters)' });
  }
  const result = db
    .prepare('INSERT INTO images (room_id, mime_type, bytes, caption) VALUES (?, ?, ?, ?)')
    .run(roomId, mime, req.body, caption.trim());
  return res.status(201).json({ image: { id: result.lastInsertRowid } });
}

router.post('/owner/property/images', requireOwner, rawImage, (req, res) => storeImage(req, res, null));

router.post('/owner/rooms/:id/images', requireOwner, rawImage, (req, res) => {
  if (!v.isValidId(req.params.id)) {
    return res.status(400).json({ error: 'Invalid room id' });
  }
  const room = db.prepare('SELECT id FROM rooms WHERE id = ?').get(Number(req.params.id));
  if (!room) return res.status(404).json({ error: 'Room not found' });
  return storeImage(req, res, room.id);
});

router.delete('/owner/images/:id', requireOwner, (req, res) => {
  if (!v.isValidId(req.params.id)) {
    return res.status(400).json({ error: 'Invalid image id' });
  }
  const result = db.prepare('DELETE FROM images WHERE id = ?').run(Number(req.params.id));
  if (result.changes === 0) {
    return res.status(404).json({ error: 'Image not found' });
  }
  res.json({ ok: true });
});

// --- Owner: notification history ---

router.get('/owner/notifications', requireOwner, (req, res) => {
  res.json({ notifications: notify.listForOwner(), transports: notify.transportStatus() });
});

module.exports = router;
