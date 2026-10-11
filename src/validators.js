'use strict';

const MAX_ADVANCE_DAYS = 365; // how far ahead a stay may start
const MAX_STAY_NIGHTS = 60;
const MAX_PRICE = 10_000_000; // whole currency units, per night
const MAX_IMAGE_BYTES = 2 * 1024 * 1024;

// Accept one mailbox, never display names or address lists. Those delimiters
// otherwise have a second meaning when passed to an email transport.
const EMAIL_RE = /^[^\s@<>,;:"\\()[\]]+@[^\s@<>,;:"\\()[\]]+\.[^\s@<>,;:"\\()[\]]+$/;
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const PHONE_RE = /^[+()\-\s0-9]{6,20}$/;

const ROLES = ['guest', 'owner'];

function normalizeEmail(email) {
  return String(email).trim().toLowerCase();
}

function isValidEmail(email) {
  return typeof email === 'string' && email.length <= 254 && EMAIL_RE.test(email);
}

function isValidName(name) {
  return typeof name === 'string' && name.trim().length >= 1 && name.trim().length <= 100;
}

// bcrypt only uses the first 72 bytes, so cap the length as well as floor it.
function isValidPassword(password) {
  return typeof password === 'string' && password.length >= 8 && Buffer.byteLength(password, 'utf8') <= 72;
}

// Guest is the only role obtainable over the network. Owner and admin exist
// solely for accounts provisioned server-side by `npm run create-owner`.
function isValidRole(role) {
  return ROLES.includes(role);
}

// The owner account controls the whole guesthouse, so it is held to a longer
// minimum and refuses the passwords attackers try first.
const WEAK_PASSWORDS = new Set([
  'password', 'password1', 'password123', 'passw0rd', '12345678', '123456789', '1234567890',
  'qwerty123', 'qwertyuiop', 'letmein123', 'welcome123', 'admin123', 'administrator',
  'iloveyou', 'sunshine', 'princess', 'football', 'baseball', 'dragon123', 'monkey123',
  'abc12345', 'changeme', 'secret123', 'owner123', 'booking123', 'guesthouse',
]);

function isStrongOwnerPassword(password) {
  if (typeof password !== 'string') return { ok: false, error: 'A password is required' };
  if (password.length < 12) {
    return { ok: false, error: 'Owner passwords must be at least 12 characters' };
  }
  if (Buffer.byteLength(password, 'utf8') > 72) {
    return { ok: false, error: 'Owner passwords must be at most 72 bytes' };
  }
  const normalized = password.toLowerCase();
  if (WEAK_PASSWORDS.has(normalized)) {
    return { ok: false, error: 'That password is too common — choose something unique' };
  }
  if (/^(.)\1+$/.test(password)) {
    return { ok: false, error: 'That password is a single repeated character' };
  }
  // Require some variety rather than a long run of one character class.
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((re) => re.test(password)).length;
  if (classes < 2) {
    return {
      ok: false,
      error: 'Use at least two of: lower case, upper case, digits, symbols',
    };
  }
  return { ok: true };
}

const TIME_RE = /^([01]\d|2[0-3]):([0-5]\d)$/;

function isValidTime(value) {
  return typeof value === 'string' && TIME_RE.test(value);
}

function isValidTotpCode(value) {
  return typeof value === 'string' && /^\d{6}$/.test(value.trim());
}

function isValidRecoveryCode(value) {
  return typeof value === 'string' && /^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(value.trim().toUpperCase());
}

function isValidText(value, max, { required = true } = {}) {
  if (typeof value !== 'string') return false;
  const trimmed = value.trim();
  if (required && trimmed.length === 0) return false;
  return trimmed.length <= max;
}

function isValidTitle(value) {
  return isValidText(value, 120);
}

function isValidLocation(value) {
  return isValidText(value, 120);
}

function isValidDescription(value) {
  return isValidText(value, 2000, { required: false });
}

function isValidRoomName(value) {
  return isValidText(value, 80);
}

function isValidCaption(value) {
  return isValidText(value, 140, { required: false });
}

function isValidTagline(value) {
  return isValidText(value, 160, { required: false });
}

function isValidAbout(value) {
  return isValidText(value, 4000, { required: false });
}

function isValidAddress(value) {
  return isValidText(value, 300, { required: false });
}

function isValidHouseRules(value) {
  return isValidText(value, 2000, { required: false });
}

function isValidNote(value) {
  return isValidText(value, 500, { required: false });
}

function isValidPhone(value) {
  return typeof value === 'string' && (value.trim() === '' || PHONE_RE.test(value.trim()));
}

// Prices are whole currency units held as integers — never floats, so totals
// cannot drift through rounding error.
function isValidPrice(value) {
  return isPositiveInteger(value, MAX_PRICE);
}

function isValidGuestCount(value) {
  return isPositiveInteger(value, 50);
}

function isValidId(value) {
  return isPositiveInteger(value, Number.MAX_SAFE_INTEGER);
}

function isPositiveInteger(value, max) {
  // URL parameters and form values may be decimal strings; objects, arrays,
  // booleans and other coercible JSON values must not become valid numbers.
  if (typeof value !== 'number' && (typeof value !== 'string' || !/^\d+$/.test(value.trim()))) {
    return false;
  }
  const n = Number(value);
  return Number.isSafeInteger(n) && n > 0 && n <= max;
}

// Accepts only a real calendar date in YYYY-MM-DD form.
function isRealDate(date) {
  if (typeof date !== 'string' || !DATE_RE.test(date)) return false;
  const parsed = new Date(`${date}T00:00:00Z`);
  if (Number.isNaN(parsed.getTime())) return false;
  // Reject dates JS silently rolls over, e.g. 2026-02-31 -> March 3rd.
  return parsed.toISOString().slice(0, 10) === date;
}

function todayUtcMs() {
  const now = new Date();
  return Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate());
}

function nightsBetween(checkIn, checkOut) {
  return (Date.parse(`${checkOut}T00:00:00Z`) - Date.parse(`${checkIn}T00:00:00Z`)) / 86400000;
}

// Validates a whole stay, returning the night count or an error message.
function validateStay(checkIn, checkOut) {
  if (!isRealDate(checkIn) || !isRealDate(checkOut)) {
    return { error: 'Check-in and check-out must be real dates in YYYY-MM-DD form' };
  }
  const startMs = Date.parse(`${checkIn}T00:00:00Z`);
  const daysAhead = (startMs - todayUtcMs()) / 86400000;
  if (daysAhead < 0) {
    return { error: 'Check-in cannot be in the past' };
  }
  if (daysAhead > MAX_ADVANCE_DAYS) {
    return { error: `Check-in cannot be more than ${MAX_ADVANCE_DAYS} days ahead` };
  }
  const nights = nightsBetween(checkIn, checkOut);
  if (nights < 1) {
    return { error: 'Check-out must be at least one night after check-in' };
  }
  if (nights > MAX_STAY_NIGHTS) {
    return { error: `Stays cannot exceed ${MAX_STAY_NIGHTS} nights` };
  }
  return { nights };
}

// Identifies an image by its magic bytes rather than trusting the declared
// Content-Type. SVG is deliberately unsupported: it can carry script.
function sniffImageType(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 12) return null;
  if (buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff) {
    return 'image/jpeg';
  }
  if (
    buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4e && buffer[3] === 0x47 &&
    buffer[4] === 0x0d && buffer[5] === 0x0a && buffer[6] === 0x1a && buffer[7] === 0x0a
  ) {
    return 'image/png';
  }
  if (buffer.toString('ascii', 0, 4) === 'RIFF' && buffer.toString('ascii', 8, 12) === 'WEBP') {
    return 'image/webp';
  }
  return null;
}

module.exports = {
  MAX_ADVANCE_DAYS,
  MAX_STAY_NIGHTS,
  MAX_PRICE,
  MAX_IMAGE_BYTES,
  ROLES,
  normalizeEmail,
  isValidEmail,
  isValidName,
  isValidPassword,
  isValidRole,
  isStrongOwnerPassword,
  isValidTime,
  isValidTotpCode,
  isValidRecoveryCode,
  isValidTitle,
  isValidLocation,
  isValidDescription,
  isValidRoomName,
  isValidCaption,
  isValidTagline,
  isValidAbout,
  isValidAddress,
  isValidHouseRules,
  isValidNote,
  isValidPhone,
  isValidPrice,
  isValidGuestCount,
  isValidId,
  isRealDate,
  nightsBetween,
  validateStay,
  sniffImageType,
};
