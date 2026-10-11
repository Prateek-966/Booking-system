'use strict';

const crypto = require('crypto');
const express = require('express');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const db = require('../db');
const totp = require('../totp');
const auth = require('../auth');
const v = require('../validators');

const router = express.Router();

const BCRYPT_ROUNDS = 12;
// Pre-computed hash compared against when the account does not exist, so the
// login endpoint takes the same time either way (no user-enumeration timing oracle).
const DUMMY_HASH = bcrypt.hashSync('invalid-password-placeholder', BCRYPT_ROUNDS);

// Which roles may sign in through each portal. Guests can never reach the
// owner portal, and the owner account can never sign in as a guest.
const PORTAL_ROLES = {
  guest: ['guest'],
  owner: ['owner', 'admin'],
};

const AUTH_LIMIT = Number(process.env.AUTH_RATE_LIMIT) || 20;

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: AUTH_LIMIT,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Too many attempts, please try again later' },
});

// The owner portal is throttled harder still: there is exactly one owner
// account, so legitimate traffic here is a handful of requests a day.
const ownerLoginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: Number(process.env.OWNER_RATE_LIMIT) || 10,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Too many attempts, please try again later' },
});

function publicUser(user) {
  return {
    id: user.id,
    email: user.email,
    name: user.name,
    role: user.role,
    totpEnabled: Boolean(user.totp_enabled ?? user.totpEnabled),
  };
}

// Registration creates guests only. There is one owner and it is provisioned
// by `npm run create-owner`, so no network path can ever mint one.
router.post('/register', authLimiter, async (req, res, next) => {
  try {
    const { email, name, password, phone } = req.body ?? {};
    if (!v.isValidEmail(email)) {
      return res.status(400).json({ error: 'A valid email address is required' });
    }
    if (!v.isValidName(name)) {
      return res.status(400).json({ error: 'Name is required (max 100 characters)' });
    }
    if (!v.isValidPassword(password)) {
      return res.status(400).json({ error: 'Password must be 8-72 characters' });
    }
    if (phone !== undefined && phone !== '' && !v.isValidPhone(phone)) {
      return res.status(400).json({ error: 'Phone number is not valid' });
    }

    const normalized = v.normalizeEmail(email);
    const hash = await bcrypt.hash(password, BCRYPT_ROUNDS);
    let result;
    try {
      result = db
        .prepare("INSERT INTO users (email, name, phone, password_hash, role) VALUES (?, ?, ?, ?, 'guest')")
        .run(normalized, name.trim(), (phone ?? '').trim(), hash);
    } catch (err) {
      if (err.code === 'SQLITE_CONSTRAINT_UNIQUE') {
        return res.status(409).json({ error: 'An account with this email already exists' });
      }
      throw err;
    }

    const user = { id: result.lastInsertRowid, email: normalized, name: name.trim(), role: 'guest' };
    auth.createSession(req, res, user);
    auth.recordLoginAttempt(req, { userId: user.id, email: normalized, outcome: 'register' });
    res.status(201).json({ user: publicUser(user) });
  } catch (err) {
    next(err);
  }
});

router.post('/login', authLimiter, (req, res, next) => {
  // A limiter ends throttled responses without calling next. Keep it in the
  // middleware chain instead of waiting on a promise that never resolves.
  if (req.body?.portal === 'owner') return ownerLoginLimiter(req, res, next);
  return next();
}, async (req, res, next) => {
  try {
    const { email, password, portal, totpCode, recoveryCode } = req.body ?? {};
    if (!Object.prototype.hasOwnProperty.call(PORTAL_ROLES, portal)) {
      return res.status(400).json({ error: 'Unknown sign-in portal' });
    }
    if (!v.isValidEmail(email) || typeof password !== 'string' || password.length > 1024) {
      return res.status(400).json({ error: 'Invalid email or password' });
    }
    const normalized = v.normalizeEmail(email);
    const account = db.prepare('SELECT * FROM users WHERE email = ?').get(normalized);

    // A locked account is refused before the password is even considered.
    if (account) {
      const remaining = auth.lockRemainingMs(account);
      if (remaining > 0) {
        auth.recordLoginAttempt(req, { userId: account.id, email: normalized, outcome: 'locked' });
        return res.status(429).json({
          error: `Too many failed attempts. Try again in ${Math.ceil(remaining / 60000)} minute(s).`,
        });
      }
    }

    // Always run a comparison so a wrong password and a missing account are
    // indistinguishable in both timing and response.
    const passwordOk = await bcrypt.compare(password, account ? account.password_hash : DUMMY_HASH);
    // Password hashing yields to other requests. Re-read security state so a
    // consumed TOTP, newly enabled 2FA, lockout or password rotation is honored.
    const user = account ? db.prepare('SELECT * FROM users WHERE id = ?').get(account.id) : null;

    if (user && auth.lockRemainingMs(user) > 0) {
      auth.recordLoginAttempt(req, { userId: user.id, email: normalized, outcome: 'locked' });
      return res.status(429).json({
        error: `Too many failed attempts. Try again in ${Math.ceil(auth.lockRemainingMs(user) / 60000)} minute(s).`,
      });
    }

    if (!user || !passwordOk || user.password_hash !== account.password_hash) {
      if (user) auth.recordFailedAttempt(user);
      auth.recordLoginAttempt(req, {
        userId: user ? user.id : null,
        email: normalized,
        outcome: user ? 'bad_password' : 'unknown_user',
      });
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Using the wrong portal is reported exactly like bad credentials, so the
    // portals cannot be used to discover which address is the owner's.
    if (!PORTAL_ROLES[portal].includes(user.role)) {
      auth.recordFailedAttempt(user);
      auth.recordLoginAttempt(req, { userId: user.id, email: normalized, outcome: 'wrong_portal' });
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Second factor, when the account has it switched on.
    if (user.totp_enabled) {
      const suppliedTotp = typeof totpCode === 'string' ? totpCode.trim() : '';
      const suppliedRecovery = typeof recoveryCode === 'string' ? recoveryCode.trim().toUpperCase() : '';

      if (suppliedTotp === '' && suppliedRecovery === '') {
        // Not a failed attempt: the password was right, we just need step two.
        return res.status(401).json({
          error: 'Enter the 6-digit code from your authenticator app',
          totpRequired: true,
        });
      }

      let accepted = false;
      if (suppliedRecovery !== '') {
        accepted = consumeRecoveryCode(user.id, suppliedRecovery);
      } else {
        const step = totp.verify(user.totp_secret, suppliedTotp, { minStep: user.totp_last_step });
        if (step !== null) {
          // Recording the step blocks replay of the same code inside its window.
          const result = db.prepare(
            `UPDATE users SET totp_last_step = ?
               WHERE id = ? AND totp_enabled = 1 AND totp_secret = ? AND totp_last_step < ?`
          ).run(step, user.id, user.totp_secret, step);
          accepted = result.changes === 1;
        }
      }

      if (!accepted) {
        auth.recordFailedAttempt(user);
        auth.recordLoginAttempt(req, { userId: user.id, email: normalized, outcome: 'bad_totp' });
        return res.status(401).json({
          error: 'That code is not valid or has already been used',
          totpRequired: true,
        });
      }
    }

    auth.clearFailedAttempts(user.id);
    auth.createSession(req, res, user);
    auth.recordLoginAttempt(req, { userId: user.id, email: normalized, outcome: 'success' });
    return res.json({ user: publicUser(user) });
  } catch (err) {
    return next(err);
  }
});

router.post('/logout', auth.requireAuth, (req, res) => {
  auth.destroySession(req, res);
  res.json({ ok: true });
});

router.get('/me', (req, res) => {
  res.json({ user: req.user });
});

router.post('/change-password', auth.requireAuth, authLimiter, async (req, res, next) => {
  try {
    const { currentPassword, newPassword } = req.body ?? {};
    if (typeof currentPassword !== 'string' || currentPassword.length > 1024) {
      return res.status(400).json({ error: 'Current password is required' });
    }

    // The owner is held to the stronger policy.
    if (auth.isPrivileged(req.user.role)) {
      const strength = v.isStrongOwnerPassword(newPassword);
      if (!strength.ok) return res.status(400).json({ error: strength.error });
    } else if (!v.isValidPassword(newPassword)) {
      return res.status(400).json({ error: 'New password must be 8-72 characters' });
    }

    const row = db.prepare('SELECT password_hash FROM users WHERE id = ?').get(req.user.id);
    const ok = await bcrypt.compare(currentPassword, row.password_hash);
    if (!ok) {
      auth.recordLoginAttempt(req, {
        userId: req.user.id,
        email: req.user.email,
        outcome: 'bad_password_change',
      });
      return res.status(401).json({ error: 'Current password is incorrect' });
    }

    const hash = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);
    const updated = db.prepare('UPDATE users SET password_hash = ? WHERE id = ? AND password_hash = ?')
      .run(hash, req.user.id, row.password_hash);
    if (!updated.changes) {
      return res.status(401).json({ error: 'Your password changed. Sign in again before retrying.' });
    }

    // A password change revokes every session, then issues one fresh session.
    auth.destroyAllSessions(req.user.id);
    auth.createSession(req, res, req.user);
    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
});

// --- Two-factor authentication (owner) ---

function generateRecoveryCodes() {
  const codes = [];
  for (let i = 0; i < 8; i += 1) {
    const raw = crypto.randomBytes(9).toString('base64').replace(/[^A-Z0-9]/gi, '').toUpperCase();
    const padded = (raw + crypto.randomBytes(9).toString('hex').toUpperCase()).slice(0, 12);
    codes.push(`${padded.slice(0, 4)}-${padded.slice(4, 8)}-${padded.slice(8, 12)}`);
  }
  return codes;
}

function storeRecoveryCodes(userId, codes) {
  const insert = db.prepare('INSERT INTO recovery_codes (user_id, code_hash) VALUES (?, ?)');
  const replace = db.transaction(() => {
    db.prepare('DELETE FROM recovery_codes WHERE user_id = ?').run(userId);
    for (const code of codes) {
      insert.run(userId, bcrypt.hashSync(code, 10));
    }
  });
  replace();
}

// Recovery codes are single use: the row is marked the moment one is accepted.
function consumeRecoveryCode(userId, supplied) {
  if (!v.isValidRecoveryCode(supplied)) return false;
  const rows = db
    .prepare('SELECT id, code_hash FROM recovery_codes WHERE user_id = ? AND used_at IS NULL')
    .all(userId);
  for (const row of rows) {
    if (bcrypt.compareSync(supplied, row.code_hash)) {
      return db.prepare("UPDATE recovery_codes SET used_at = datetime('now') WHERE id = ? AND used_at IS NULL")
        .run(row.id).changes === 1;
    }
  }
  return false;
}

// Step one: hand back a secret and its QR-ready URI. Nothing is switched on
// until the owner proves they can generate a code from it.
router.post('/2fa/setup', auth.requireOwner, authLimiter, (req, res) => {
  const secret = totp.generateSecret();
  const result = db.prepare(
    'UPDATE users SET totp_secret = ?, totp_last_step = 0 WHERE id = ? AND totp_enabled = 0'
  ).run(secret, req.user.id);
  if (!result.changes) {
    return res.status(409).json({ error: 'Two-factor authentication is already on. Disable it before starting setup again.' });
  }
  res.json({
    secret,
    uri: totp.provisioningUri(secret, { issuer: 'Staylist', account: req.user.email }),
  });
});

// Step two: confirm a code, enable two-factor, and issue recovery codes. They
// are shown exactly once — only their hashes are stored.
router.post('/2fa/enable', auth.requireOwner, authLimiter, (req, res) => {
  const { code } = req.body ?? {};
  const row = db.prepare('SELECT totp_secret, totp_enabled FROM users WHERE id = ?').get(req.user.id);
  if (!row.totp_secret) {
    return res.status(400).json({ error: 'Start the setup step first' });
  }
  if (row.totp_enabled) {
    return res.status(409).json({ error: 'Two-factor authentication is already on' });
  }
  if (!v.isValidTotpCode(code)) {
    return res.status(400).json({ error: 'Enter the 6-digit code from your authenticator app' });
  }
  const step = totp.verify(row.totp_secret, code);
  if (step === null) {
    return res.status(400).json({ error: 'That code is not valid — check your app and try again' });
  }

  const codes = generateRecoveryCodes();
  storeRecoveryCodes(req.user.id, codes);
  db.prepare('UPDATE users SET totp_enabled = 1, totp_last_step = ? WHERE id = ?').run(step, req.user.id);

  // Turning two-factor on invalidates other sessions, in case one was stolen.
  auth.destroyOtherSessions(req.user.id, req.sessionToken);
  res.json({ ok: true, recoveryCodes: codes });
});

// Disabling requires the current password: a stolen session alone must not be
// enough to strip the second factor off the account.
router.post('/2fa/disable', auth.requireOwner, authLimiter, async (req, res, next) => {
  try {
    const { password } = req.body ?? {};
    if (typeof password !== 'string' || password.length === 0 || password.length > 1024) {
      return res.status(400).json({ error: 'Your password is required to turn two-factor off' });
    }
    const row = db.prepare('SELECT password_hash FROM users WHERE id = ?').get(req.user.id);
    const ok = await bcrypt.compare(password, row.password_hash);
    if (!ok) {
      return res.status(401).json({ error: 'Password is incorrect' });
    }
    const updated = db.prepare(
      'UPDATE users SET totp_enabled = 0, totp_secret = NULL, totp_last_step = 0 WHERE id = ? AND password_hash = ?'
    ).run(req.user.id, row.password_hash);
    if (!updated.changes) {
      return res.status(401).json({ error: 'Your password changed. Sign in again before retrying.' });
    }
    db.prepare('DELETE FROM recovery_codes WHERE user_id = ?').run(req.user.id);
    auth.destroyOtherSessions(req.user.id, req.sessionToken);
    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
});

router.post('/2fa/recovery-codes', auth.requireOwner, authLimiter, async (req, res, next) => {
  try {
    const { password } = req.body ?? {};
    if (typeof password !== 'string' || password.length === 0 || password.length > 1024) {
      return res.status(400).json({ error: 'Your password is required' });
    }
    const row = db.prepare('SELECT password_hash, totp_enabled FROM users WHERE id = ?').get(req.user.id);
    if (!row.totp_enabled) {
      return res.status(400).json({ error: 'Two-factor authentication is not on' });
    }
    const ok = await bcrypt.compare(password, row.password_hash);
    if (!ok) return res.status(401).json({ error: 'Password is incorrect' });
    const current = db.prepare('SELECT password_hash, totp_enabled FROM users WHERE id = ?').get(req.user.id);
    if (!current || current.password_hash !== row.password_hash || !current.totp_enabled) {
      return res.status(401).json({ error: 'Your security settings changed. Sign in again before retrying.' });
    }

    const codes = generateRecoveryCodes();
    storeRecoveryCodes(req.user.id, codes);
    res.json({ ok: true, recoveryCodes: codes });
  } catch (err) {
    next(err);
  }
});

// --- Session visibility and revocation (owner) ---

router.get('/security', auth.requireOwner, (req, res) => {
  const row = db
    .prepare('SELECT totp_enabled, last_login_at, failed_attempts FROM users WHERE id = ?')
    .get(req.user.id);
  const unusedCodes = db
    .prepare('SELECT COUNT(*) AS n FROM recovery_codes WHERE user_id = ? AND used_at IS NULL')
    .get(req.user.id).n;
  res.json({
    twoFactorEnabled: Boolean(row.totp_enabled),
    lastLoginAt: row.last_login_at,
    failedAttempts: row.failed_attempts,
    unusedRecoveryCodes: unusedCodes,
    sessions: auth.listSessions(req.user.id, req.sessionToken),
    recentAttempts: auth.recentLoginAttempts(req.user.id),
  });
});

router.delete('/sessions/:id', auth.requireOwner, (req, res) => {
  const removed = auth.revokeSessionById(req.user.id, req.params.id);
  if (removed === 0) {
    return res.status(404).json({ error: 'Session not found' });
  }
  res.json({ ok: true });
});

router.post('/sessions/revoke-others', auth.requireOwner, (req, res) => {
  auth.destroyOtherSessions(req.user.id, req.sessionToken);
  res.json({ ok: true });
});

module.exports = router;
