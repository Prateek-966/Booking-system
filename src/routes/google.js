'use strict';

const crypto = require('node:crypto');
const express = require('express');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const { OAuth2Client } = require('google-auth-library');
const db = require('../db');
const auth = require('../auth');
const totp = require('../totp');
const v = require('../validators');

const router = express.Router();
const verifier = new OAuth2Client({ transporterOptions: { timeout: 10000, retry: false } });
const lifetime = 10 * 60 * 1000;
const cookieName = process.env.NODE_ENV === 'production' ? '__Host-google-login' : 'google-login';
const cookieOptions = { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'strict', path: '/' };
const digest = (value) => crypto.createHash('sha256').update(value).digest('hex');
const clientId = () => process.env.GOOGLE_CLIENT_ID?.trim() || '';
const allowed = (user, portal) => portal === 'guest' ? user.role === 'guest' : auth.isPrivileged(user.role);
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: Number(process.env.AUTH_RATE_LIMIT) || 20,
  standardHeaders: 'draft-7', legacyHeaders: false,
  message: { error: 'Too many sign-in attempts. Please try again later.' },
});

const ownerLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: Number(process.env.OWNER_RATE_LIMIT) || 10,
  standardHeaders: 'draft-7', legacyHeaders: false,
  message: { error: 'Too many owner sign-in attempts. Please try again later.' },
});

router.get('/config', (req, res) => res.json({ enabled: Boolean(clientId()), clientId: clientId() }));
router.post('/start', limiter, (req, res) => {
  if (!clientId()) return res.status(503).json({ error: 'Google sign-in is not configured' });
  const portal = req.body?.portal;
  if (!['guest', 'owner'].includes(portal)) return res.status(400).json({ error: 'Unknown sign-in portal' });
  db.prepare('DELETE FROM google_login_attempts WHERE expires_at <= ?').run(Date.now());
  const previous = req.cookies[cookieName];
  if (typeof previous === 'string') db.prepare('DELETE FROM google_login_attempts WHERE nonce_hash = ?').run(digest(previous));
  const nonce = crypto.randomBytes(32).toString('base64url');
  db.prepare('INSERT INTO google_login_attempts(nonce_hash, portal, expires_at) VALUES (?,?,?)')
    .run(digest(nonce), portal, Date.now() + lifetime);
  res.cookie(cookieName, nonce, { ...cookieOptions, maxAge: lifetime });
  return res.json({ nonce });
});

function failure(status, error, extra = {}) { return { status, body: { error, ...extra } }; }

// Keep identity assignment, second-factor consumption and nonce consumption
// in one synchronous transaction, after all asynchronous verification finishes.
const finish = db.transaction((req, res, identity, nonceHash, checkedPassword) => {
  const attempt = db.prepare('SELECT * FROM google_login_attempts WHERE nonce_hash = ? AND expires_at > ?')
    .get(nonceHash, Date.now());
  if (!attempt) return failure(401, 'Google sign-in expired. Refresh this page and try again.');
  const linked = db.prepare('SELECT user_id FROM google_identities WHERE subject = ?').get(identity.sub);
  let user = linked
    ? db.prepare('SELECT * FROM users WHERE id = ?').get(linked.user_id)
    : db.prepare('SELECT * FROM users WHERE email = ?').get(v.normalizeEmail(identity.email));
  if (user && !allowed(user, attempt.portal)) return failure(403, 'This account cannot sign in through this portal.');
  if (!user && attempt.portal === 'owner') return failure(403, 'This account cannot sign in through this portal.');
  if (user && auth.lockRemainingMs(user) > 0) return failure(429, 'This account is temporarily locked. Try again later.');

  if (user && !linked) {
    const other = db.prepare('SELECT subject FROM google_identities WHERE user_id = ?').get(user.id);
    if (other) return failure(403, 'A different Google account is already linked. Use your original sign-in method.');
    // Email ownership alone cannot safely link a previously unverified local
    // account. Require its password once, including for the existing owner.
    if (!checkedPassword || checkedPassword.userId !== user.id || checkedPassword.hash !== user.password_hash) {
      return failure(401, 'Enter your existing account password once to link Google.', { linkRequired: true });
    }
    if (!checkedPassword.ok) {
      auth.recordFailedAttempt(user);
      auth.recordLoginAttempt(req, { userId: user.id, email: user.email, outcome: 'google_bad_link_password' });
      return failure(401, 'Password is incorrect.', { linkRequired: true });
    }
  }

  if (user?.totp_enabled) {
    const code = req.body?.totpCode;
    const recovery = req.body?.recoveryCode;
    let accepted = false;
    if (v.isValidRecoveryCode(recovery)) {
      for (const row of db.prepare('SELECT id, code_hash FROM recovery_codes WHERE user_id = ? AND used_at IS NULL').all(user.id)) {
        if (bcrypt.compareSync(recovery.trim().toUpperCase(), row.code_hash)) {
          accepted = db.prepare("UPDATE recovery_codes SET used_at = datetime('now') WHERE id = ? AND used_at IS NULL").run(row.id).changes === 1;
          break;
        }
      }
    } else {
      const step = totp.verify(user.totp_secret, code, { minStep: user.totp_last_step });
      if (step !== null) accepted = db.prepare('UPDATE users SET totp_last_step = ? WHERE id = ? AND totp_last_step < ?').run(step, user.id, step).changes === 1;
    }
    if (!accepted) {
      if (code || recovery) {
        auth.recordFailedAttempt(user);
        auth.recordLoginAttempt(req, { userId: user.id, email: user.email, outcome: 'google_bad_totp' });
      }
      return failure(401, 'Enter a valid authenticator or recovery code.', { totpRequired: true });
    }
  }

  if (!user) {
    const name = v.isValidName(identity.name) ? identity.name.trim() : identity.email.split('@')[0].slice(0, 100);
    // No password is assigned or exposed for Google-created guest accounts.
    // The invalid bcrypt marker ensures password login cannot authenticate them.
    const result = db.prepare("INSERT INTO users(email,name,password_hash,role) VALUES (?,?,'!google-only','guest')")
      .run(v.normalizeEmail(identity.email), name);
    user = db.prepare('SELECT * FROM users WHERE id = ?').get(result.lastInsertRowid);
  }
  if (!linked) {
    db.prepare('INSERT INTO google_identities(subject,user_id) VALUES (?,?)').run(identity.sub, user.id);
    // Remove any sessions made before the Google identity was linked.
    auth.destroyAllSessions(user.id);
  }
  db.prepare('DELETE FROM google_login_attempts WHERE nonce_hash = ?').run(nonceHash);
  auth.clearFailedAttempts(user.id);
  auth.createSession(req, res, user);
  auth.recordLoginAttempt(req, { userId: user.id, email: user.email, outcome: 'google_success' });
  res.clearCookie(cookieName, cookieOptions);
  return { status: 200, body: { user: { id: user.id, email: user.email, name: user.name, role: user.role, totpEnabled: Boolean(user.totp_enabled) } } };
});

router.post('/', limiter, (req, res, next) => {
  const nonce = req.cookies[cookieName];
  const attempt = typeof nonce === 'string' && nonce.length === 43
    ? db.prepare('SELECT portal FROM google_login_attempts WHERE nonce_hash = ?').get(digest(nonce)) : null;
  if (attempt?.portal === 'owner') return ownerLimiter(req, res, next);
  return next();
}, async (req, res, next) => {
  if (!clientId()) return res.status(503).json({ error: 'Google sign-in is not configured' });
  const nonce = req.cookies[cookieName];
  const credential = req.body?.credential;
  if (typeof nonce !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(nonce) || typeof credential !== 'string' || credential.length > 8000) {
    return res.status(401).json({ error: 'Google sign-in expired. Refresh this page and try again.' });
  }
  const nonceHash = digest(nonce);
  const attempt = db.prepare('SELECT * FROM google_login_attempts WHERE nonce_hash = ? AND expires_at > ?').get(nonceHash, Date.now());
  if (!attempt) return res.status(401).json({ error: 'Google sign-in expired. Refresh this page and try again.' });
  let identity;
  try {
    const ticket = await verifier.verifyIdToken({ idToken: credential, audience: clientId() });
    identity = ticket.getPayload();
    if (!identity || identity.nonce !== nonce || identity.email_verified !== true ||
        !v.isValidEmail(identity.email) || typeof identity.sub !== 'string' || !identity.sub || identity.sub.length > 255) {
      throw new Error('Invalid Google identity claims');
    }
  } catch {
    return res.status(401).json({ error: 'Google sign-in could not be verified. Please try again.' });
  }
  try {
    let checkedPassword;
    if (typeof req.body.password === 'string' && Buffer.byteLength(req.body.password, 'utf8') <= 72) {
      const user = db.prepare('SELECT * FROM users WHERE email = ?').get(v.normalizeEmail(identity.email));
      if (user && allowed(user, attempt.portal) && !auth.lockRemainingMs(user)) {
        checkedPassword = { userId: user.id, hash: user.password_hash, ok: await bcrypt.compare(req.body.password, user.password_hash) };
      }
    }
    const result = finish(req, res, identity, nonceHash, checkedPassword);
    return res.status(result.status).json(result.body);
  } catch (err) { return next(err); }
});

module.exports = router;
