'use strict';

const crypto = require('crypto');
const db = require('./db');

// Guests get a long, convenient session. The owner account holds the keys to
// the whole guesthouse, so its sessions are deliberately short-lived and
// expire both on inactivity and in absolute terms.
const GUEST_IDLE_MS = 7 * 24 * 60 * 60 * 1000; // 7 days
const GUEST_ABSOLUTE_MS = 30 * 24 * 60 * 60 * 1000; // 30 days
const OWNER_IDLE_MS = 2 * 60 * 60 * 1000; // 2 hours
const OWNER_ABSOLUTE_MS = 12 * 60 * 60 * 1000; // 12 hours

// Brute-force protection per account, on top of the per-IP rate limit (which
// a rotating-IP attacker can sidestep). Locks are always temporary, so an
// attacker cannot permanently deny the owner access to their own account.
const MAX_FAILED_ATTEMPTS = 5;
const BASE_LOCK_MS = 15 * 60 * 1000;
const MAX_LOCK_MS = 6 * 60 * 60 * 1000;

const PRIVILEGED_ROLES = ['owner', 'admin'];

// The __Host- prefix makes browsers refuse the cookie unless it is Secure,
// Path=/ and has no Domain — it cannot be overwritten by a subdomain.
const COOKIE_NAME = process.env.NODE_ENV === 'production' ? '__Host-session' : 'session';

function isPrivileged(role) {
  return PRIVILEGED_ROLES.includes(role);
}

// Session tokens are stored only as SHA-256 hashes so that a leaked database
// does not allow session hijacking.
function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

function clientIp(req) {
  return String(req.ip || req.socket?.remoteAddress || '').slice(0, 45);
}

function clientAgent(req) {
  return String(req.headers['user-agent'] || '').slice(0, 200);
}

function cookieOptions(maxAge) {
  return {
    httpOnly: true,
    sameSite: 'strict',
    secure: process.env.NODE_ENV === 'production',
    maxAge,
    path: '/',
  };
}

function createSession(req, res, user) {
  const privileged = isPrivileged(user.role);
  const idleMs = privileged ? OWNER_IDLE_MS : GUEST_IDLE_MS;
  const absoluteMs = privileged ? OWNER_ABSOLUTE_MS : GUEST_ABSOLUTE_MS;

  const token = crypto.randomBytes(32).toString('base64url');
  const now = Date.now();
  db.prepare(
    `INSERT INTO sessions
       (token_hash, user_id, expires_at, absolute_expires_at, last_seen_at, ip, user_agent)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).run(hashToken(token), user.id, now + idleMs, now + absoluteMs, now, clientIp(req), clientAgent(req));

  res.cookie(COOKIE_NAME, token, cookieOptions(idleMs));
}

function destroySession(req, res) {
  const token = req.cookies[COOKIE_NAME];
  if (token) {
    db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(hashToken(token));
  }
  const { maxAge, ...clearOptions } = cookieOptions(0);
  res.clearCookie(COOKIE_NAME, clearOptions);
}

// Invalidate every session for a user (used after a password change, a
// two-factor change, or an explicit "sign out everywhere").
function destroyAllSessions(userId) {
  db.prepare('DELETE FROM sessions WHERE user_id = ?').run(userId);
}

function destroyOtherSessions(userId, currentToken) {
  if (!currentToken) {
    destroyAllSessions(userId);
    return;
  }
  db.prepare('DELETE FROM sessions WHERE user_id = ? AND token_hash != ?').run(
    userId,
    hashToken(currentToken)
  );
}

function listSessions(userId, currentToken) {
  const currentHash = currentToken ? hashToken(currentToken) : '';
  return db
    .prepare(
      `SELECT token_hash, ip, user_agent, created_at, last_seen_at, expires_at
         FROM sessions WHERE user_id = ? ORDER BY last_seen_at DESC`
    )
    .all(userId)
    .map((s) => ({
      id: s.token_hash.slice(0, 12),
      ip: s.ip,
      userAgent: s.user_agent,
      createdAt: s.created_at,
      lastSeenAt: s.last_seen_at,
      current: s.token_hash === currentHash,
    }));
}

function revokeSessionById(userId, shortId) {
  if (typeof shortId !== 'string' || !/^[0-9a-f]{12}$/.test(shortId)) {
    return 0;
  }
  // Scoped to the caller's own user id, so one account can never revoke
  // another account's sessions.
  const match = db
    .prepare('SELECT token_hash FROM sessions WHERE user_id = ? AND substr(token_hash, 1, 12) = ?')
    .get(userId, shortId);
  if (!match) return 0;
  return db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(match.token_hash).changes;
}

// Populates req.user when a valid, unexpired session cookie is present, and
// slides the idle window forward without ever exceeding the absolute deadline.
function sessionLoader(req, res, next) {
  req.user = null;
  req.sessionToken = null;
  const token = req.cookies[COOKIE_NAME];

  if (typeof token === 'string' && token.length > 0 && token.length <= 128) {
    const tokenHash = hashToken(token);
    const row = db
      .prepare(
        `SELECT u.id, u.email, u.name, u.role, u.totp_enabled,
                s.expires_at, s.absolute_expires_at
           FROM sessions s JOIN users u ON u.id = s.user_id
          WHERE s.token_hash = ?`
      )
      .get(tokenHash);

    if (row) {
      const now = Date.now();
      const idleExpired = row.expires_at <= now;
      const absoluteExpired = row.absolute_expires_at > 0 && row.absolute_expires_at <= now;

      if (idleExpired || absoluteExpired) {
        db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(tokenHash);
      } else {
        req.user = {
          id: row.id,
          email: row.email,
          name: row.name,
          role: row.role,
          totpEnabled: Boolean(row.totp_enabled),
        };
        req.sessionToken = token;

        const idleMs = isPrivileged(row.role) ? OWNER_IDLE_MS : GUEST_IDLE_MS;
        const nextIdle = row.absolute_expires_at > 0
          ? Math.min(now + idleMs, row.absolute_expires_at)
          : now + idleMs;
        db.prepare('UPDATE sessions SET expires_at = ?, last_seen_at = ? WHERE token_hash = ?')
          .run(nextIdle, now, tokenHash);
      }
    }
  }
  next();
}

function requireAuth(req, res, next) {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  next();
}

// Role gate. Admins are not granted every role implicitly — each route lists
// exactly which roles may reach it.
function requireRole(...roles) {
  return function roleGuard(req, res, next) {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'You do not have access to this area' });
    }
    next();
  };
}

const requireAdmin = requireRole('admin');
const requireOwner = requireRole('owner', 'admin');
const requireGuest = requireRole('guest');

// CSRF defence in depth: the session cookie is SameSite=Strict, and every
// state-changing request must additionally arrive from our own origin.
function csrfProtection(req, res, next) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    return next();
  }
  if (req.headers['sec-fetch-site'] === 'cross-site') {
    return res.status(403).json({ error: 'Cross-origin request rejected' });
  }
  const origin = req.headers.origin || req.headers.referer;
  if (origin) {
    let requestOrigin;
    try {
      requestOrigin = new URL(origin).origin;
    } catch {
      return res.status(403).json({ error: 'Invalid origin' });
    }
    if (requestOrigin !== `${req.protocol}://${req.headers.host}`) {
      return res.status(403).json({ error: 'Cross-origin request rejected' });
    }
  }
  next();
}

// --- Account lockout ---

function lockRemainingMs(user, now = Date.now()) {
  return user.locked_until > now ? user.locked_until - now : 0;
}

const recordFailure = db.transaction((userId) => {
  // Requests can finish their asynchronous password checks concurrently.
  // Increment the stored count instead of using a pre-comparison snapshot.
  const row = db.prepare(
    'UPDATE users SET failed_attempts = failed_attempts + 1 WHERE id = ? RETURNING failed_attempts'
  ).get(userId);
  if (!row) return 0;
  const attempts = row.failed_attempts;
  let lockedUntil = 0;
  if (attempts >= MAX_FAILED_ATTEMPTS) {
    // Each failure past the threshold doubles the wait, up to the cap.
    const overshoot = attempts - MAX_FAILED_ATTEMPTS;
    const lockMs = Math.min(BASE_LOCK_MS * 2 ** overshoot, MAX_LOCK_MS);
    lockedUntil = Date.now() + lockMs;
  }
  db.prepare('UPDATE users SET locked_until = ? WHERE id = ?').run(lockedUntil, userId);
  return lockedUntil;
});

function recordFailedAttempt(user) {
  return recordFailure(user.id);
}

function clearFailedAttempts(userId) {
  db.prepare(
    "UPDATE users SET failed_attempts = 0, locked_until = 0, last_login_at = datetime('now') WHERE id = ?"
  ).run(userId);
}

// --- Login audit ---

function recordLoginAttempt(req, { userId = null, email = '', outcome }) {
  db.prepare(
    'INSERT INTO login_audit (user_id, email, ip, user_agent, outcome) VALUES (?, ?, ?, ?, ?)'
  ).run(userId, String(email).slice(0, 254), clientIp(req), clientAgent(req), outcome);
}

function recentLoginAttempts(userId, limit = 20) {
  return db
    .prepare(
      `SELECT ip, user_agent AS userAgent, outcome, created_at AS createdAt
         FROM login_audit WHERE user_id = ? ORDER BY id DESC LIMIT ?`
    )
    .all(userId, limit);
}

// Opportunistically purge expired sessions and stale audit rows.
function pruneExpiredSessions() {
  const now = Date.now();
  db.prepare('DELETE FROM sessions WHERE expires_at <= ? OR (absolute_expires_at > 0 AND absolute_expires_at <= ?)')
    .run(now, now);
  db.prepare("DELETE FROM login_audit WHERE created_at < datetime('now', '-90 days')").run();
}

module.exports = {
  COOKIE_NAME,
  MAX_FAILED_ATTEMPTS,
  isPrivileged,
  createSession,
  destroySession,
  destroyAllSessions,
  destroyOtherSessions,
  listSessions,
  revokeSessionById,
  sessionLoader,
  requireAuth,
  requireRole,
  requireAdmin,
  requireOwner,
  requireGuest,
  csrfProtection,
  lockRemainingMs,
  recordFailedAttempt,
  clearFailedAttempts,
  recordLoginAttempt,
  recentLoginAttempts,
  pruneExpiredSessions,
};
