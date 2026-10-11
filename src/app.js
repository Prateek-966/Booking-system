'use strict';

const path = require('path');
const express = require('express');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const db = require('./db');
const { sessionLoader, csrfProtection, pruneExpiredSessions } = require('./auth');
const authRoutes = require('./routes/auth');
const roomRoutes = require('./routes/rooms');
const bookingRoutes = require('./routes/bookings');

const app = express();

// Do not advertise the framework.
app.disable('x-powered-by');

// On hosting platforms the app sits behind exactly one TLS-terminating proxy;
// trusting it makes Secure cookies and per-client rate limiting work correctly.
if (process.env.TRUST_PROXY === '1') {
  app.set('trust proxy', 1);
}

// Security headers, including a strict same-origin CSP (no inline scripts).
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'"],
        imgSrc: ["'self'", 'data:'],
        // Fonts are self-hosted, so no external font host is permitted —
        // tighter than Helmet's default, which allows any https origin.
        fontSrc: ["'self'"],
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'"],
        frameAncestors: ["'none'"],
      },
    },
    referrerPolicy: { policy: 'no-referrer' },
  })
);

// Health check for the hosting platform. Deliberately a dedicated endpoint
// rather than a product one: it must keep answering across refactors, and it
// sits above the rate limiter so frequent polling can never be throttled or
// eat into a real visitor's allowance.
app.get('/healthz', (req, res) => {
  try {
    // Confirms the process is up *and* the database is readable.
    db.prepare('SELECT 1').get();
    res.json({ status: 'ok' });
  } catch (err) {
    console.error('Health check failed:', err.message);
    res.status(503).json({ status: 'unavailable' });
  }
});

// Global rate limit; credential endpoints have their own tighter limit.
app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: Number(process.env.GLOBAL_RATE_LIMIT) || 500,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    message: { error: 'Too many requests, please try again later' },
  })
);

// Public assets do not need session lookups or SQLite writes on every load.
app.use(express.static(path.join(__dirname, '..', 'public')));

// Authenticated API responses contain guest and owner information. Prevent
// browsers and intermediaries from retaining it after logout.
app.use('/api', (req, res, next) => {
  res.set('Cache-Control', 'no-store');
  next();
});

// Small body limit: no JSON endpoint needs large payloads.
app.use(express.json({ limit: '10kb' }));
app.use(cookieParser());
app.use(sessionLoader);
app.use(csrfProtection);

app.use('/api/auth', authRoutes);
app.use('/api', roomRoutes);
app.use('/api', bookingRoutes);

// Unknown API routes get JSON 404s rather than the static handler's HTML.
app.use('/api', (req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// Central error handler: log details server-side, never leak them to clients.
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  if (err.type === 'entity.too.large') {
    return res.status(413).json({ error: 'That file or request is too large' });
  }
  if (err.type === 'entity.parse.failed') {
    return res.status(400).json({ error: 'Invalid request body' });
  }
  console.error(err);
  res.status(500).json({ error: 'Internal server error' });
});

// Hourly cleanup of expired sessions.
const pruneTimer = setInterval(pruneExpiredSessions, 60 * 60 * 1000);
pruneTimer.unref();

module.exports = app;
