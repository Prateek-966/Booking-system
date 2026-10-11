'use strict';

// Booking notifications.
//
// Every message is recorded in the database *before* delivery is attempted,
// so a booking request is never lost because email or SMS is unconfigured or
// the provider is down — the owner dashboard reads from that same table.
// Delivery is best-effort and never blocks or fails a booking.
//
// Transports activate purely from environment variables:
//   email       SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM
//   whatsapp    WHATSAPP_TOKEN, WHATSAPP_PHONE_NUMBER_ID
//               plus WHATSAPP_TEMPLATE_NAME for business-initiated messages
//               (Meta only allows free-form text within 24h of the recipient
//               messaging you; outside that window a template is required)
// With nothing configured, messages stay queued as 'skipped' and remain
// visible in the dashboard.

const db = require('./db');
const { isValidEmail } = require('./validators');

const GRAPH_VERSION = process.env.WHATSAPP_API_VERSION || 'v21.0';

const emailConfigured = () =>
  Boolean(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS);

const whatsappConfigured = () =>
  Boolean(process.env.WHATSAPP_TOKEN && process.env.WHATSAPP_PHONE_NUMBER_ID);

function record({ bookingId = null, channel, recipient = '', subject = '', body = '' }) {
  const status = channel === 'inapp' ? 'sent' : 'queued';
  return db
    .prepare(
      `INSERT INTO notifications (booking_id, channel, recipient, subject, body, status)
       VALUES (?, ?, ?, ?, ?, ?)`
    )
    .run(bookingId, channel, recipient, subject, body, status).lastInsertRowid;
}

function markSent(id) {
  db.prepare("UPDATE notifications SET status = 'sent' WHERE id = ?").run(id);
}

function markSkipped(id, reason) {
  db.prepare("UPDATE notifications SET status = 'skipped', detail = ? WHERE id = ?").run(reason, id);
}

function markFailed(id, reason) {
  db.prepare("UPDATE notifications SET status = 'failed', detail = ? WHERE id = ?")
    .run(String(reason).slice(0, 500), id);
}

async function deliverEmail(id, { to, subject, body }) {
  if (!to) return markSkipped(id, 'no recipient address configured');
  if (!isValidEmail(to)) return markFailed(id, 'invalid recipient address');
  if (!emailConfigured()) return markSkipped(id, 'SMTP is not configured');
  try {
    // Required lazily so the app runs fine when email is not in use.
    const nodemailer = require('nodemailer');
    const host = process.env.SMTP_HOST;
    const localRelay = ['localhost', '127.0.0.1', '::1', '[::1]'].includes(host.toLowerCase());
    const transport = nodemailer.createTransport({
      host,
      port: Number(process.env.SMTP_PORT) || 587,
      secure: Number(process.env.SMTP_PORT) === 465,
      // Remote relays must support TLS before credentials or guest details
      // are sent. An explicitly local relay may use plain loopback SMTP.
      requireTLS: !localRelay,
      connectionTimeout: 10_000,
      greetingTimeout: 10_000,
      socketTimeout: 20_000,
      auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
    });
    await transport.sendMail({
      from: process.env.SMTP_FROM || process.env.SMTP_USER,
      // Use a structured mailbox so even legacy stored input is never
      // interpreted as multiple recipients or a display-name expression.
      to: { address: to },
      subject,
      text: body,
    });
    markSent(id);
  } catch (err) {
    markFailed(id, err.message);
  }
}

// Meta requires international format with no '+' and no leading zeros.
function normalizeWhatsAppNumber(value) {
  return String(value).replace(/[^\d]/g, '').replace(/^0+/, '');
}

async function deliverWhatsApp(id, { to, body, templateParams }) {
  const number = normalizeWhatsAppNumber(to || '');
  if (!number) return markSkipped(id, 'no recipient number configured');
  if (!whatsappConfigured()) return markSkipped(id, 'WhatsApp Cloud API is not configured');

  const template = process.env.WHATSAPP_TEMPLATE_NAME;
  // A booking request is business-initiated, so an approved template is the
  // only reliable way to reach the owner. Plain text is the fallback and only
  // lands inside Meta's 24-hour customer-service window.
  const payload = template
    ? {
        messaging_product: 'whatsapp',
        to: number,
        type: 'template',
        template: {
          name: template,
          language: { code: process.env.WHATSAPP_TEMPLATE_LANG || 'en' },
          components: [
            {
              type: 'body',
              parameters: templateParams.map((text) => ({ type: 'text', text: String(text) })),
            },
          ],
        },
      }
    : { messaging_product: 'whatsapp', to: number, type: 'text', text: { body } };

  try {
    const res = await fetch(
      `https://graph.facebook.com/${GRAPH_VERSION}/${process.env.WHATSAPP_PHONE_NUMBER_ID}/messages`,
      {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${process.env.WHATSAPP_TOKEN}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(15_000),
        redirect: 'error',
      }
    );
    if (!res.ok) {
      const detail = await res.text().catch(() => '');
      throw new Error(`WhatsApp API returned ${res.status}: ${detail.slice(0, 200)}`);
    }
    markSent(id);
  } catch (err) {
    markFailed(id, err.message);
  }
}

function ownerContacts() {
  const property = db
    .prepare('SELECT contact_email, contact_phone FROM property WHERE id = 1')
    .get() ?? {};
  return {
    email: process.env.NOTIFY_EMAIL || property.contact_email || '',
    phone: process.env.NOTIFY_PHONE || property.contact_phone || '',
  };
}

function money(amount) {
  return `INR ${Number(amount).toLocaleString('en-IN')}`;
}

// Fire-and-forget: the returned promise is not awaited by request handlers, so
// a slow or broken provider can never delay or fail a guest's booking.
async function notifyOwnerOfRequest(booking) {
  const { email, phone } = ownerContacts();
  const subject = `Booking request: ${booking.room} — ${booking.checkIn} to ${booking.checkOut}`;
  const body =
    `${booking.guestName} has requested ${booking.room}.\n\n` +
    `Dates: ${booking.checkIn} to ${booking.checkOut} (${booking.nights} night(s))\n` +
    `Guests: ${booking.guests}\n` +
    `Total: ${money(booking.totalPrice)}\n` +
    `Guest contact: ${booking.guestEmail}${booking.guestPhone ? ` / ${booking.guestPhone}` : ''}\n` +
    (booking.guestNote ? `Message: ${booking.guestNote}\n` : '') +
    `\nApprove or decline it in your dashboard.`;

  record({ bookingId: booking.id, channel: 'inapp', subject, body });

  const emailId = record({ bookingId: booking.id, channel: 'email', recipient: email, subject, body });

  const waBody =
    `Booking request: ${booking.room}, ${booking.checkIn} to ${booking.checkOut}, ` +
    `${booking.guests} guest(s), ${money(booking.totalPrice)}. From ${booking.guestName}. ` +
    `Approve in your dashboard.`;
  const waId = record({ bookingId: booking.id, channel: 'whatsapp', recipient: phone, subject, body: waBody });

  return Promise.allSettled([
    deliverEmail(emailId, { to: email, subject, body }),
    deliverWhatsApp(waId, {
      to: phone,
      body: waBody,
      // Order must match the {{1}}..{{5}} placeholders in the approved template.
      templateParams: [
        booking.guestName,
        booking.room,
        booking.checkIn,
        booking.checkOut,
        money(booking.totalPrice),
      ],
    }),
  ]);
}

async function notifyGuestOfDecision(booking, approved) {
  const subject = approved
    ? `Booking confirmed: ${booking.room}`
    : `Booking request declined: ${booking.room}`;
  const body = approved
    ? `Good news — your stay in ${booking.room} from ${booking.checkIn} to ${booking.checkOut} is confirmed.\n` +
      `Total: ${money(booking.totalPrice)}\n` +
      (booking.ownerNote ? `\nFrom your host: ${booking.ownerNote}\n` : '')
    : `Your request for ${booking.room} from ${booking.checkIn} to ${booking.checkOut} was not accepted.\n` +
      (booking.ownerNote ? `\nFrom the host: ${booking.ownerNote}\n` : '');

  const emailId = record({
    bookingId: booking.id,
    channel: 'email',
    recipient: booking.guestEmail,
    subject,
    body,
  });
  return deliverEmail(emailId, { to: booking.guestEmail, subject, body });
}

function listForOwner(limit = 50) {
  return db
    .prepare(
      `SELECT id, booking_id AS bookingId, channel, recipient, subject, body,
              status, detail, read_at AS readAt, created_at AS createdAt
         FROM notifications ORDER BY id DESC LIMIT ?`
    )
    .all(limit);
}

function transportStatus() {
  return {
    email: emailConfigured(),
    whatsapp: whatsappConfigured(),
    whatsappTemplate: Boolean(process.env.WHATSAPP_TEMPLATE_NAME),
  };
}

module.exports = {
  notifyOwnerOfRequest,
  notifyGuestOfDecision,
  listForOwner,
  transportStatus,
};
