'use strict';

// Every helper here builds DOM through textContent and setAttribute.
// innerHTML is never used anywhere in this app, so listing text written by
// owners or guests can never be interpreted as markup.

export async function api(path, options = {}) {
  const init = {
    method: options.method || 'GET',
    credentials: 'same-origin',
    headers: {},
  };
  if (options.body !== undefined) {
    init.headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(options.body);
  }
  if (options.raw !== undefined) {
    init.headers['Content-Type'] = options.raw.type;
    init.body = options.raw;
  }
  const res = await fetch(path, init);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    // Carry the response fields on the error so callers can react to flags
    // such as totpRequired without re-parsing the body.
    const error = new Error(data.error || `Request failed (${res.status})`);
    Object.assign(error, data, { status: res.status });
    throw error;
  }
  return data;
}

// el('div', { className: 'card' }, 'text', childNode)
export function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (value === undefined || value === null || value === false) continue;
    if (key === 'className' || key === 'textContent' || key === 'value' || key === 'type') {
      node[key] = value;
    } else if (key === 'onClick') {
      node.addEventListener('click', value);
    } else if (key === 'onSubmit') {
      node.addEventListener('submit', value);
    } else if (key === 'onChange') {
      node.addEventListener('change', value);
    } else {
      node.setAttribute(key, value === true ? '' : String(value));
    }
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

const currencyFormatter = new Intl.NumberFormat('en-IN', {
  style: 'currency',
  currency: 'INR',
  maximumFractionDigits: 0,
});

export function money(amount) {
  return currencyFormatter.format(amount);
}

// Resolve with the same URL parser the browser uses before allowing a login
// redirect. Backslashes and embedded tabs/newlines can turn a seemingly local
// path into a network-path reference to another origin.
export function safeNextPath(next, fallback, origin = window.location.origin) {
  if (typeof next !== 'string' || !next.startsWith('/') || next.startsWith('//')) {
    return fallback;
  }
  try {
    const target = new URL(next, origin);
    if (target.origin !== origin || target.username || target.password) return fallback;
    // Keep the absolute same-origin URL: normalization may leave a pathname
    // beginning with //, which would be external if assigned on its own.
    return target.href;
  } catch {
    return fallback;
  }
}

export function formatDate(iso) {
  return new Date(`${iso}T00:00:00Z`).toLocaleDateString(undefined, {
    day: 'numeric',
    month: 'short',
    year: 'numeric',
    timeZone: 'UTC',
  });
}

export function nightsBetween(checkIn, checkOut) {
  return (Date.parse(`${checkOut}T00:00:00Z`) - Date.parse(`${checkIn}T00:00:00Z`)) / 86400000;
}

export function todayIso() {
  return new Date().toISOString().slice(0, 10);
}

export function showMessage(text, kind = 'error') {
  const box = document.getElementById('message');
  if (!box) return;
  box.textContent = text || '';
  box.className = kind;
  box.hidden = !text;
  if (text) box.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
}

export async function fetchUser() {
  try {
    const { user } = await api('/api/auth/me');
    return user;
  } catch {
    return null;
  }
}

async function signOut() {
  try {
    await api('/api/auth/logout', { method: 'POST', body: {} });
  } catch {
    /* session may already be gone — send them home regardless */
  }
  window.location.href = '/';
}

// The links and actions a given user should see, as plain descriptors so the
// pill, the inline actions and the mobile drawer all stay in step.
function navEntries(user) {
  if (!user) {
    return [
      { label: 'Owner', href: '/owner-login.html' },
      { label: 'Sign in to book', href: '/login.html', primary: true },
    ];
  }
  const home = user.role === 'guest'
    ? { label: 'My trips', href: '/bookings.html' }
    : { label: 'Dashboard', href: '/owner.html' };
  return [home, { label: 'Sign out', onClick: signOut }];
}

function entryNode(entry, className) {
  if (entry.onClick) {
    return el('button', { type: 'button', className, onClick: entry.onClick }, entry.label);
  }
  return el('a', { href: entry.href, className }, entry.label);
}

// Renders the header navigation, plus a mobile drawer holding the same items.
export function mountNav(user, sectionLinks = []) {
  const nav = document.getElementById('nav');
  if (!nav) return;

  const entries = navEntries(user);

  // Desktop pill: in-page section links plus the primary action.
  const pill = document.getElementById('nav-pill');
  if (pill && sectionLinks.length > 0) {
    pill.replaceChildren(
      ...sectionLinks.map((link, i) =>
        el('a', { href: link.href, className: i === 0 ? 'current' : '' }, link.label)
      ),
      entryNode(entries.find((e) => e.primary) ?? entries.at(-1), 'nav-btn')
    );
  }

  // Inline actions. The primary button is marked so CSS can hide it on wide
  // screens, where the pill already carries it.
  nav.replaceChildren(
    ...(user ? [el('span', { className: 'nav-user' }, user.name)] : []),
    ...entries.map((e) =>
      entryNode(e, e.primary && pill ? 'nav-btn in-actions' : e.primary ? 'nav-btn' : 'nav-link')
    ),
    el(
      'button',
      {
        className: 'menu-btn',
        type: 'button',
         'aria-label': 'Menu',
        'aria-expanded': 'false',
        onClick: toggleDrawer,
      },
      el('span', {}),
      el('span', {}),
      el('span', {})
    )
  );

  mountDrawer(sectionLinks, entries);
}

function toggleDrawer() {
  const open = document.body.classList.toggle('menu-open');
  document.body.style.overflow = open ? 'hidden' : '';
  const button = document.querySelector('.menu-btn');
  if (button) button.setAttribute('aria-expanded', String(open));
}

function closeDrawer() {
  document.body.classList.remove('menu-open');
  document.body.style.overflow = '';
  const button = document.querySelector('.menu-btn');
  if (button) button.setAttribute('aria-expanded', 'false');
}

function mountDrawer(sectionLinks, entries) {
  document.querySelectorAll('.drawer, .drawer-scrim').forEach((n) => n.remove());

  const scrim = el('div', { className: 'drawer-scrim', onClick: closeDrawer });
  const drawer = el(
    'div',
    { className: 'drawer' },
    ...sectionLinks.map((link) =>
      el('a', { href: link.href, onClick: closeDrawer }, link.label)
    ),
    ...entries.map((e) =>
      e.onClick
        ? el('button', { type: 'button', onClick: e.onClick }, e.label)
        : el('a', { href: e.href, onClick: closeDrawer }, e.label)
    )
  );

  document.body.append(scrim, drawer);

  // Escape closes it, which keyboard users expect.
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeDrawer();
  });
}

// Standard page bootstrap: resolve the user, draw the nav, hand it back.
export async function initPage(sectionLinks = []) {
  const user = await fetchUser();
  mountNav(user, sectionLinks);
  return user;
}
