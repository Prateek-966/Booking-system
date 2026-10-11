'use strict';

import { api, showMessage, initPage, safeNextPath } from './common.js';

const portal = document.body.dataset.portal; // 'guest' or 'owner'
const isOwnerPortal = portal === 'owner';
const home = isOwnerPortal ? '/owner.html' : '/bookings.html';

let registering = false;

// Guests can self-register; the owner account never can.
function setMode(toRegistering) {
  registering = toRegistering;
  document.getElementById('auth-title').textContent = registering ? 'Create a guest account' : 'Sign in to book';
  document.getElementById('submit').textContent = registering ? 'Create account' : 'Sign in';
  document.getElementById('toggle').textContent = registering ? 'Sign in instead' : 'Create a guest account';
  document.getElementById('toggle-text').textContent = registering ? 'Already registered?' : 'New here?';
  document.getElementById('name-row').hidden = !registering;
  document.getElementById('phone-row').hidden = !registering;
  document.getElementById('name').required = registering;
  document.getElementById('password').autocomplete = registering ? 'new-password' : 'current-password';
  showMessage('');
}

if (!isOwnerPortal) {
  document.getElementById('toggle').addEventListener('click', () => setMode(!registering));
  setMode(false);
} else {
  document.getElementById('use-recovery').addEventListener('click', () => {
    const row = document.getElementById('recovery-row');
    row.hidden = !row.hidden;
    document.getElementById('totpCode').required = row.hidden;
  });
}

document.getElementById('auth-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const email = document.getElementById('email').value;
  const password = document.getElementById('password').value;

  try {
    if (registering) {
      await api('/api/auth/register', {
        method: 'POST',
        body: {
          email,
          password,
          name: document.getElementById('name').value,
          phone: document.getElementById('phone').value,
        },
      });
    } else {
      const body = { email, password, portal };
      if (isOwnerPortal) {
        const code = document.getElementById('totpCode').value.trim();
        const recovery = document.getElementById('recoveryCode').value.trim();
        if (code) body.totpCode = code;
        if (recovery) body.recoveryCode = recovery;
      }
      await api('/api/auth/login', { method: 'POST', body });
    }
    const next = new URLSearchParams(window.location.search).get('next');
    window.location.href = safeNextPath(next, home);
  } catch (err) {
    // A second factor is needed: reveal the code field rather than treating
    // this as a failure.
    if (isOwnerPortal && err.totpRequired) {
      document.getElementById('totp-row').hidden = false;
      document.getElementById('totpCode').focus();
    }
    showMessage(err.message);
  }
});

initPage().then((user) => {
  if (user) {
    window.location.replace(user.role === 'guest' ? '/bookings.html' : '/owner.html');
  }
});
