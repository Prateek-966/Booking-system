'use strict';

import { api, showMessage, safeNextPath } from './common.js';

const portal = document.body.dataset.portal;
const home = portal === 'owner' ? '/owner.html' : '/bookings.html';
const section = document.getElementById('google-signin');
const confirmForm = document.getElementById('google-confirm');
const password = document.getElementById('google-password');
const submit = document.getElementById('google-submit');
let credential;
let busy = false;

async function signIn() {
  if (!credential || busy) return;
  busy = true;
  submit.disabled = true;
  try {
    await api('/api/auth/google', {
      method: 'POST',
      body: {
        credential,
        ...(password.value ? { password: password.value } : {}),
        totpCode: document.getElementById('google-code').value.trim(),
        recoveryCode: document.getElementById('google-recovery').value.trim(),
      },
    });
    credential = undefined;
    password.value = '';
    const next = new URLSearchParams(window.location.search).get('next');
    window.location.assign(safeNextPath(next, home));
  } catch (error) {
    showMessage(error.message);
    if (error.linkRequired || error.totpRequired) {
      confirmForm.hidden = false;
      document.getElementById('google-instructions').textContent = error.message;
      if (error.linkRequired) {
        document.getElementById('google-password-row').hidden = false;
        password.required = true;
        password.focus();
      }
      if (error.totpRequired) {
        document.getElementById('google-factor-row').hidden = false;
        document.getElementById('google-code').focus();
      }
    }
  } finally {
    busy = false;
    submit.disabled = false;
  }
}

confirmForm.addEventListener('submit', (event) => {
  event.preventDefault();
  signIn();
});

async function initialize() {
  const config = await api('/api/auth/google/config');
  if (!config.enabled) return;
  const { nonce } = await api('/api/auth/google/start', { method: 'POST', body: { portal } });
  await new Promise((resolve, reject) => {
    const script = document.createElement('script');
    script.src = 'https://accounts.google.com/gsi/client';
    script.async = true;
    script.onload = resolve;
    script.onerror = () => reject(new Error('Google sign-in could not load. You can still use your password.'));
    document.head.appendChild(script);
  });
  window.google.accounts.id.initialize({
    client_id: config.clientId,
    nonce,
    auto_select: false,
    callback(response) {
      credential = response.credential;
      confirmForm.reset();
      confirmForm.hidden = true;
      password.required = false;
      document.getElementById('google-password-row').hidden = true;
      document.getElementById('google-factor-row').hidden = true;
      showMessage('');
      signIn();
    },
  });
  window.google.accounts.id.renderButton(document.getElementById('google-button'), {
    type: 'standard', theme: 'outline', size: 'large', text: 'continue_with',
  });
  section.hidden = false;
}

initialize().catch((error) => showMessage(error.message));
