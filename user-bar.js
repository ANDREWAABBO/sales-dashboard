/*!
  userbar.js — injects "👤 username" + "Logout" into the black top bar
  Requires password.js (for Auth/logout). Load AFTER password.js:
  <script defer src="password.js"></script>
  <script defer src="userbar.js?v=1"></script>
*/
(function () {
  'use strict';

  const HOST_SELECTOR = '.company-switcher'; // the black top bar
  const BAR_ID = 'userbar';

  function isGuestView() {
    const sp = new URLSearchParams(location.search);
    return sp.has('token') || sp.has('resetToken'); // hide on guest/token/reset pages
  }

  function isAuthed() {
    return (
      sessionStorage.getItem('dashboardAuth') === 'true' &&
      !!sessionStorage.getItem('dashboardUser')
    );
  }

  // Remove any legacy header-based logout UI that password.js might add
  function removeLegacyHeaderButtons() {
    try {
      document.querySelectorAll('.header .logout-container').forEach(el => el.remove());
    } catch (_) {}
  }

  function injectUserbar() {
    if (document.getElementById(BAR_ID)) return;
    const host = document.querySelector(HOST_SELECTOR);
    if (!host) return; // only place it when the black bar exists

    const user = sessionStorage.getItem('dashboardUser') || 'User';
    const email = sessionStorage.getItem('userEmail') || '';
    const company = sessionStorage.getItem('userCompany') || '';

    const wrap = document.createElement('div');
    wrap.id = BAR_ID;
    wrap.style.cssText = [
      'position:absolute',
      'right:20px',
      'top:50%',
      'transform:translateY(-50%)',
      'display:flex',
      'gap:12px',
      'align-items:center'
    ].join(';');

    const userBtn = document.createElement('button');
    userBtn.type = 'button';
    userBtn.textContent = '👤 ' + user;
    userBtn.title = 'View profile';
    userBtn.style.cssText = [
      'background:rgba(255,255,255,0.1)',
      'border:2px solid rgba(255,255,255,0.2)',
      'color:#fff',
      'padding:8px 14px',
      'border-radius:999px',
      'cursor:pointer',
      'font-weight:600',
      'font-size:16px'
    ].join(';');
    userBtn.onclick = () => {
      alert(`Profile: ${user}\nEmail: ${email}\nCompany: ${company}`);
    };

    const logoutBtn = document.createElement('button');
    logoutBtn.type = 'button';
    logoutBtn.textContent = 'Logout';
    logoutBtn.style.cssText = [
      'background:#fff',
      'color:#111',
      'border:2px solid rgba(255,255,255,0.3)',
      'padding:8px 14px',
      'border-radius:999px',
      'cursor:pointer',
      'font-weight:700'
    ].join(';');
    logoutBtn.onclick = () => {
      try {
        if (window.logout) return window.logout();
        if (window.Auth && Auth.logout) return Auth.logout();
      } catch (_) {}
      // fallback
      sessionStorage.clear();
      location.reload();
    };

    wrap.appendChild(userBtn);
    wrap.appendChild(logoutBtn);
    host.appendChild(wrap);
  }

  function maybeRender() {
    removeLegacyHeaderButtons();
    if (isGuestView()) return; // never show for guest/token views
    if (isAuthed()) injectUserbar();
  }

  document.addEventListener('DOMContentLoaded', () => {
    // initial attempt
    maybeRender();

    // If user logs in after page load, poll briefly to render once authenticated
    let tries = 0;
    const iv = setInterval(() => {
      if (document.getElementById(BAR_ID)) { clearInterval(iv); return; }
      if (isGuestView()) { clearInterval(iv); return; }
      if (isAuthed()) { injectUserbar(); clearInterval(iv); return; }
      if (++tries > 120) clearInterval(iv); // stop after ~60s
    }, 500);
  });
})();
