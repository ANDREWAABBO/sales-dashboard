// password.js — auth/login/register/forgot/reset + user menu (username + logout)
// Safe to include on any page. Auto-initializes on DOMContentLoaded.

(function (global) {
  'use strict';

  // --- Config --------------------------------------------------------------
  const CFG = {
    USER_MANAGEMENT_URL:
      (global.AUTH_CONFIG && global.AUTH_CONFIG.USER_MANAGEMENT_URL) ||
      'https://script.google.com/macros/s/AKfycbx76lEJH6uwQuaLQ_ML0IfHnS4G3saXlF-Lz7G8vKbWrUT1IMa7BZtCz9ZiqX7tIava/exec',
    SHOW_RESET_TOKEN_FOR_TESTING:
      (global.AUTH_CONFIG && !!global.AUTH_CONFIG.SHOW_RESET_TOKEN_FOR_TESTING) || false,
  };

  // --- Validation ----------------------------------------------------------
  const PASSWORD_COMPLEXITY = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\w\s]).{8,}$/;

  // --- Private helpers -----------------------------------------------------
  function showMessage(message, type) {
    const toast = document.createElement('div');
    toast.style.cssText = `
      position: fixed; top: 20px; right: 20px; z-index: 100000;
      padding: 15px 25px; border-radius: 10px; color: white; font-weight: 600;
      background: ${type === 'success' ? '#059669' : '#dc3545'};
      box-shadow: 0 4px 20px rgba(0,0,0,0.3); animation: slideIn 0.3s ease;
    `;
    toast.textContent = message;
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 3000);
  }

  function showError(message) {
    const errorDiv = document.getElementById('authError');
    const successDiv = document.getElementById('authSuccess');
    if (!errorDiv || !successDiv) return showMessage(message, 'error');
    successDiv.style.display = 'none';
    errorDiv.textContent = message;
    errorDiv.style.display = 'block';
    const modal = document.getElementById('loginModal');
    if (modal) {
      modal.style.animation = 'shake 0.5s';
      setTimeout(() => (modal.style.animation = ''), 500);
    }
  }

  function showSuccess(message) {
    const errorDiv = document.getElementById('authError');
    const successDiv = document.getElementById('authSuccess');
    if (!errorDiv || !successDiv) return showMessage(message, 'success');
    errorDiv.style.display = 'none';
    successDiv.textContent = message;
    successDiv.style.display = 'block';
  }

  function injectKeyframeCSS() {
    if (document.getElementById('authKeyframesCSS')) return;
    const css = document.createElement('style');
    css.id = 'authKeyframesCSS';
    css.textContent = `
      @keyframes shake { 0%,100%{transform:translateX(0)}
        10%,30%,50%,70%,90%{transform:translateX(-5px)}
        20%,40%,60%,80%{transform:translateX(5px)} }
      @keyframes slideIn { from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; } }
    `;
    document.head.appendChild(css);
  }

  // --- UI builders ---------------------------------------------------------
  function showLoginForm() {
    injectKeyframeCSS();

    const existing = document.getElementById('loginOverlay');
    if (existing) return false;

    const loginOverlay = document.createElement('div');
    loginOverlay.id = 'loginOverlay';
    loginOverlay.style.cssText = `
      position: fixed; inset: 0; background: rgba(0,0,0,0.8);
      display: flex; justify-content: center; align-items: center;
      z-index: 99999; backdrop-filter: blur(5px);
    `;

    const loginModal = document.createElement('div');
    loginModal.id = 'loginModal';
    loginModal.style.cssText = `
      background: white; padding: 40px; border-radius: 20px;
      box-shadow: 0 20px 60px rgba(0,0,0,0.3); max-width: 450px;
      width: 90%; text-align: center;
    `;

    loginModal.innerHTML = buildLoginViewHTML();

    loginOverlay.appendChild(loginModal);
    document.body.appendChild(loginOverlay);

    // Prevent backdrop-close for this overlay (protect against page-level handlers)
    loginOverlay.addEventListener('click', (e) => {
      if (e.target === loginOverlay) e.stopPropagation();
    });

    // Hooks for the default login view
    wireLoginViewHandlers();

    setTimeout(() => document.getElementById('loginUsername')?.focus(), 50);
    return false;
  }

  function buildLoginViewHTML() {
    return `
      <div style="margin-bottom: 30px;">
        <h2 style="color:#1e3a8a;margin-bottom:10px;font-size:1.8em;">Dashboard Access</h2>
        <p style="color:#64748b;font-size:1.1em;">Login or create a new account</p>
      </div>

      <!-- Login Form -->
      <div id="loginFormContainer">
        <form id="loginForm" style="margin-bottom:10px;">
          <input type="text" id="loginUsername" placeholder="Username or Email" required
                 style="width:100%;padding:15px;border:2px solid #e2e8f0;border-radius:10px;font-size:1.1em;margin-bottom:15px;">
          <input type="password" id="loginPassword" placeholder="Password" required
                 style="width:100%;padding:15px;border:2px solid #e2e8f0;border-radius:10px;font-size:1.1em;margin-bottom:15px;">
          <button type="submit" style="width:100%;padding:15px;background:#1e3a8a;color:#fff;border:none;border-radius:10px;font-size:1.1em;font-weight:600;cursor:pointer;margin-bottom:8px;">
            Login
          </button>
        </form>

        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:18px;">
          <button class="link-btn" id="forgotLink" style="background:transparent;border:none;color:#1e3a8a;font-weight:600;cursor:pointer;padding:8px 0;">Forgot password?</button>
          <button class="link-btn" id="showRegisterBtn" style="background:transparent;border:none;color:#1e3a8a;font-weight:600;cursor:pointer;padding:8px 0;">Create account</button>
        </div>
      </div>

      <!-- Registration Form (hidden initially) -->
      <div id="registerFormContainer" style="display:none;">
        <form id="registerForm">
          <input type="text" id="regUsername" placeholder="Choose Username" required
                 style="width:100%;padding:15px;border:2px solid #e2e8f0;border-radius:10px;font-size:1.1em;margin-bottom:15px;">
          <input type="email" id="regEmail" placeholder="Email Address" required
                 style="width:100%;padding:15px;border:2px solid #e2e8f0;border-radius:10px;font-size:1.1em;margin-bottom:15px;">
          <input type="password" id="regPassword" placeholder="Choose Password (8+ chars, upper/lower/number/special)" required
                 style="width:100%;padding:15px;border:2px solid #e2e8f0;border-radius:10px;font-size:1.1em;margin-bottom:15px;">
          <input type="password" id="regConfirmPassword" placeholder="Confirm Password" required
                 style="width:100%;padding:15px;border:2px solid #e2e8f0;border-radius:10px;font-size:1.1em;margin-bottom:15px;">
          <input type="text" id="regCompany" placeholder="Company Name" required
                 style="width:100%;padding:15px;border:2px solid #e2e8f0;border-radius:10px;font-size:1.1em;margin-bottom:20px;">

          <button type="submit" style="width:100%;padding:15px;background:#059669;color:white;border:none;border-radius:10px;font-size:1.1em;font-weight:600;cursor:pointer;margin-bottom:15px;">
            Create Account
          </button>

          <button type="button" id="backToLoginBtn"
                  style="width:100%;padding:10px;background:transparent;color:#64748b;border:1px solid #e2e8f0;border-radius:10px;font-size:1em;cursor:pointer;">
            Back to Login
          </button>
        </form>
      </div>

      <!-- Forgot Password: request link -->
      <div id="forgotFormContainer" style="display:none;">
        <form id="requestResetForm">
          <p style="color:#4a5568;text-align:left;margin-bottom:10px;">Enter your <strong>username or email</strong> to request a reset link.</p>
          <input type="text" id="forgotUsernameOrEmail" placeholder="Username or Email" required
                 style="width:100%;padding:15px;border:2px solid #e2e8f0;border-radius:10px;font-size:1.1em;margin-bottom:15px;">
          <button type="submit" style="width:100%;padding:15px;background:#1e3a8a;color:white;border:none;border-radius:10px;font-size:1.1em;font-weight:600;cursor:pointer;margin-bottom:10px;">
            Send Reset Link
          </button>
          <button type="button" class="link-btn" id="haveTokenBtn" style="background:transparent;border:none;color:#1e3a8a;font-weight:600;cursor:pointer;padding:8px 0;">I already have a token</button>
          <button type="button" class="link-btn" id="forgotBackToLoginBtn" style="background:transparent;border:none;color:#1e3a8a;font-weight:600;cursor:pointer;padding:8px 0;">Back to Login</button>
          <div id="tokenReveal" style="display:none;background:#f7fafc;border:1px dashed #cbd5e1;padding:12px;border-radius:10px;text-align:left;margin-top:10px;"></div>
        </form>
      </div>

      <!-- Reset Password (manual token entry) -->
      <div id="resetFormContainer" style="display:none;">
        <form id="resetPasswordForm">
          <input type="text" id="resetToken" placeholder="Paste your reset token" required
                 style="width:100%;padding:15px;border:2px solid #e2e8f0;border-radius:10px;font-size:1.1em;margin-bottom:15px;">
          <input type="password" id="resetNewPassword" placeholder="New Password (8+ chars, upper/lower/number/special)" required
                 style="width:100%;padding:15px;border:2px solid #e2e8f0;border-radius:10px;font-size:1.1em;margin-bottom:15px;">
          <input type="password" id="resetConfirmPassword" placeholder="Confirm New Password" required
                 style="width:100%;padding:15px;border:2px solid #e2e8f0;border-radius:10px;font-size:1.1em;margin-bottom:15px;">

          <button type="submit" style="width:100%;padding:15px;background:#059669;color:white;border:none;border-radius:10px;font-size:1.1em;font-weight:600;cursor:pointer;margin-bottom:10px;">
            Reset Password
          </button>
          <button type="button" class="link-btn" id="needTokenBtn" style="background:transparent;border:none;color:#1e3a8a;font-weight:600;cursor:pointer;padding:8px 0;">Need a token?</button>
          <button type="button" class="link-btn" id="resetBackToLoginBtn" style="background:transparent;border:none;color:#1e3a8a;font-weight:600;cursor:pointer;padding:8px 0;">Back to Login</button>
        </form>
      </div>

      <div id="authError" style="color:#dc3545;margin-top:15px;display:none;font-size:1em;"></div>
      <div id="authSuccess" style="color:#059669;margin-top:15px;display:none;font-size:1em;"></div>
    `;
  }

  function wireLoginViewHandlers() {
    // Buttons that swap sections
    const regBtn = document.getElementById('showRegisterBtn');
    if (regBtn) regBtn.onclick = showRegisterForm;

    const backToLoginBtn = document.getElementById('backToLoginBtn');
    if (backToLoginBtn) backToLoginBtn.onclick = showLoginFormInModal;

    setupLoginHandler();
    setupRegisterHandler();
    setupForgotHandlers();
  }

  function showRegisterForm() {
    document.getElementById('loginFormContainer').style.display = 'none';
    document.getElementById('registerFormContainer').style.display = 'block';
    const f = document.getElementById('forgotFormContainer'); if (f) f.style.display = 'none';
    const r = document.getElementById('resetFormContainer'); if (r) r.style.display = 'none';
    setTimeout(() => document.getElementById('regUsername')?.focus(), 50);
  }

  function showLoginFormInModal() {
    document.getElementById('registerFormContainer').style.display = 'none';
    const f = document.getElementById('forgotFormContainer'); if (f) f.style.display = 'none';
    const r = document.getElementById('resetFormContainer'); if (r) r.style.display = 'none';
    // If we had a token-mode container, remove it
    const tm = document.getElementById('tokenModeReset');
    if (tm) tm.remove();
    document.getElementById('loginFormContainer').style.display = 'block';
    setTimeout(() => document.getElementById('loginUsername')?.focus(), 50);
  }

  function showForgotRequestForm() {
    document.getElementById('loginFormContainer').style.display = 'none';
    document.getElementById('registerFormContainer').style.display = 'none';
    document.getElementById('resetFormContainer').style.display = 'none';
    const tm = document.getElementById('tokenModeReset');
    if (tm) tm.remove();
    document.getElementById('forgotFormContainer').style.display = 'block';
    setTimeout(() => document.getElementById('forgotUsernameOrEmail')?.focus(), 50);
  }

  function showResetForm() {
    document.getElementById('loginFormContainer').style.display = 'none';
    document.getElementById('registerFormContainer').style.display = 'none';
    document.getElementById('forgotFormContainer').style.display = 'none';
    const tm = document.getElementById('tokenModeReset');
    if (tm) tm.remove();
    document.getElementById('resetFormContainer').style.display = 'block';
    setTimeout(() => document.getElementById('resetToken')?.focus(), 50);
  }

  // Render a "Set New Password" view *inside the same modal* using a token from URL
  function showResetFormWithToken(tokenFromURL) {
    // Ensure overlay exists
    if (!document.getElementById('loginOverlay')) showLoginForm();

    const modal = document.getElementById('loginModal');
    if (!modal) return;

    // Hide other containers, inject token-mode container
    const containers = ['loginFormContainer','registerFormContainer','forgotFormContainer','resetFormContainer'];
    containers.forEach(id => { const el = document.getElementById(id); if (el) el.style.display = 'none'; });
    const old = document.getElementById('tokenModeReset'); if (old) old.remove();

    const wrap = document.createElement('div');
    wrap.id = 'tokenModeReset';
    wrap.innerHTML = `
      <h3 style="margin-bottom:12px;">Set a New Password</h3>
      <p style="color:#64748b;margin-bottom:16px;">Enter a new password for your account.</p>
      <div class="form-group" style="text-align:left;margin-bottom:12px;">
        <input id="authNewPass" type="password" placeholder="New Password (8+ chars, upper/lower/number/special)"
               autocomplete="new-password"
               style="width:100%;padding:15px;border:2px solid #e2e8f0;border-radius:10px;font-size:1.05em;">
      </div>
      <div class="form-group" style="text-align:left;">
        <input id="authNewPass2" type="password" placeholder="Confirm New Password"
               autocomplete="new-password"
               style="width:100%;padding:15px;border:2px solid #e2e8f0;border-radius:10px;font-size:1.05em;">
      </div>
      <div style="display:flex;gap:10px;margin-top:18px;">
        <button class="btn btn-primary" id="authDoReset" style="flex:2;background:#059669;">Update Password</button>
        <button class="btn btn-secondary" id="authCancelReset" style="flex:1;background:#64748b;">Cancel</button>
      </div>
      <div id="authResetMsg" style="margin-top:12px;font-size:14px;color:#64748b;"></div>
    `;
    modal.appendChild(wrap);

    const cancelBtn = wrap.querySelector('#authCancelReset');
    cancelBtn.onclick = showLoginFormInModal;

    const doReset = async () => {
      const p1 = wrap.querySelector('#authNewPass').value.trim();
      const p2 = wrap.querySelector('#authNewPass2').value.trim();
      const msg = wrap.querySelector('#authResetMsg');

      if (!p1 || !p2) { msg.textContent = 'Please enter and confirm your new password.'; return; }
      if (p1 !== p2) { msg.textContent = 'Passwords do not match.'; return; }
      if (!PASSWORD_COMPLEXITY.test(p1)) { msg.textContent = 'Password must be 8+ chars incl. upper, lower, number, special.'; return; }
      msg.innerHTML = '<span class="loading-spinner"></span> Updating password…';

      try {
        const res = await fetch(CFG.USER_MANAGEMENT_URL, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: `action=resetpassword&token=${encodeURIComponent(tokenFromURL)}&newPassword=${encodeURIComponent(p1)}`
        });
        const j = await res.json().catch(() => ({}));
        if (j.success) {
          msg.style.color = '#059669';
          msg.textContent = 'Password updated. You can now log in.';
          // Strip token from URL so refresh won't reopen this view
          const url = new URL(location.href);
          url.searchParams.delete('resetToken'); url.searchParams.delete('token');
          history.replaceState({}, '', url.toString());
          setTimeout(() => showLoginFormInModal(), 800);
        } else {
          msg.style.color = '#dc2626';
          msg.textContent = j.message || 'Unable to update password.';
        }
      } catch (e) {
        msg.style.color = '#dc2626';
        msg.textContent = 'Connection error. Please try again.';
      }
    };

    wrap.querySelector('#authDoReset').onclick = doReset;
    setTimeout(() => wrap.querySelector('#authNewPass')?.focus(), 50);
  }

  // --- Event handlers ------------------------------------------------------
  function setupLoginHandler() {
    document.getElementById('loginForm').addEventListener('submit', async function (e) {
      e.preventDefault();
      const username = document.getElementById('loginUsername').value.trim();
      const password = document.getElementById('loginPassword').value;

      try {
        const response = await fetch(CFG.USER_MANAGEMENT_URL, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: `action=login&username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}`
        });
        const result = await response.json();

        if (result.success) {
          sessionStorage.setItem('dashboardAuth', 'true');
          sessionStorage.setItem('dashboardUser', result.username || username);
          sessionStorage.setItem('userEmail', result.email || '');
          sessionStorage.setItem('userCompany', result.company || '');
          document.getElementById('loginOverlay')?.remove();
          addLogoutButton();
          showMessage('Login successful!', 'success');
        } else {
          showError(result.message || 'Invalid username or password');
        }
      } catch (_) {
        showError('Connection error. Please try again.');
      }
    });
  }

  function setupRegisterHandler() {
    document.getElementById('registerForm').addEventListener('submit', async function (e) {
      e.preventDefault();

      const username = document.getElementById('regUsername').value.trim();
      const email = document.getElementById('regEmail').value.trim();
      const password = document.getElementById('regPassword').value;
      const confirmPassword = document.getElementById('regConfirmPassword').value;
      const company = document.getElementById('regCompany').value.trim();

      if (password !== confirmPassword) return showError('Passwords do not match');
      if (!PASSWORD_COMPLEXITY.test(password)) {
        return showError('Password must be 8+ chars and include upper, lower, number, and special character.');
      }
      if (username.length < 3) return showError('Username must be at least 3 characters');

      try {
        const response = await fetch(CFG.USER_MANAGEMENT_URL, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body:
            `action=register&username=${encodeURIComponent(username)}` +
            `&email=${encodeURIComponent(email)}` +
            `&password=${encodeURIComponent(password)}` +
            `&company=${encodeURIComponent(company)}`
        });
        const result = await response.json();

        if (result.success) {
          showSuccess('Account created successfully! You can now login.');
          setTimeout(() => {
            showLoginFormInModal();
            const lu = document.getElementById('loginUsername');
            if (lu) lu.value = username;
          }, 1200);
        } else {
          showError(result.message || 'Registration failed');
        }
      } catch (_) {
        showError('Connection error. Please try again.');
      }
    });
  }

  function setupForgotHandlers() {
    const forgotLink = document.getElementById('forgotLink');
    if (forgotLink) forgotLink.onclick = showForgotRequestForm;

    const haveTokenBtn = document.getElementById('haveTokenBtn');
    if (haveTokenBtn) haveTokenBtn.onclick = showResetForm;

    const forgotBackToLoginBtn = document.getElementById('forgotBackToLoginBtn');
    if (forgotBackToLoginBtn) forgotBackToLoginBtn.onclick = showLoginFormInModal;

    const needTokenBtn = document.getElementById('needTokenBtn');
    if (needTokenBtn) needTokenBtn.onclick = showForgotRequestForm;

    const resetBackToLoginBtn = document.getElementById('resetBackToLoginBtn');
    if (resetBackToLoginBtn) resetBackToLoginBtn.onclick = showLoginFormInModal;

    // Request reset link
    const reqForm = document.getElementById('requestResetForm');
    reqForm.addEventListener('submit', async function (e) {
      e.preventDefault();
      const id = document.getElementById('forgotUsernameOrEmail').value.trim();
      if (!id) return showError('Please enter your username or email.');

      try {
        const base = location.origin + location.pathname;
        const response = await fetch(CFG.USER_MANAGEMENT_URL, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body:
            `action=requestpasswordreset` +
            `&usernameOrEmail=${encodeURIComponent(id)}` +
            `&resetUrlBase=${encodeURIComponent(base)}`
        });
        const result = await response.json();

        if (result.success) {
          showSuccess('If an account exists, a reset link has been sent. Please check your email.');

          const box = document.getElementById('tokenReveal');
          if (CFG.SHOW_RESET_TOKEN_FOR_TESTING && result.resetToken) {
            box.style.display = 'block';
            const expiresTxt = result.expiresAt ? new Date(result.expiresAt).toLocaleString() : 'unknown';
            box.innerHTML = `
              <div><strong>Token:</strong> <code style="user-select:all;">${result.resetToken}</code></div>
              <div style="margin-top:6px;"><small>Expires: ${expiresTxt}</small></div>
              <div style="margin-top:10px;">
                <button class="btn btn-secondary" id="copyTokenBtn" type="button" style="padding:8px 14px;">Copy token</button>
                <button class="btn btn-primary" id="goToResetBtn" type="button" style="padding:8px 14px;margin-left:8px;">Continue to Reset</button>
              </div>
            `;
            setTimeout(() => {
              const ct = document.getElementById('copyTokenBtn');
              const gr = document.getElementById('goToResetBtn');
              if (ct) ct.onclick = async () => {
                try { await navigator.clipboard.writeText(result.resetToken); showMessage('Token copied', 'success'); } catch (_) {}
              };
              if (gr) gr.onclick = () => {
                showResetForm();
                const rt = document.getElementById('resetToken');
                if (rt) rt.value = result.resetToken || '';
              };
            }, 0);
          } else {
            box.style.display = 'none';
            box.innerHTML = '';
          }
        } else {
          showError(result.message || 'Could not send reset link.');
        }
      } catch (_) {
        showError('Connection error. Please try again.');
      }
    });

    // Submit new password (manual token flow)
    const resetForm = document.getElementById('resetPasswordForm');
    resetForm.addEventListener('submit', async function (e) {
      e.preventDefault();
      const token = document.getElementById('resetToken').value.trim();
      const pw = document.getElementById('resetNewPassword').value;
      const conf = document.getElementById('resetConfirmPassword').value;

      if (!token) return showError('Reset token is required.');
      if (pw !== conf) return showError('Passwords do not match.');
      if (!PASSWORD_COMPLEXITY.test(pw)) {
        return showError('New password must be 8+ chars and include upper, lower, number, and special character.');
      }

      try {
        const response = await fetch(CFG.USER_MANAGEMENT_URL, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: `action=resetpassword&token=${encodeURIComponent(token)}&newPassword=${encodeURIComponent(pw)}`
        });
        const result = await response.json();

        if (result.success) {
          showSuccess('Password has been reset. Please login with your new password.');
          setTimeout(() => {
            showLoginFormInModal();
            document.getElementById('loginPassword')?.focus();
          }, 1000);
        } else {
          showError(result.message || 'Reset failed.');
        }
      } catch (_) {
        showError('Connection error. Please try again.');
      }
    });
  }

  // --- Optional small modal helpers (legacy helpers remain available) ------
  function openForgotPassword() {
    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay';
    overlay.style.display = 'block';

    const modal = document.createElement('div');
    modal.className = 'modal';
    modal.innerHTML = `
      <h3>Reset your password</h3>
      <div class="form-group">
        <label for="fpEmail">Email or Username</label>
        <input type="text" id="fpEmail" placeholder="you@example.com" />
        <small>We’ll email you a reset link if the account exists.</small>
      </div>
      <div class="modal-buttons">
        <button class="btn btn-secondary" onclick="this.closest('.modal-overlay').remove()">Cancel</button>
        <button class="btn btn-primary" id="fpSendBtn">Send reset link</button>
      </div>
      <div id="fpMsg" style="margin-top:12px;font-size:0.95em;"></div>
    `;
    overlay.appendChild(modal);
    document.body.appendChild(overlay);
    setTimeout(() => document.getElementById('fpEmail')?.focus(), 50);

    document.getElementById('fpSendBtn').onclick = async () => {
      const id = (document.getElementById('fpEmail').value || '').trim();
      const msg = document.getElementById('fpMsg');
      if (!id) { msg.style.color = '#dc3545'; msg.textContent = 'Please enter your email or username.'; return; }

      const btn = document.getElementById('fpSendBtn');
      btn.disabled = true; btn.innerHTML = '<span class="loading-spinner"></span> Sending...';

      try {
        const base = location.origin + location.pathname;
        const body = `action=requestpasswordreset&usernameOrEmail=${encodeURIComponent(id)}&resetUrlBase=${encodeURIComponent(base)}`;
        const resp = await fetch(CFG.USER_MANAGEMENT_URL, {
          method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body
        });
        await resp.json();
        msg.style.color = '#059669';
        msg.textContent = 'If an account exists, a reset link has been sent. Please check your email.';
      } catch (_) {
        msg.style.color = '#dc3545';
        msg.textContent = 'Could not send reset link. Please try again.';
      } finally {
        btn.disabled = false; btn.textContent = 'Send reset link';
      }
    };
  }

  // Legacy helper kept for compatibility (now unused by router)
  function openResetWithToken(token) {
    showResetFormWithToken(token);
  }

  // --- Routing: handle ?resetToken=... ------------------------------------
  function routeFromURL() {
    try {
      const url = new URL(window.location.href);
      const token = url.searchParams.get('resetToken') || url.searchParams.get('token') || '';
      if (token) {
        sessionStorage.clear();     // ensure not logged-in during reset
        showLoginForm();            // ensure modal exists (and topmost z-index)
        // Render token-based reset UI *inside* the login modal (no second overlay)
        showResetFormWithToken(token);
        return true;
      }
    } catch (_) {}
    return false;
  }

  // --- User menu / logout --------------------------------------------------
  function openUserProfile() {
    const user = sessionStorage.getItem('dashboardUser') || 'Unknown';
    const email = sessionStorage.getItem('userEmail') || '';
    const company = sessionStorage.getItem('userCompany') || '';
    alert(`Profile: ${user}\nEmail: ${email}\nCompany: ${company}\n\nPassword change feature coming soon!`);
  }

  function addLogoutButton() {
    const header = document.querySelector('.header');
    if (!header) return;
    const loggedInUser = sessionStorage.getItem('dashboardUser') || 'User';

    const existingBtn = header.querySelector('.logout-container');
    if (existingBtn) existingBtn.remove();

    const logoutContainer = document.createElement('div');
    logoutContainer.className = 'logout-container';
    logoutContainer.style.cssText = 'position:absolute;top:20px;right:20px;display:flex;align-items:center;gap:15px;';

    const userInfo = document.createElement('button');
    userInfo.textContent = `👤 ${loggedInUser}`;
    userInfo.style.cssText = 'background:rgba(255,255,255,0.1);border:1px solid rgba(255,255,255,0.3);color:white;padding:8px 15px;border-radius:20px;cursor:pointer;font-size:0.9em;';
    userInfo.onclick = openUserProfile;

    const logoutBtn = document.createElement('button');
    logoutBtn.textContent = 'Logout';
    logoutBtn.className = 'btn logout-btn';
    logoutBtn.style.cssText = 'padding:10px 20px;';
    logoutBtn.onclick = logout;

    logoutContainer.appendChild(userInfo);
    logoutContainer.appendChild(logoutBtn);
    header.appendChild(logoutContainer);
  }

  function logout() {
    sessionStorage.clear();
    location.reload();
  }

  // --- Public API ----------------------------------------------------------
  const Auth = {
    checkAuth() {
      const isLoggedIn = sessionStorage.getItem('dashboardAuth') === 'true';
      const loggedInUser = sessionStorage.getItem('dashboardUser');
      if (!isLoggedIn || !loggedInUser) {
        showLoginForm();
        return false;
      }
      return true;
    },
    showLoginForm,
    openForgotPassword,      // optional helper
    openResetWithToken,      // optional helper (wraps new UI)
    addLogoutButton,
    logout,
    routeFromURL,
  };

  // expose for pages that already call checkAuth()/logout()
  global.Auth = Auth;
  global.checkAuth = Auth.checkAuth;
  global.logout = Auth.logout;

  // --- Auto-init on page load ---------------------------------------------
  document.addEventListener('DOMContentLoaded', function () {
    injectKeyframeCSS();
    // If URL contains a reset token, open the "Set New Password" view first.
    if (Auth.routeFromURL()) return;

    // Otherwise, normal auth gate.
    if (Auth.checkAuth()) {
      Auth.addLogoutButton();
    }
  });
})(window);
