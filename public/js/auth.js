/**
 * FAF Authentication Module
 * Handles registration, login, and JWT token management
 */

// Configuration
const API_BASE_URL = window.location.origin;

// Utility: Show feedback message
function showFeedback(elementId, message, type = 'error') {
  const feedback = document.getElementById(elementId);
  if (!feedback) return;

  feedback.textContent = message;
  feedback.className = `feedback feedback-${type}`;
  feedback.style.display = 'block';

  // Auto-hide success messages after 5 seconds
  if (type === 'success') {
    setTimeout(() => {
      feedback.style.display = 'none';
    }, 5000);
  }
}

// Utility: Validate password strength
function validatePassword(password) {
  // Min 8 chars, 1 uppercase, 1 digit
  const minLength = password.length >= 8;
  const hasUppercase = /[A-Z]/.test(password);
  const hasDigit = /\d/.test(password);

  return {
    valid: minLength && hasUppercase && hasDigit,
    minLength,
    hasUppercase,
    hasDigit
  };
}

// Utility: Update password strength indicator
function updatePasswordStrength(password, elementId) {
  const strengthEl = document.getElementById(elementId);
  if (!strengthEl) return;

  const validation = validatePassword(password);

  let strength = 0;
  let color = '#e74c3c';
  let text = 'Faible';

  if (validation.minLength) strength++;
  if (validation.hasUppercase) strength++;
  if (validation.hasDigit) strength++;

  if (strength === 3) {
    color = '#27ae60';
    text = 'Fort';
  } else if (strength === 2) {
    color = '#f39c12';
    text = 'Moyen';
  }

  strengthEl.innerHTML = `
    <div class="strength-bar" style="width: ${(strength / 3) * 100}%; background-color: ${color}"></div>
    <span class="strength-text">${text}</span>
  `;
  strengthEl.style.display = password.length > 0 ? 'block' : 'none';
}

// Initialize Register Form
function initRegisterForm() {
  const form = document.getElementById('registerForm');
  const passwordInput = document.getElementById('password');
  const submitBtn = document.getElementById('submitBtn');

  if (!form) return;

  // Real-time password strength validation
  if (passwordInput) {
    passwordInput.addEventListener('input', (e) => {
      updatePasswordStrength(e.target.value, 'passwordStrength');
    });
  }

  // Form submission
  form.addEventListener('submit', async (e) => {
    e.preventDefault();

    const username = document.getElementById('username').value.trim().toLowerCase();
    const email = document.getElementById('email').value.trim();
    const password = document.getElementById('password').value;
    const confirmPassword = document.getElementById('confirmPassword').value;
    const honeypot = document.getElementById('website').value;

    // Client-side validation
    if (honeypot) {
      showFeedback('feedback', 'Erreur de validation', 'error');
      return;
    }

    if (password !== confirmPassword) {
      showFeedback('feedback', 'Les mots de passe ne correspondent pas', 'error');
      return;
    }

    const passwordValidation = validatePassword(password);
    if (!passwordValidation.valid) {
      let errorMsg = 'Mot de passe trop faible. Il doit contenir : ';
      const missing = [];
      if (!passwordValidation.minLength) missing.push('8 caractères min');
      if (!passwordValidation.hasUppercase) missing.push('1 majuscule');
      if (!passwordValidation.hasDigit) missing.push('1 chiffre');
      errorMsg += missing.join(', ');
      showFeedback('feedback', errorMsg, 'error');
      return;
    }

    // Username validation
    if (!/^[a-z0-9_-]{3,20}$/.test(username)) {
      showFeedback('feedback', 'Nom d\'utilisateur invalide (3-20 caractères, minuscules uniquement)', 'error');
      return;
    }

    // Disable submit button
    submitBtn.disabled = true;
    submitBtn.textContent = 'Création en cours...';

    try {
      const response = await fetch(`${API_BASE_URL}/api/auth/register`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ username, email, password })
      });

      const data = await response.json();

      if (response.ok) {
        // Success: Store token and redirect
        localStorage.setItem('faf_token', data.token);
        localStorage.setItem('faf_username', data.admin.username);
        localStorage.setItem('faf_admin_id', data.admin.id);

        showFeedback('feedback', 'Compte créé avec succès ! Redirection...', 'success');

        // Redirect to onboarding
        setTimeout(() => {
          window.location.href = '/auth/onboarding.html';
        }, 1500);
      } else {
        // Error from server
        showFeedback('feedback', data.error || 'Erreur lors de l\'inscription', 'error');
        submitBtn.disabled = false;
        submitBtn.textContent = 'Créer mon compte';
      }
    } catch (err) {
      console.error('Register error:', err);
      showFeedback('feedback', 'Erreur réseau. Veuillez réessayer.', 'error');
      submitBtn.disabled = false;
      submitBtn.textContent = 'Créer mon compte';
    }
  });
}

// Initialize Login Form
function initLoginForm() {
  const form = document.getElementById('loginForm');
  const submitBtn = document.getElementById('submitBtn');

  if (!form) return;

  form.addEventListener('submit', async (e) => {
    e.preventDefault();

    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;
    const honeypot = document.getElementById('website').value;

    // Client-side validation
    if (honeypot) {
      showFeedback('feedback', 'Erreur de validation', 'error');
      return;
    }

    if (!username || !password) {
      showFeedback('feedback', 'Veuillez remplir tous les champs', 'error');
      return;
    }

    // Disable submit button
    submitBtn.disabled = true;
    submitBtn.textContent = 'Connexion...';

    try {
      const response = await fetch(`${API_BASE_URL}/api/auth/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ username, password })
      });

      const data = await response.json();

      if (response.ok) {
        // Success: Store token and redirect
        localStorage.setItem('faf_token', data.token);
        localStorage.setItem('faf_username', data.admin.username);
        localStorage.setItem('faf_admin_id', data.admin.id);

        showFeedback('feedback', 'Connexion réussie ! Redirection...', 'success');

        // Redirect to dashboard
        setTimeout(() => {
          window.location.href = '/admin/dashboard.html';
        }, 1500);
      } else {
        // Error from server
        showFeedback('feedback', data.error || 'Identifiants invalides', 'error');
        submitBtn.disabled = false;
        submitBtn.textContent = 'Se connecter';
      }
    } catch (err) {
      console.error('Login error:', err);
      showFeedback('feedback', 'Erreur réseau. Veuillez réessayer.', 'error');
      submitBtn.disabled = false;
      submitBtn.textContent = 'Se connecter';
    }
  });
}

// Check if user is already authenticated
async function checkAuth() {
  const token = localStorage.getItem('faf_token');
  if (!token) {
    return false;
  }

  try {
    const response = await fetch(`${API_BASE_URL}/api/auth/verify`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });

    if (response.ok) {
      const data = await response.json();
      // Update stored username if needed
      if (data.admin && data.admin.username) {
        localStorage.setItem('faf_username', data.admin.username);
        localStorage.setItem('faf_admin_id', data.admin.id);
      }
      return true;
    } else {
      // Token invalid or expired
      localStorage.removeItem('faf_token');
      localStorage.removeItem('faf_username');
      localStorage.removeItem('faf_admin_id');
      return false;
    }
  } catch (err) {
    console.error('Auth check error:', err);
    return false;
  }
}

// Logout function
function logout() {
  localStorage.removeItem('faf_token');
  localStorage.removeItem('faf_username');
  localStorage.removeItem('faf_admin_id');
  window.location.href = '/auth/login.html';
}

// Export functions for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    initRegisterForm,
    initLoginForm,
    checkAuth,
    logout,
    validatePassword
  };
}
