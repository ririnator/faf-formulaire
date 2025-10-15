/**
 * FAF Multi-Tenant - Formulaire dynamique
 *
 * Module JavaScript pour gérer le formulaire dynamique par admin
 * - Extraction du username depuis l'URL (/form/{username})
 * - Fetch des données admin depuis /api/form/{username}
 * - Affichage dynamique du formulaire
 * - Upload d'images vers Cloudinary
 * - Soumission vers /api/response/submit
 */

// === CONFIGURATION ===
const API_BASE_URL = window.location.origin;

// === EXTRACTION DU USERNAME DEPUIS L'URL ===
function extractUsernameFromURL() {
  // URL format: /form/{username} ou /form/{username}/
  const pathParts = window.location.pathname.split('/').filter(p => p);

  // pathParts = ['form', 'username']
  if (pathParts.length >= 2 && pathParts[0] === 'form') {
    return pathParts[1];
  }

  return null;
}

// === FETCH DES DONNÉES ADMIN ===
async function fetchAdminData(username) {
  try {
    const response = await fetch(`${API_BASE_URL}/api/form/${username}`);

    if (!response.ok) {
      if (response.status === 404) {
        return { error: 'Admin introuvable', status: 404 };
      }
      return { error: 'Erreur serveur', status: response.status };
    }

    const data = await response.json();
    return { data };
  } catch (error) {
    console.error('Fetch admin data error:', error);
    return { error: 'Erreur de connexion au serveur' };
  }
}

// === AFFICHAGE PAGE D'ERREUR 404 ===
function renderErrorPage(username) {
  const container = document.getElementById('content-container');

  container.innerHTML = `
    <div class="error-container">
      <h1>404</h1>
      <p>Le formulaire de <strong>${escapeHTML(username)}</strong> n'existe pas.</p>
      <p>Vérifiez que vous avez le bon lien ou contactez la personne qui vous l'a envoyé.</p>
      <a href="/auth/landing.html">Retour à l'accueil</a>
    </div>
  `;
}

// === AFFICHAGE DU FORMULAIRE ===
function renderForm(adminData, username) {
  const container = document.getElementById('content-container');

  // Mise à jour du titre de la page
  const pageTitle = document.getElementById('page-title');
  pageTitle.textContent = `Formulaire de ${adminData.admin.username}`;

  container.innerHTML = `
    <h1 id="form-title">Formulaire mensuel de ${escapeHTML(adminData.admin.username)}</h1>

    <form id="friendForm" role="form" aria-labelledby="form-title" novalidate>
      <!-- Honeypot field for spam protection -->
      <input type="text" name="website" style="display:none" tabindex="-1" autocomplete="off" aria-hidden="true">

      <!-- Champ caché avec le username de l'admin -->
      <input type="hidden" id="adminUsername" name="username" value="${escapeHTML(username)}">

      <!-- Champ Nom -->
      <div class="form-group">
        <label for="name">Ton nom :</label>
        <input type="text" id="name" name="name" required
               aria-describedby="name-help"
               aria-invalid="false"
               autocomplete="name">
        <div id="name-help" class="sr-only">Entrez votre prénom ou surnom</div>
      </div>

      <!-- Question 1 -->
      <fieldset class="form-group">
        <legend>En rapide, comment ça va ? :</legend>
        <div class="radio-group">
          <input type="radio" name="question1" id="option1" value="ça va" required
                 aria-describedby="q1-help">
          <label for="option1">ça va</label>
        </div>
        <div class="radio-group">
          <input type="radio" name="question1" id="option2" value="a connu meilleur mois">
          <label for="option2" id="labelOption2"></label>
        </div>
        <div class="radio-group">
          <input type="radio" name="question1" id="option3" value="ITS JOEVER">
          <label for="option3">ITS JOEVER</label>
        </div>
        <div class="radio-group">
          <input type="radio" name="question1" id="option4" value="WE'RE BARACK">
          <label for="option4">WE'RE BARACK</label>
        </div>
      </fieldset>

      <!-- Question 2 -->
      <div class="form-group">
        <label for="question2">Possibilité d'ajouter un peu plus de détails à la question précédente :</label>
        <input type="text" id="question2" name="question2" required
               aria-describedby="q2-help"
               aria-invalid="false"
               maxlength="10000">
      </div>

      <!-- Question 3 -->
      <div class="form-group">
        <label for="question3">Le pulse check mensuel... montre une photo de toi ce mois-ci :</label>
        <input type="file" id="question3" name="question3" accept="image/*" required
               aria-describedby="q3-help"
               aria-invalid="false">
      </div>

      <!-- Question 4 -->
      <div class="form-group">
        <label for="question4">Est-ce que tu veux partager un truc cool que t'as fait ce mois-ci ? :</label>
        <textarea id="question4" name="question4" rows="3" required></textarea>
      </div>

      <!-- Question 5 -->
      <div class="form-group">
        <label for="question5">C'est quoi la reaction pic que tu utilises le plus en ce moment ? :</label>
        <input type="file" id="question5" name="question5" accept="image/*" required>
      </div>

      <!-- Question 6 -->
      <div class="form-group">
        <label for="question6">Est-ce que t'as eu une conversation intéressante avec quelqu'un récemment ? De quoi est-ce que ça parlait ? :</label>
        <textarea id="question6" name="question6" rows="3" required></textarea>
      </div>

      <!-- Question 7 -->
      <div class="form-group">
        <label for="question7">Ta découverte culturelle du moment ? (film, série, resto, bar, zoo, belle femme, vêtement... une catégorie assez libre finalement) :</label>
        <input type="file" id="question7" name="question7" accept="image/*" required>
      </div>

      <!-- Question 8 -->
      <div class="form-group">
        <label for="question8">Est-ce que t'as une habitude ou une nouvelle routine que t'essaies d'implémenter ces temps-ci ? Si oui... est-ce que ça fonctionne... si non... est-ce que y'a un truc que tu voudrais implémenter ? :</label>
        <textarea id="question8" name="question8" rows="3" required></textarea>
      </div>

      <!-- Question 9 -->
      <div class="form-group">
        <label for="question9">Appel à un AMI : Est-ce que t'as un problème particulier pour lequel tu aurais besoin d'opinions tierces ? (exemple : poll pour ta prochaine teinture, recommandations de matelas, etc.) :</label>
        <textarea id="question9" name="question9" rows="3" required></textarea>
      </div>

      <!-- Question 10 -->
      <div class="form-group">
        <label for="question10">Pour terminer : une photo de toi qui touche de l'herbe ou un arbre :</label>
        <input type="file" id="question10" name="question10" accept="image/*" required>
      </div>

      <!-- Question 11 - Champ libre (optionnel) -->
      <div class="form-group">
        <label for="question11">Dump - Si tu as des choses à dire sens-toi libre de t'exprimer :</label>
        <textarea id="question11" name="question11" rows="4"
                  placeholder="Ce champ est optionnel. Exprimez-vous librement !"
                  aria-describedby="q11-help"
                  maxlength="10000"></textarea>
      </div>

      <button type="submit"
              aria-describedby="submit-help"
              class="btn-submit">
        Envoyer le formulaire
      </button>
      <div id="submit-help" class="sr-only">
        Soumettre vos réponses mensuelles. Un lien privé vous sera fourni pour consulter vos réponses.
      </div>
    </form>

    <!-- Section de feedback -->
    <section id="feedback" role="status" aria-live="polite" aria-atomic="true"></section>
  `;

  // Initialiser les événements du formulaire
  initFormEvents();

  // Générer l'option 2 dynamique
  generateDynamicOption2();
}

// === GÉNÉRATION OPTION 2 DYNAMIQUE ===
function generateDynamicOption2() {
  const today = new Date();
  const prev = new Date(today.getFullYear(), today.getMonth() - 1, 1);

  // Force la locale française pour assurer la cohérence
  const month = prev.toLocaleString('fr-FR', { month: 'long' });

  // Voyelles françaises + 'h' muet (règles d'élision)
  const vowelsAndH = ['a', 'e', 'i', 'o', 'u', 'h'];

  const firstLetter = month[0].toLowerCase();
  const prefix = vowelsAndH.includes(firstLetter)
    ? "a connu meilleur mois d'"
    : 'a connu meilleur mois de ';

  const fullText = `${prefix}${month}`;

  const opt2 = document.getElementById('option2');
  const lbl2 = document.getElementById('labelOption2');

  if (opt2 && lbl2) {
    opt2.value = fullText;
    lbl2.textContent = fullText;
  }
}

// === INITIALISATION DES ÉVÉNEMENTS DU FORMULAIRE ===
function initFormEvents() {
  const form = document.getElementById('friendForm');
  if (!form) return;

  form.addEventListener('submit', handleFormSubmit);
}

// === GESTION SOUMISSION DU FORMULAIRE ===
async function handleFormSubmit(e) {
  e.preventDefault();

  const feedback = document.getElementById('feedback');
  const submitBtn = document.querySelector('button[type="submit"]');

  // Réinitialiser l'état
  feedback.textContent = '';

  // Afficher état de chargement
  showLoading(true, 'Validation en cours...');
  submitBtn.disabled = true;
  submitBtn.textContent = 'Envoi en cours...';

  try {
    // Validation des champs
    const validationResult = validateFormFields();
    if (!validationResult.valid) {
      showLoading(false);
      submitBtn.disabled = false;
      submitBtn.textContent = 'Envoyer le formulaire';
      feedback.textContent = `❌ ${validationResult.error}`;
      return;
    }

    const { name, q1, q2, q4, q6, q8, q9, q11 } = validationResult;

    // Upload des 4 images en parallèle
    showLoading(true, 'Upload des images (0/4)...');

    const uploadPromises = [
      uploadFile('question3'),
      uploadFile('question5'),
      uploadFile('question7'),
      uploadFile('question10')
    ];

    let completedUploads = 0;
    const trackProgress = (promise) => {
      return promise.then(
        result => {
          completedUploads++;
          showLoading(true, `Upload des images (${completedUploads}/4)...`);
          return result;
        },
        error => {
          throw error;
        }
      );
    };

    const [q3, q5, q7, q10] = await Promise.all(
      uploadPromises.map(trackProgress)
    );

    // Construire le tableau de réponses
    const responses = [
      { question: 'En rapide, comment ça va ?', answer: q1 },
      { question: 'Possibilité d\'ajouter un peu plus de détails à la question précédente :', answer: q2 },
      { question: 'Le pulse check mensuel... montre une photo de toi ce mois-ci', answer: q3 },
      { question: "Est-ce que tu veux partager un truc cool que t'as fait ce mois-ci ?", answer: q4 },
      { question: "C'est quoi la reaction pic que tu utilises le plus en ce moment ?", answer: q5 },
      { question: "Est-ce que t'as eu une conversation intéressante avec quelqu'un récemment ? De quoi est-ce que ça parlait ?", answer: q6 },
      { question: "Ta découverte culturelle du moment ? (film, série, resto, bar, zoo, belle femme, vêtement... une catégorie assez libre finalement)", answer: q7 },
      { question: "Est-ce que t'as une habitude ou une nouvelle routine que t'essaies d'implémenter ces temps-ci ? Si oui... est-ce que ça fonctionne... si non... est-ce que y'a un truc que tu voudrais implémenter ?", answer: q8 },
      { question: "Appel à un AMI : Est-ce que t'as un problème particulier pour lequel tu aurais besoin d'opinions tierces ? (exemple : poll pour ta prochaine teinture, recommandations de matelas, etc.)", answer: q9 },
      { question: "Pour terminer : une photo de toi qui touche de l'herbe ou un arbre", answer: q10 }
    ];

    // Ajouter la question 11 seulement si elle a été remplie
    if (q11) {
      responses.push({
        question: "Dump - Si tu as des choses à dire sens-toi libre de t'exprimer",
        answer: q11
      });
    }

    // Récupérer le username de l'admin depuis le champ caché
    const username = document.getElementById('adminUsername').value;

    const data = {
      username,
      name,
      responses
    };

    // Mettre à jour le message de chargement
    showLoading(true, 'Envoi de vos réponses...');

    // Envoi des réponses
    const resp = await fetch(`${API_BASE_URL}/api/response/submit`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    });

    const resJ = await resp.json();

    if (!resp.ok) {
      throw new Error(resJ.error || resJ.message || 'Erreur lors de l\'envoi');
    }

    // Afficher la modal de succès
    feedback.replaceChildren();

    const userName = resJ.userName || 'Vous';
    const adminName = resJ.adminName || 'Admin';

    showSuccessModal(resJ.message, resJ.link, userName, adminName);

  } catch (err) {
    console.error('Form submission error:', err);
    feedback.textContent = '❌ ' + err.message;
  } finally {
    showLoading(false);
    submitBtn.disabled = false;
    submitBtn.textContent = 'Envoyer le formulaire';
  }
}

// === VALIDATION DES CHAMPS DU FORMULAIRE ===
function validateFormFields() {
  // Helper function
  function validateField(id, errorMessage, isFile = false) {
    const element = document.getElementById(id);
    const value = isFile ? element.files[0] : element.value.trim();
    if (!value) {
      return { valid: false, error: errorMessage };
    }
    return { valid: true, value };
  }

  // Validate radio button
  const q1Radio = document.querySelector('input[name="question1"]:checked');
  if (!q1Radio) {
    return { valid: false, error: 'Veuillez sélectionner une réponse à la première question' };
  }

  // Validate all required fields
  const name = validateField('name', 'Veuillez renseigner votre nom');
  if (!name.valid) return name;

  const q1 = q1Radio.value;

  const q2 = validateField('question2', 'Veuillez répondre à la question 2');
  if (!q2.valid) return q2;

  const q3File = validateField('question3', 'Veuillez ajouter une photo pour la question 3', true);
  if (!q3File.valid) return q3File;

  const q4 = validateField('question4', 'Veuillez répondre à la question 4');
  if (!q4.valid) return q4;

  const q5File = validateField('question5', 'Veuillez ajouter une image pour la question 5', true);
  if (!q5File.valid) return q5File;

  const q6 = validateField('question6', 'Veuillez répondre à la question 6');
  if (!q6.valid) return q6;

  const q7File = validateField('question7', 'Veuillez ajouter une image pour la question 7', true);
  if (!q7File.valid) return q7File;

  const q8 = validateField('question8', 'Veuillez répondre à la question 8');
  if (!q8.valid) return q8;

  const q9 = validateField('question9', 'Veuillez répondre à la question 9');
  if (!q9.valid) return q9;

  const q10File = validateField('question10', 'Veuillez ajouter une photo pour la question 10', true);
  if (!q10File.valid) return q10File;

  // Question 11 est optionnelle
  const q11 = document.getElementById('question11').value.trim();

  return {
    valid: true,
    name: name.value,
    q1,
    q2: q2.value,
    q4: q4.value,
    q6: q6.value,
    q8: q8.value,
    q9: q9.value,
    q11
  };
}

// === UPLOAD D'UNE IMAGE VERS CLOUDINARY ===
async function uploadFile(id) {
  const inp = document.getElementById(id);
  const f = inp.files[0];
  if (!f) return null;

  // Compression d'image si > 2MB pour améliorer la vitesse d'upload
  let fileToUpload = f;
  if (f.size > 2 * 1024 * 1024 && f.type.startsWith('image/')) {
    try {
      const canvas = document.createElement('canvas');
      const ctx = canvas.getContext('2d');
      const img = new Image();

      await new Promise((resolve, reject) => {
        img.onload = resolve;
        img.onerror = reject;
        img.src = URL.createObjectURL(f);
      });

      // Redimensionner si trop grand (max 1920px)
      const maxSize = 1920;
      let width = img.width;
      let height = img.height;

      if (width > maxSize || height > maxSize) {
        if (width > height) {
          height = (height * maxSize) / width;
          width = maxSize;
        } else {
          width = (width * maxSize) / height;
          height = maxSize;
        }
      }

      canvas.width = width;
      canvas.height = height;
      ctx.drawImage(img, 0, 0, width, height);

      // Convertir en blob avec compression
      const blob = await new Promise(resolve =>
        canvas.toBlob(resolve, 'image/jpeg', 0.85)
      );

      // Préserver l'extension originale ou remplacer par .jpg pour HEIC
      const newName = f.name.replace(/\.(heic|HEIC)$/i, '.jpg').replace(/\.[^.]+$/, '.jpg');
      fileToUpload = new File([blob], newName, { type: 'image/jpeg' });
      URL.revokeObjectURL(img.src);
    } catch (e) {
      console.warn('Compression failed, using original:', e);
    }
  }

  const fd = new FormData();
  fd.append('image', fileToUpload);
  const r = await fetch(`${API_BASE_URL}/api/upload`, {
    method: 'POST',
    credentials: 'include',
    body: fd
  });

  if (!r.ok) throw new Error(`Upload ${id} failed (${r.status})`);
  const j = await r.json();
  return j.url;
}

// === AFFICHAGE/MASQUAGE DE L'ÉTAT DE CHARGEMENT ===
function showLoading(show = true, message = 'Traitement en cours...') {
  let overlay = document.getElementById('loadingOverlay');

  if (!overlay) {
    overlay = document.createElement('div');
    overlay.id = 'loadingOverlay';
    overlay.className = 'loading-overlay hidden';
    overlay.innerHTML = `
      <div class="loading-content">
        <div class="loading-spinner"></div>
        <div class="loading-text">${escapeHTML(message)}</div>
      </div>
    `;
    document.body.appendChild(overlay);
  }

  if (show) {
    overlay.classList.remove('hidden');
    overlay.querySelector('.loading-text').textContent = message;
  } else {
    overlay.classList.add('hidden');
  }
}

// === MODAL DE SUCCÈS ===
function showSuccessModal(message, link, userName, adminName) {
  const modal = document.getElementById('successModal');
  const messageElement = document.getElementById('success-message');
  const linkElement = document.getElementById('success-link');

  // Mise à jour du contenu
  if (link) {
    messageElement.textContent = `Votre formulaire a été envoyé ! Voici votre lien privé pour voir la comparaison ${userName} vs ${adminName} :`;
    linkElement.href = link;
    linkElement.style.display = 'inline-block';
  } else {
    messageElement.textContent = message;
    linkElement.style.display = 'none';
  }

  // Afficher la modal
  modal.setAttribute('aria-hidden', 'false');
  modal.classList.add('show');

  // Focus pour l'accessibilité
  modal.querySelector('.modal-close-btn').focus();

  // Fermeture automatique au clic sur l'overlay
  modal.addEventListener('click', function(e) {
    if (e.target === modal) {
      closeSuccessModal();
    }
  });

  // Fermeture avec Échap
  document.addEventListener('keydown', function escapeHandler(e) {
    if (e.key === 'Escape') {
      closeSuccessModal();
      document.removeEventListener('keydown', escapeHandler);
    }
  });
}

window.closeSuccessModal = function() {
  const modal = document.getElementById('successModal');
  modal.setAttribute('aria-hidden', 'true');
  modal.classList.remove('show');
};

// === UTILITAIRE : ÉCHAPPEMENT HTML (XSS PROTECTION) ===
function escapeHTML(str) {
  if (!str) return '';
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

// === INITIALISATION AU CHARGEMENT DE LA PAGE ===
document.addEventListener('DOMContentLoaded', async () => {
  // 1. Extraire le username depuis l'URL
  const username = extractUsernameFromURL();

  if (!username) {
    renderErrorPage('unknown');
    return;
  }

  // 2. Fetch les données de l'admin
  const result = await fetchAdminData(username);

  if (result.error) {
    renderErrorPage(username);
    return;
  }

  // 3. Afficher le formulaire
  renderForm(result.data, username);
});
