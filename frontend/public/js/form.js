// JavaScript pour la page de formulaire - validation, upload et soumission

// Fonctionnalité de barre de progression
document.addEventListener('DOMContentLoaded', function() {
  const progressBar = document.getElementById('progressFill');
  const formGroups = document.querySelectorAll('.form-group, fieldset');
  const totalSteps = formGroups.length;
  
  function updateProgress() {
    let completedSteps = 0;
    
    formGroups.forEach(group => {
      const inputs = group.querySelectorAll('input, textarea');
      let hasValue = false;
      
      inputs.forEach(input => {
        if (input.type === 'radio' && input.checked) {
          hasValue = true;
        } else if (input.type === 'file' && input.files.length > 0) {
          hasValue = true;
        } else if (input.type === 'text' && input.value.trim()) {
          hasValue = true;
        } else if (input.tagName === 'TEXTAREA' && input.value.trim()) {
          hasValue = true;
        }
      });
      
      if (hasValue) {
        completedSteps++;
      }
    });
    
    const percentage = (completedSteps / totalSteps) * 100;
    progressBar.style.width = percentage + '%';
  }
  
  // Écouter les changements sur tous les champs
  document.addEventListener('input', updateProgress);
  document.addEventListener('change', updateProgress);
  
  // Mise à jour initiale
  updateProgress();
});

/**
 * Génère dynamiquement l'option 2 du formulaire avec le mois précédent
 * Utilise les règles de français pour les articles ('d'' vs 'de ')
 * Voyelles + 'h' → "d'" (ex: "a connu meilleur mois d'octobre")  
 * Consonnes → "de " (ex: "a connu meilleur mois de janvier")
 */
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
  
  return `${prefix}${month}`;
}

// Mise à jour dynamique de l'option 2
document.addEventListener('DOMContentLoaded', () => {
  const opt2 = document.getElementById('option2');
  const lbl2 = document.getElementById('labelOption2');
  
  if (opt2 && lbl2) {
    const fullText = generateDynamicOption2();
    opt2.value = fullText;
    lbl2.textContent = fullText;
  }
});

// Fonction pour afficher/cacher l'état de chargement
function showLoading(show = true, message = 'Traitement en cours...') {
  let overlay = document.getElementById('loadingOverlay');
  
  if (!overlay) {
    overlay = document.createElement('div');
    overlay.id = 'loadingOverlay';
    overlay.className = 'loading-overlay hidden';
    overlay.innerHTML = `
      <div class="loading-content">
        <div class="loading-spinner"></div>
        <div class="loading-text">${message}</div>
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

// Upload et soumission
document.getElementById('friendForm').addEventListener('submit', async e => {
  e.preventDefault();
  const feedback = document.getElementById('feedback');
  const submitBtn = document.querySelector('button[type="submit"]');
  
  // Réinitialiser l'état
  feedback.textContent = '';
  
  // Afficher état de chargement
  showLoading(true, 'Validation en cours...');
  submitBtn.disabled = true;
  submitBtn.textContent = 'Envoi en cours...';

  // Validation helper function
  function validateField(id, errorMessage, isFile = false) {
    const element = document.getElementById(id);
    const value = isFile ? element.files[0] : element.value.trim();
    if (!value) {
      showLoading(false);
      submitBtn.disabled = false;
      submitBtn.textContent = 'Envoyer le formulaire';
      feedback.textContent = `❌ ${errorMessage}`;
      return false;
    }
    return value;
  }

  // Validate radio button
  const q1Radio = document.querySelector('input[name="question1"]:checked');
  if (!q1Radio) {
    showLoading(false);
    submitBtn.disabled = false;
    submitBtn.textContent = 'Envoyer le formulaire';
    feedback.textContent = '❌ Veuillez sélectionner une réponse à la première question';
    return;
  }

  // Validate all fields
  const name = validateField('name', 'Veuillez renseigner votre nom');
  if (!name) return;

  const q1 = q1Radio.value;
  const q2 = validateField('question2', 'Veuillez répondre à la question 2');
  if (!q2) return;

  const q3File = validateField('question3', 'Veuillez ajouter une photo pour la question 3', true);
  if (!q3File) return;

  const q4 = validateField('question4', 'Veuillez répondre à la question 4');
  if (!q4) return;

  const q5File = validateField('question5', 'Veuillez ajouter une image pour la question 5', true);
  if (!q5File) return;

  const q6 = validateField('question6', 'Veuillez répondre à la question 6');
  if (!q6) return;

  const q7File = validateField('question7', 'Veuillez ajouter une image pour la question 7', true);
  if (!q7File) return;

  const q8 = validateField('question8', 'Veuillez répondre à la question 8');
  if (!q8) return;

  const q9 = validateField('question9', 'Veuillez répondre à la question 9');
  if (!q9) return;

  const q10File = validateField('question10', 'Veuillez ajouter une photo pour la question 10', true);
  if (!q10File) return;

  async function uploadFile(id) {
    const inp = document.getElementById(id);
    const f = inp.files[0];
    if (!f) return null;
    const fd = new FormData();
    fd.append('image', f);
    const r = await fetch('/api/upload', {
      method: 'POST',
      credentials:'include',
      body: fd
    });
    if (!r.ok) throw new Error(`Upload ${id} ${r.status}`);
    const j = await r.json();
    return j.url;
  }

  try {
    const q3  = await uploadFile('question3');
    const q5  = await uploadFile('question5');
    const q7  = await uploadFile('question7');
    const q10 = await uploadFile('question10');

    const data = {
      name,
      responses: [
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
      ]
    };

    // Mettre à jour le message de chargement
    showLoading(true, 'Envoi de vos réponses...');

    // Envoi des réponses
    const resp = await fetch('/api/response', {
      method: 'POST',
      credentials:'include',
      headers: { 'Content-Type':'application/json' },
      body: JSON.stringify(data)
    });

    const resJ = await resp.json();

    if (!resp.ok) {
      throw new Error(resJ.message || 'Erreur lors de l'envoi');
    }

    // Affiche le message et le lien de manière sécurisée
    feedback.replaceChildren();
    
    const successIcon = document.createTextNode('✅ ');
    const messageText = document.createTextNode(resJ.message);
    feedback.appendChild(successIcon);
    feedback.appendChild(messageText);
    
    if (resJ.link) {
      const br = document.createElement('br');
      const linkText = document.createTextNode('Votre lien privé : ');
      const linkEl = document.createElement('a');
      linkEl.href = resJ.link;
      linkEl.target = '_blank';
      linkEl.textContent = resJ.link;
      
      feedback.appendChild(br);
      feedback.appendChild(linkText);
      feedback.appendChild(linkEl);
    }
  } catch (err) {
    console.error(err);
    feedback.textContent = '❌ ' + err.message;
  } finally {
    // Restaurer l'état du bouton et cacher le chargement
    showLoading(false);
    submitBtn.disabled = false;
    submitBtn.textContent = 'Envoyer le formulaire';
  }
});