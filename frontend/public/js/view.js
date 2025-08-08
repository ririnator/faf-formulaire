// Fonction pour décoder uniquement les entités HTML sûres (liste blanche)
function unescapeHTML(text) {
  if (!text || typeof text !== 'string') return text || '';
  
  // Approche liste blanche : décoder uniquement les entités communes et sûres
  const safeEntityMap = {
    '&#x27;': "'",
    '&#39;': "'",
    '&apos;': "'",
    '&quot;': '"',
    '&amp;': '&',
    '&lt;': '<',
    '&gt;': '>',
    '&nbsp;': ' ',
    '&eacute;': 'é',
    '&egrave;': 'è',
    '&ecirc;': 'ê',
    '&agrave;': 'à',
    '&acirc;': 'â',
    '&ugrave;': 'ù',
    '&ucirc;': 'û',
    '&icirc;': 'î',
    '&ocirc;': 'ô',
    '&ccedil;': 'ç'
  };
  
  let result = text;
  for (const [entity, char] of Object.entries(safeEntityMap)) {
    result = result.replace(new RegExp(entity, 'g'), char);
  }
  
  return result;
}

// Fonction pour détecter et afficher une image sécurisée
function createAnswerContent(answer) {
  const container = document.createElement('span');
  
  // 🔒 SECURITY: Only allow trusted image domains (whitelist approach)
  const TRUSTED_IMAGE_DOMAINS = [
    'res.cloudinary.com',           // Cloudinary CDN (notre service upload)
    'images.unsplash.com',          // Unsplash (si utilisé pour placeholder)
    'via.placeholder.com',          // Placeholder service (si nécessaire)
    // Ajouter d'autres domaines de confiance si nécessaire
  ];
  
  // Strict validation: URL must be HTTPS and from trusted domain
  const isValidImageUrl = (url) => {
    try {
      const urlObj = new URL(url);
      return urlObj.protocol === 'https:' && 
             TRUSTED_IMAGE_DOMAINS.some(domain => urlObj.hostname.endsWith(domain));
    } catch {
      return false;
    }
  };
  
  // Check if answer looks like an image URL (contains image extensions)
  const imageExtensions = /\.(jpg|jpeg|png|gif|webp)(\?|$)/i;
  
  if (typeof answer === 'string' && 
      (answer.includes('res.cloudinary.com') || imageExtensions.test(answer)) && 
      isValidImageUrl(answer)) {
    
    // Create secure image element
    const img = document.createElement('img');
    img.src = answer;
    img.alt = 'Image de réponse';
    img.style.cssText = 'max-width: 400px; max-height: 300px; border-radius: 8px; margin: 10px 0;';
    
    // Add error handling for failed image loads
    img.onerror = function() {
      this.style.display = 'none';
      const fallback = document.createElement('span');
      fallback.textContent = '[Image non disponible]';
      fallback.style.cssText = 'color: #666; font-style: italic;';
      this.parentNode.appendChild(fallback);
    };
    
    container.appendChild(img);
  } else {
    // Text content - decode HTML entities safely and use textContent for XSS protection
    container.textContent = unescapeHTML(answer);
  }
  
  return container;
}

(async () => {
  const token = location.pathname.split('/').pop();
  const res = await fetch(`/api/view/${token}`);
  if (!res.ok) {
    document.body.textContent = 'Lien invalide ou expiré.';
    return;
  }
  const { user, admin } = await res.json();
  document.getElementById('month').textContent = user.month;

  // Configuration du regroupement des questions
  const questionGroups = [
    { name: "État général du mois", questions: [0, 1] }, // Q1-Q2: Comment ça va + détails
    { name: "Check personnel", questions: [2] }, // Q3: Photo de toi
    { name: "Activités & découvertes", questions: [3, 4, 6] }, // Q4: Truc cool, Q5: Reaction pic, Q7: Découverte culturelle  
    { name: "Réflexions & conversations", questions: [5, 7] }, // Q6: Conversation intéressante, Q8: Habitudes/routines
    { name: "Appel à un ami", questions: [8] }, // Q9: Problème/opinions tierces
    { name: "Connexion à la nature", questions: [9] } // Q10: Photo avec herbe/arbre
  ];

  const container = document.getElementById('qa-container');
  
  questionGroups.forEach(group => {
    // Titre du groupe
    const groupTitle = document.createElement('h2');
    groupTitle.textContent = group.name;
    groupTitle.style.cssText = 'color: #2c5aa0; margin: 30px 0 15px 0; font-size: 1.3em; border-bottom: 2px solid #2c5aa0; padding-bottom: 5px;';
    container.appendChild(groupTitle);
    
    group.questions.forEach(qIndex => {
      if (qIndex < user.responses.length && qIndex < admin.responses.length) {
        const userQ = user.responses[qIndex];
        const adminQ = admin.responses[qIndex];
        
        // Question
        const questionDiv = document.createElement('div');
        questionDiv.style.cssText = 'margin: 20px 0; padding: 15px; background: #f8f9fa; border-radius: 8px; border-left: 4px solid #2c5aa0;';
        
        const questionTitle = document.createElement('h3');
        questionTitle.textContent = unescapeHTML(userQ.question);
        questionTitle.style.cssText = 'margin: 0 0 10px 0; color: #2c5aa0; font-size: 1.1em;';
        questionDiv.appendChild(questionTitle);
        
        // Réponses côte à côte
        const answersContainer = document.createElement('div');
        answersContainer.style.cssText = 'display: flex; gap: 20px; flex-wrap: wrap;';
        
        // Réponse utilisateur
        const userAnswer = document.createElement('div');
        userAnswer.style.cssText = 'flex: 1; min-width: 300px; padding: 15px; background: white; border-radius: 6px; border: 1px solid #ddd;';
        const userLabel = document.createElement('strong');
        userLabel.textContent = `${user.name}: `;
        userLabel.style.cssText = 'color: #0066cc; display: block; margin-bottom: 5px;';
        userAnswer.appendChild(userLabel);
        userAnswer.appendChild(createAnswerContent(userQ.answer));
        
        // Réponse admin
        const adminAnswer = document.createElement('div');
        adminAnswer.style.cssText = 'flex: 1; min-width: 300px; padding: 15px; background: #fff8e1; border-radius: 6px; border: 1px solid #ffd54f;';
        const adminLabel = document.createElement('strong');
        adminLabel.textContent = `${admin.name}: `;
        adminLabel.style.cssText = 'color: #f57f17; display: block; margin-bottom: 5px;';
        adminAnswer.appendChild(adminLabel);
        adminAnswer.appendChild(createAnswerContent(adminQ.answer));
        
        answersContainer.appendChild(userAnswer);
        answersContainer.appendChild(adminAnswer);
        questionDiv.appendChild(answersContainer);
        container.appendChild(questionDiv);
      }
    });
  });
})();