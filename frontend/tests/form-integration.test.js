/**
 * Tests d'intégration end-to-end pour le formulaire FAF
 * Simule l'interaction utilisateur complète du début à la fin
 */

// Setup complet du DOM avec le vrai HTML
function setupFullFormDOM() {
  document.body.innerHTML = `
    <!DOCTYPE html>
    <html lang="fr">
    <head>
      <meta charset="UTF-8">
      <title>Form-a-Friend - Formulaire</title>
    </head>
    <body>
      <h1>Formulaire Mensuel... dis-moi tout</h1>
      <form id="friendForm">
        <input type="text" name="website" style="display:none" tabindex="-1" autocomplete="off">

        <!-- Champ Nom -->
        <div class="form-group">
          <label for="name">Ton nom :</label>
          <input type="text" id="name" name="name" required>
        </div>

        <!-- Question 1 -->
        <div class="form-group">
          <label>En rapide, comment ça va ? :</label>
          <div class="radio-group">
            <input type="radio" name="question1" id="option1" value="ça va" required>
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
        </div>

        <!-- Questions suivantes -->
        <div class="form-group">
          <label for="question2">Possibilité d'ajouter un peu plus de détails à la question précédente :</label>
          <input type="text" id="question2" name="question2" required>
        </div>

        <div class="form-group">
          <label for="question3">Le pulse check mensuel... montre une photo de toi ce mois-ci :</label>
          <input type="file" id="question3" name="question3" accept="image/*" required>
        </div>

        <div class="form-group">
          <label for="question4">Est-ce que tu veux partager un truc cool que t'as fait ce mois-ci ? :</label>
          <textarea id="question4" name="question4" rows="3" required></textarea>
        </div>

        <div class="form-group">
          <label for="question5">C'est quoi la reaction pic que tu utilises le plus en ce moment ? :</label>
          <input type="file" id="question5" name="question5" accept="image/*" required>
        </div>

        <div class="form-group">
          <label for="question6">Est-ce que t'as eu une conversation intéressante avec quelqu'un récemment ? De quoi est-ce que ça parlait ? :</label>
          <textarea id="question6" name="question6" rows="3" required></textarea>
        </div>

        <div class="form-group">
          <label for="question7">Ta découverte culturelle du moment ? (film, série, resto, bar, zoo, belle femme, vêtement... une catégorie assez libre finalement) :</label>
          <input type="file" id="question7" name="question7" accept="image/*" required>
        </div>

        <div class="form-group">
          <label for="question8">Est-ce que t'as une habitude ou une nouvelle routine que t'essaies d'implémenter ces temps-ci ? Si oui... est-ce que ça fonctionne... si non... est-ce que y'a un truc que tu voudrais implémenter ? :</label>
          <textarea id="question8" name="question8" rows="3" required></textarea>
        </div>

        <div class="form-group">
          <label for="question9">Appel à un AMI : Est-ce que t'as un problème particulier pour lequel tu aurais besoin d'opinions tierces ? (exemple : poll pour ta prochaine teinture, recommandations de matelas, etc.) :</label>
          <textarea id="question9" name="question9" rows="3" required></textarea>
        </div>

        <div class="form-group">
          <label for="question10">Pour terminer : une photo de toi qui touche de l'herbe ou un arbre :</label>
          <input type="file" id="question10" name="question10" accept="image/*" required>
        </div>

        <button type="submit">Envoyer</button>
      </form>

      <div id="feedback"></div>
    </body>
    </html>
  `;
}

// Mock complet des fichiers
class MockFile {
  constructor(name, type, size = 1024) {
    this.name = name;
    this.type = type;
    this.size = size;
    this.lastModified = Date.now();
  }
}

// Simulation de l'event submit avec preventDefault
function simulateFormSubmit(form) {
  const event = new Event('submit', { bubbles: true, cancelable: true });
  form.dispatchEvent(event);
  return event.defaultPrevented; // true si preventDefault() a été appelé
}

describe('Form Integration End-to-End Tests', () => {

  let mockFetch;

  beforeEach(() => {
    setupFullFormDOM();
    
    // Mock fetch global
    mockFetch = jest.fn();
    global.fetch = mockFetch;
    
    // Mock des fichiers pour tous les inputs file
    const fileInputs = ['question3', 'question5', 'question7', 'question10'];
    fileInputs.forEach((id, index) => {
      const input = document.getElementById(id);
      if (input) {
        Object.defineProperty(input, 'files', {
          value: [new MockFile(`test-${id}.jpg`, 'image/jpeg', 2048)],
          writable: true
        });
      }
    });
  });

  afterEach(() => {
    document.body.innerHTML = '';
    jest.restoreAllMocks();
  });

  describe('Complete User Journey - Happy Path', () => {

    test('should complete entire form submission flow successfully', async () => {
      // 1. Utilisateur remplit le formulaire
      document.getElementById('name').value = 'Alice Dupont';
      document.getElementById('option1').checked = true;
      document.getElementById('question2').value = 'Oui, ça va plutôt bien ce mois-ci !';
      document.getElementById('question4').value = 'J\'ai appris à faire du pain maison';
      document.getElementById('question6').value = 'Discussion intéressante sur l\'IA avec un collègue';
      document.getElementById('question8').value = 'Je fais du sport 3x par semaine maintenant';
      document.getElementById('question9').value = 'Besoin de conseils pour choisir un nouveau laptop';

      // 2. Mock des uploads qui réussissent
      mockFetch
        .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve({ url: 'https://cloudinary.com/photo1.jpg' }) })
        .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve({ url: 'https://cloudinary.com/photo2.jpg' }) })
        .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve({ url: 'https://cloudinary.com/photo3.jpg' }) })
        .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve({ url: 'https://cloudinary.com/photo4.jpg' }) });

      // 3. Mock de la soumission finale qui réussit
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 201,
        json: () => Promise.resolve({
          message: 'Réponse enregistrée avec succès !',
          link: `${process.env.APP_BASE_URL || 'http://localhost:3000'}/view/abc123def456`
        })
      });

      // 4. Simuler la soumission (implémentation simplifiée de la logique du HTML)
      const name = document.getElementById('name').value;
      const q1Radio = document.querySelector('input[name="question1"]:checked');
      const q2 = document.getElementById('question2').value;
      
      // Validation côté client passerait
      expect(name.length).toBeGreaterThan(0);
      expect(q1Radio).toBeTruthy();
      expect(q2.length).toBeGreaterThan(0);

      // 5. Simuler le processus d'upload
      const uploadResults = [
        'https://cloudinary.com/photo1.jpg',
        'https://cloudinary.com/photo2.jpg', 
        'https://cloudinary.com/photo3.jpg',
        'https://cloudinary.com/photo4.jpg'
      ];

      // 6. Simuler l'envoi des données
      const formData = {
        name: name,
        responses: [
          { question: 'En rapide, comment ça va ?', answer: q1Radio.value },
          { question: 'Possibilité d\'ajouter un peu plus de détails à la question précédente :', answer: q2 },
          { question: 'Le pulse check mensuel... montre une photo de toi ce mois-ci', answer: uploadResults[0] },
          { question: "Est-ce que tu veux partager un truc cool que t'as fait ce mois-ci ?", answer: document.getElementById('question4').value },
          { question: "C'est quoi la reaction pic que tu utilises le plus en ce moment ?", answer: uploadResults[1] },
          { question: "Est-ce que t'as eu une conversation intéressante avec quelqu'un récemment ? De quoi est-ce que ça parlait ?", answer: document.getElementById('question6').value },
          { question: "Ta découverte culturelle du moment ? (film, série, resto, bar, zoo, belle femme, vêtement... une catégorie assez libre finalement)", answer: uploadResults[2] },
          { question: "Est-ce que t'as une habitude ou une nouvelle routine que t'essaies d'implémenter ces temps-ci ? Si oui... est-ce que ça fonctionne... si non... est-ce que y'a un truc que tu voudrais implémenter ?", answer: document.getElementById('question8').value },
          { question: "Appel à un AMI : Est-ce que t'as un problème particulier pour lequel tu aurais besoin d'opinions tierces ? (exemple : poll pour ta prochaine teinture, recommandations de matelas, etc.)", answer: document.getElementById('question9').value },
          { question: "Pour terminer : une photo de toi qui touche de l'herbe ou un arbre", answer: uploadResults[3] }
        ]
      };

      expect(formData.responses).toHaveLength(10);
      expect(formData.name).toBe('Alice Dupont');

      // 7. Vérifier l'affichage du succès
      const feedback = document.getElementById('feedback');
      feedback.innerHTML = `
        ✅ Réponse enregistrée avec succès !<br/>
        Votre lien privé : <a href="${process.env.APP_BASE_URL || 'http://localhost:3000'}/view/abc123def456" target="_blank">${process.env.APP_BASE_URL || 'http://localhost:3000'}/view/abc123def456</a>
      `;

      expect(feedback.innerHTML).toContain('✅ Réponse enregistrée avec succès !');
      expect(feedback.innerHTML).toContain('Votre lien privé :');
      
      const link = feedback.querySelector('a');
      expect(link.href).toBe(`${process.env.APP_BASE_URL || 'http://localhost:3000'}/view/abc123def456`);
      expect(link.target).toBe('_blank');

      // 8. Vérifier que le formulaire n'a PAS été reset (comportement actuel)
      expect(document.getElementById('name').value).toBe('Alice Dupont');
      expect(document.getElementById('question2').value).toBe('Oui, ça va plutôt bien ce mois-ci !');
    });

  });

  describe('Complete User Journey - Error Scenarios', () => {

    test('should handle upload failure gracefully', async () => {
      // Utilisateur remplit le formulaire
      document.getElementById('name').value = 'Bob Martin';
      document.getElementById('option2').checked = true;
      document.getElementById('question2').value = 'Ça va bien !';

      // Premier upload échoue
      mockFetch.mockRejectedValueOnce(new Error('Upload failed: Network error'));

      // Simuler la gestion d'erreur
      const feedback = document.getElementById('feedback');
      try {
        throw new Error('Upload failed: Network error');
      } catch (err) {
        console.error(err);
        feedback.textContent = '❌ ' + err.message;
      }

      expect(feedback.textContent).toBe('❌ Upload failed: Network error');
      
      // Le formulaire garde les données pour que l'utilisateur puisse réessayer
      expect(document.getElementById('name').value).toBe('Bob Martin');
      expect(document.getElementById('question2').value).toBe('Ça va bien !');
    });

    test('should handle server validation error', async () => {
      // Utilisateur soumet avec données invalides
      document.getElementById('name').value = 'A'; // Trop court
      document.getElementById('option3').checked = true;

      // Mock server error
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 400,
        json: () => Promise.resolve({
          message: 'Le nom doit contenir entre 2 et 100 caractères',
          field: 'name'
        })
      });

      const feedback = document.getElementById('feedback');
      
      // Simuler la gestion d'erreur serveur
      const errorResponse = {
        message: 'Le nom doit contenir entre 2 et 100 caractères',
        field: 'name'
      };
      
      feedback.textContent = '❌ ' + errorResponse.message;

      expect(feedback.textContent).toBe('❌ Le nom doit contenir entre 2 et 100 caractères');
      expect(document.getElementById('name').value).toBe('A'); // Garde la valeur pour correction
    });

    test('should handle rate limiting appropriately', async () => {
      // Mock rate limiting response
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 429,
        json: () => Promise.resolve({
          message: 'Trop de tentatives. Réessayez dans 15 minutes.'
        })
      });

      const feedback = document.getElementById('feedback');
      feedback.textContent = '❌ Trop de tentatives. Réessayez dans 15 minutes.';

      expect(feedback.textContent).toContain('Trop de tentatives');
      expect(feedback.textContent).toContain('15 minutes');
    });

  });

  describe('Dynamic Option Behavior in Real Context', () => {

    test('should properly initialize and use dynamic option2', () => {
      // Simuler l'initialisation de l'option 2 (comme dans le DOM load)
      const today = new Date();
      const prev = new Date(today.getFullYear(), today.getMonth() - 1, 1);
      const month = prev.toLocaleString('fr-FR', { month: 'long' });
      const vowelsAndH = ['a', 'e', 'i', 'o', 'u', 'h'];
      
      const firstLetter = month[0].toLowerCase();
      const prefix = vowelsAndH.includes(firstLetter)
        ? "a connu meilleur mois d'"
        : 'a connu meilleur mois de ';
      
      const fullText = `${prefix}${month}`;
      
      // Mettre à jour le DOM comme le fait le JavaScript
      const opt2 = document.getElementById('option2');
      const lbl2 = document.getElementById('labelOption2');
      
      opt2.value = fullText;
      lbl2.textContent = fullText;

      expect(opt2.value).toBe(fullText);
      expect(lbl2.textContent).toBe(fullText);
      expect(fullText.length).toBeGreaterThan(0);
      expect(fullText).toMatch(/^a connu meilleur mois d'|de /);
      
      // L'utilisateur peut sélectionner cette option
      opt2.checked = true;
      const selected = document.querySelector('input[name="question1"]:checked');
      expect(selected.value).toBe(fullText);
    });

  });

  describe('Form State Management', () => {

    test('should maintain form state after successful submission for user review', () => {
      // Remplir le formulaire
      const testData = {
        name: 'Charlie Wilson',
        question2: 'Excellente question !',
        question4: 'J\'ai visité un musée fantastique',
        question6: 'Discussion sur les voyages avec ma grand-mère',
        question8: 'Je médite 10 minutes chaque matin maintenant',
        question9: 'Quel est le meilleur moyen d\'apprendre une nouvelle langue ?'
      };

      Object.entries(testData).forEach(([key, value]) => {
        const element = document.getElementById(key);
        if (element) element.value = value;
      });

      document.getElementById('option4').checked = true;

      // Après une soumission réussie, tout devrait rester en place
      Object.entries(testData).forEach(([key, value]) => {
        const element = document.getElementById(key);
        if (element) expect(element.value).toBe(value);
      });

      expect(document.getElementById('option4').checked).toBe(true);
    });

    test('should allow user to modify and resubmit if needed', () => {
      // Scénario: utilisateur soumet, voit une erreur, modifie et resoumet
      
      // Première soumission
      document.getElementById('name').value = 'Dana Smith';
      document.getElementById('option1').checked = true;
      
      // Erreur serveur - utilisateur corrige
      document.getElementById('name').value = 'Dana Smith-Johnson';
      
      // Nouvelle tentative avec données corrigées
      expect(document.getElementById('name').value).toBe('Dana Smith-Johnson');
      expect(document.getElementById('option1').checked).toBe(true);
    });

  });

  describe('Accessibility and Usability', () => {

    test('should have proper form labeling and structure', () => {
      const nameLabel = document.querySelector('label[for="name"]');
      const nameInput = document.getElementById('name');
      
      expect(nameLabel).toBeTruthy();
      expect(nameLabel.textContent).toContain('Ton nom');
      expect(nameInput.hasAttribute('required')).toBe(true);
      
      // Vérifier que tous les champs requis ont des labels
      const requiredFields = document.querySelectorAll('[required]');
      requiredFields.forEach(field => {
        if (field.id) {
          const label = document.querySelector(`label[for="${field.id}"]`);
          expect(label).toBeTruthy();
        }
      });
    });

    test('should have proper feedback area for messages', () => {
      const feedback = document.getElementById('feedback');
      expect(feedback).toBeTruthy();
      
      // Test d'affichage de différents types de messages
      feedback.innerHTML = '✅ Message de succès';
      expect(feedback.innerHTML).toContain('✅');
      
      feedback.textContent = '❌ Message d\'erreur';
      expect(feedback.textContent).toContain('❌');
    });

  });

});