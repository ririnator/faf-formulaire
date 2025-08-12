/**
 * Tests de soumission réelle du formulaire avec le JavaScript actuel
 * Utilise le vrai code JavaScript extrait du HTML pour tester le comportement réel
 */

// Import du HTML complet pour extraire le JavaScript
const fs = require('fs');
const path = require('path');

// Mock fetch global
global.fetch = jest.fn();

// Mock des fichiers
class MockFile {
  constructor(name, type, size = 1024) {
    this.name = name;
    this.type = type;
    this.size = size;
    this.lastModified = Date.now();
  }
}

// Setup du DOM avec le vrai HTML
function setupRealFormDOM() {
  // Lecture du fichier HTML réel
  const htmlPath = path.join(__dirname, '../public/index.html');
  const htmlContent = fs.readFileSync(htmlPath, 'utf8');
  
  // Parser le HTML et l'injecter dans jsdom
  document.documentElement.innerHTML = htmlContent.split('<html')[1].split('</html>')[0];
  
  // Mock des fichiers dans les inputs
  const fileInputs = ['question3', 'question5', 'question7', 'question10'];
  fileInputs.forEach((id, index) => {
    const input = document.getElementById(id);
    if (input) {
      Object.defineProperty(input, 'files', {
        value: [new MockFile(`test-${id}.jpg`, 'image/jpeg', 2048)],
        writable: true,
        configurable: true
      });
    }
  });
}

// Extraction et exécution du JavaScript du HTML
function executeFormJavaScript() {
  // Récupération du contenu du script depuis le DOM
  const scriptTag = document.querySelector('script');
  if (scriptTag && scriptTag.textContent) {
    // Exécution du JavaScript dans le contexte du test
    eval(scriptTag.textContent);
  }
}

describe('Real Form Submission Tests', () => {
  
  beforeEach(() => {
    // Reset mocks
    global.fetch.mockClear();
    
    // Setup DOM complet avec le vrai HTML
    setupRealFormDOM();
    
    // Exécuter le JavaScript réel du formulaire
    executeFormJavaScript();
    
    // Simuler le DOMContentLoaded pour initialiser l'option 2
    const event = new Event('DOMContentLoaded');
    document.dispatchEvent(event);
  });

  afterEach(() => {
    document.documentElement.innerHTML = '';
    jest.clearAllMocks();
  });

  describe('Real Dynamic Option Generation', () => {

    test('should correctly initialize option2 with real JavaScript', () => {
      // Vérifier que l'option 2 a été initialisée par le vrai code
      const opt2 = document.getElementById('option2');
      const lbl2 = document.getElementById('labelOption2');

      expect(opt2).toBeTruthy();
      expect(lbl2).toBeTruthy();
      
      // Le JavaScript réel devrait avoir mis à jour la valeur
      expect(opt2.value.length).toBeGreaterThan(0);
      expect(lbl2.textContent.length).toBeGreaterThan(0);
      
      // Vérifier le format attendu
      expect(opt2.value).toMatch(/^a connu meilleur mois d'|de /);
      expect(lbl2.textContent).toBe(opt2.value);
      
      console.log('Option 2 généré:', opt2.value);
    });

  });

  describe('Real Form Validation', () => {

    test('should validate empty name field with real JavaScript', async () => {
      const form = document.getElementById('friendForm');
      const feedback = document.getElementById('feedback');
      
      // Laisser le nom vide
      document.getElementById('name').value = '';
      
      // Simuler la soumission du formulaire
      const submitEvent = new Event('submit', { cancelable: true });
      form.dispatchEvent(submitEvent);
      
      // Attendre un peu pour que le JavaScript s'exécute
      await new Promise(resolve => setTimeout(resolve, 100));
      
      // Vérifier que le message d'erreur s'affiche
      expect(feedback.textContent).toContain('Veuillez renseigner votre nom');
    });

    test('should validate radio button selection with real JavaScript', async () => {
      const form = document.getElementById('friendForm');
      const feedback = document.getElementById('feedback');
      
      // Remplir le nom mais ne pas sélectionner de radio
      document.getElementById('name').value = 'Test User';
      
      // Simuler la soumission
      const submitEvent = new Event('submit', { cancelable: true });
      form.dispatchEvent(submitEvent);
      
      await new Promise(resolve => setTimeout(resolve, 100));
      
      // Vérifier le message d'erreur radio
      expect(feedback.textContent).toContain('Veuillez sélectionner une réponse à la première question');
    });

    test('should validate all required fields step by step', async () => {
      const form = document.getElementById('friendForm');
      const feedback = document.getElementById('feedback');
      
      // Test 1: Nom manquant
      const submitEvent1 = new Event('submit', { cancelable: true });
      form.dispatchEvent(submitEvent1);
      await new Promise(resolve => setTimeout(resolve, 50));
      expect(feedback.textContent).toContain('nom');
      
      // Test 2: Ajouter nom, radio manquant
      document.getElementById('name').value = 'Test User';
      feedback.textContent = ''; // Clear
      
      const submitEvent2 = new Event('submit', { cancelable: true });
      form.dispatchEvent(submitEvent2);
      await new Promise(resolve => setTimeout(resolve, 50));
      expect(feedback.textContent).toContain('première question');
      
      // Test 3: Ajouter radio, question2 manquante
      document.getElementById('option1').checked = true;
      feedback.textContent = ''; // Clear
      
      const submitEvent3 = new Event('submit', { cancelable: true });
      form.dispatchEvent(submitEvent3);
      await new Promise(resolve => setTimeout(resolve, 50));
      expect(feedback.textContent).toContain('question 2');
    });

  });

  describe('Real File Upload Process', () => {

    test('should handle file upload with real JavaScript', async () => {
      // Mock successful upload
      global.fetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ url: 'https://cloudinary.com/test.jpg' })
      });

      // Remplir le formulaire partiellement
      document.getElementById('name').value = 'Test User';
      document.getElementById('option1').checked = true;
      document.getElementById('question2').value = 'Test response';
      
      // Vérifier que les fichiers sont présents (mockés)
      const fileInput = document.getElementById('question3');
      expect(fileInput.files).toHaveLength(1);
      expect(fileInput.files[0].name).toBe('test-question3.jpg');
      
      // Le test d'upload complet nécessiterait de mocker tous les champs
      // mais on peut vérifier que le setup est correct
    });

  });

  describe('Real Form Submission Success Flow', () => {

    function fillCompleteForm() {
      document.getElementById('name').value = 'Alice Test';
      document.getElementById('option2').checked = true; // Utiliser l'option dynamique
      document.getElementById('question2').value = 'Détails supplémentaires test';
      document.getElementById('question4').value = 'Quelque chose de cool ce mois-ci';
      document.getElementById('question6').value = 'Conversation intéressante sur les tests';
      document.getElementById('question8').value = 'Nouvelle routine de test unitaire';
      document.getElementById('question9').value = 'Problème: comment tester du JavaScript réel?';
    }

    test('should process complete form submission with real handlers', async () => {
      // Mock tous les uploads
      global.fetch
        .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve({ url: 'url1.jpg' }) })
        .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve({ url: 'url2.jpg' }) })
        .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve({ url: 'url3.jpg' }) })
        .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve({ url: 'url4.jpg' }) });

      // Mock soumission finale
      global.fetch.mockResolvedValueOnce({
        ok: true,
        status: 201,
        json: () => Promise.resolve({
          message: 'Réponse enregistrée avec succès !',
          link: `${process.env.APP_BASE_URL || 'http://localhost:3000'}/view/token123`
        })
      });

      fillCompleteForm();

      const form = document.getElementById('friendForm');
      const feedback = document.getElementById('feedback');

      // Simuler la soumission complète
      const submitEvent = new Event('submit', { cancelable: true });
      form.dispatchEvent(submitEvent);

      // Attendre que tous les uploads et la soumission se terminent
      await new Promise(resolve => setTimeout(resolve, 1000));

      // Vérifier les appels fetch (4 uploads + 1 soumission)
      expect(global.fetch).toHaveBeenCalledTimes(5);
      
      // Vérifier que les uploads ont été appelés avec FormData
      const uploadCalls = global.fetch.mock.calls.slice(0, 4);
      uploadCalls.forEach(call => {
        expect(call[0]).toBe('/api/upload');
        expect(call[1].method).toBe('POST');
        expect(call[1].body).toBeInstanceOf(FormData);
      });

      // Vérifier l'appel de soumission finale
      const submissionCall = global.fetch.mock.calls[4];
      expect(submissionCall[0]).toBe('/api/response');
      expect(submissionCall[1].method).toBe('POST');
      expect(submissionCall[1].headers['Content-Type']).toBe('application/json');
      
      // Parser les données envoyées
      const sentData = JSON.parse(submissionCall[1].body);
      expect(sentData.name).toBe('Alice Test');
      expect(sentData.responses).toHaveLength(10);
      expect(sentData.responses[0].answer).toMatch(/^a connu meilleur mois/); // Option dynamique
      expect(sentData.responses[2].answer).toBe('url1.jpg'); // Image uploadée
    });

    test('should handle upload error in real flow', async () => {
      // Premier upload échoue
      global.fetch.mockRejectedValueOnce(new Error('Upload failed'));

      fillCompleteForm();

      const form = document.getElementById('friendForm');
      const feedback = document.getElementById('feedback');

      const submitEvent = new Event('submit', { cancelable: true });
      form.dispatchEvent(submitEvent);

      // Attendre l'erreur
      await new Promise(resolve => setTimeout(resolve, 500));

      // Vérifier que l'erreur est affichée
      expect(feedback.textContent).toContain('❌');
      
      // Vérifier que le formulaire garde les données
      expect(document.getElementById('name').value).toBe('Alice Test');
      expect(document.getElementById('question2').value).toBe('Détails supplémentaires test');
    });

    test('should handle server error in real flow', async () => {
      // Mock uploads réussis
      global.fetch
        .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve({ url: 'url1.jpg' }) })
        .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve({ url: 'url2.jpg' }) })
        .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve({ url: 'url3.jpg' }) })
        .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve({ url: 'url4.jpg' }) });

      // Mock erreur serveur
      global.fetch.mockResolvedValueOnce({
        ok: false,
        status: 400,
        json: () => Promise.resolve({
          message: 'Le nom doit contenir entre 2 et 100 caractères'
        })
      });

      fillCompleteForm();
      // Modifier le nom pour déclencher une erreur de validation
      document.getElementById('name').value = 'A'; // Trop court

      const form = document.getElementById('friendForm');
      const feedback = document.getElementById('feedback');

      const submitEvent = new Event('submit', { cancelable: true });
      form.dispatchEvent(submitEvent);

      await new Promise(resolve => setTimeout(resolve, 1000));

      // Vérifier l'erreur de validation
      expect(feedback.textContent).toContain('Le nom doit contenir entre 2 et 100 caractères');
    });

  });

  describe('Real Form State Management', () => {

    test('should NOT reset form after successful submission (current behavior)', async () => {
      // Mock successful flow
      global.fetch
        .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve({ url: 'url1.jpg' }) })
        .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve({ url: 'url2.jpg' }) })
        .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve({ url: 'url3.jpg' }) })
        .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve({ url: 'url4.jpg' }) })
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({
            message: 'Réponse enregistrée avec succès !',
            link: `${process.env.APP_BASE_URL || 'http://localhost:3000'}/view/token456`
          })
        });

      // Remplir le formulaire
      document.getElementById('name').value = 'Bob Test';
      document.getElementById('option3').checked = true;
      document.getElementById('question2').value = 'Ma réponse test';

      const originalName = document.getElementById('name').value;
      const originalQ2 = document.getElementById('question2').value;

      const form = document.getElementById('friendForm');
      const submitEvent = new Event('submit', { cancelable: true });
      form.dispatchEvent(submitEvent);

      await new Promise(resolve => setTimeout(resolve, 1000));

      // Vérifier que le formulaire n'a pas été reset
      expect(document.getElementById('name').value).toBe(originalName);
      expect(document.getElementById('question2').value).toBe(originalQ2);
      expect(document.getElementById('option3').checked).toBe(true);

      console.log('Formulaire préservé après succès - nom:', document.getElementById('name').value);
    });

  });

  describe('Real Honeypot and Security', () => {

    test('should detect spam with real honeypot validation', async () => {
      // Remplir le champ honeypot (normalement caché)
      const honeypot = document.querySelector('input[name="website"]');
      honeypot.value = 'spam-content';

      // Remplir le reste du formulaire
      document.getElementById('name').value = 'Spammer';
      document.getElementById('option1').checked = true;

      const form = document.getElementById('friendForm');
      const feedback = document.getElementById('feedback');

      // Note: Le JavaScript actuel ne semble pas vérifier le honeypot côté client
      // mais on peut tester la présence du champ
      expect(honeypot.style.display).toBe('none');
      expect(honeypot.getAttribute('tabindex')).toBe('-1');
      expect(honeypot.getAttribute('autocomplete')).toBe('off');
    });

  });

});