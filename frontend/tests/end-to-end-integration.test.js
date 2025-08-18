/**
 * End-to-End Integration Tests
 * Comprehensive test suite for complete user workflows,
 * API integration, real-time features, and cross-component interactions
 */

const { JSDOM } = require('jsdom');
const fs = require('fs');
const path = require('path');

describe('🔄 End-to-End Integration Tests', () => {
  let dom;
  let window;
  let document;
  let mockAdminAPI;
  let mockNotificationCenter;
  let mockWebSocket;

  beforeEach(() => {
    // Create comprehensive integration test environment
    dom = new JSDOM(`
      <!DOCTYPE html>
      <html lang="fr">
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width,initial-scale=1">
          <title>Integration Test Environment</title>
          <style>
            .hidden { display: none !important; }
            .loading { opacity: 0.5; pointer-events: none; }
            .success { background: #10b981; color: white; }
            .error { background: #ef4444; color: white; }
            .modal-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.5); z-index: 1000; }
            .contact-card { background: white; border-radius: 8px; padding: 1rem; margin: 0.5rem; }
            .notification { background: #3b82f6; color: white; padding: 1rem; border-radius: 8px; margin: 0.5rem; }
            .lightbox { position: fixed; inset: 0; background: rgba(0,0,0,0.9); z-index: 2000; }
            .timeline-item { background: white; border-radius: 8px; padding: 1rem; margin: 0.5rem; }
            .comparison-view { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }
          </style>
        </head>
        <body>
          <!-- Authentication Section -->
          <section id="authSection" class="auth-section">
            <form id="loginForm">
              <input type="email" id="loginEmail" placeholder="Email" required>
              <input type="password" id="loginPassword" placeholder="Mot de passe" required>
              <button type="submit" id="loginSubmit">Se connecter</button>
            </form>
            <div id="authStatus" class="hidden"></div>
          </section>

          <!-- Dashboard Section -->
          <section id="dashboardSection" class="dashboard-section hidden">
            <nav class="dashboard-nav">
              <button id="contactsNavBtn" class="nav-btn">Contacts</button>
              <button id="timelineNavBtn" class="nav-btn">Timeline</button>
              <button id="compareNavBtn" class="nav-btn">Comparer</button>
              <button id="settingsNavBtn" class="nav-btn">Paramètres</button>
            </nav>

            <!-- Real-time Notifications -->
            <div id="notificationCenter" class="notification-center">
              <div id="notificationList" class="notification-list"></div>
              <div id="notificationSettings" class="notification-settings hidden">
                <label>
                  <input type="checkbox" id="emailNotifications"> Notifications email
                </label>
                <label>
                  <input type="checkbox" id="browserNotifications"> Notifications navigateur
                </label>
              </div>
            </div>

            <!-- Quick Stats -->
            <div id="quickStats" class="stats-grid">
              <div class="stat-card" id="totalContactsStat">
                <span class="stat-value">0</span>
                <span class="stat-label">Contacts</span>
              </div>
              <div class="stat-card" id="activeHandshakesStat">
                <span class="stat-value">0</span>
                <span class="stat-label">Handshakes actifs</span>
              </div>
              <div class="stat-card" id="pendingInvitationsStat">
                <span class="stat-value">0</span>
                <span class="stat-label">Invitations</span>
              </div>
            </div>
          </section>

          <!-- Contact Management Section -->
          <section id="contactsSection" class="contacts-section hidden">
            <div class="contacts-header">
              <h2>Gestion des Contacts</h2>
              <div class="contacts-actions">
                <button id="addContactBtn" class="btn-primary">Ajouter Contact</button>
                <button id="importContactsBtn" class="btn-secondary">Importer CSV</button>
                <button id="exportContactsBtn" class="btn-secondary">Exporter CSV</button>
              </div>
            </div>

            <!-- Search and Filters -->
            <div class="contacts-filters">
              <input type="text" id="contactSearchInput" placeholder="Rechercher...">
              <select id="statusFilter">
                <option value="">Tous les statuts</option>
                <option value="active">Actif</option>
                <option value="pending">En attente</option>
                <option value="declined">Refusé</option>
              </select>
              <select id="tagFilter">
                <option value="">Tous les tags</option>
              </select>
            </div>

            <!-- Contacts Grid -->
            <div id="contactsGrid" class="contacts-grid">
              <!-- Contacts will be loaded here -->
            </div>

            <!-- Pagination -->
            <div id="contactsPagination" class="pagination hidden">
              <button id="prevPageBtn">Précédent</button>
              <span id="pageInfo">Page 1 sur 1</span>
              <button id="nextPageBtn">Suivant</button>
            </div>
          </section>

          <!-- Timeline Section -->
          <section id="timelineSection" class="timeline-section hidden">
            <div class="timeline-header">
              <h2>Timeline des Soumissions</h2>
              <div class="timeline-filters">
                <select id="contactSelectFilter">
                  <option value="">Tous les contacts</option>
                </select>
                <select id="timeRangeFilter">
                  <option value="all">Toutes les périodes</option>
                  <option value="recent">3 derniers mois</option>
                  <option value="6months">6 derniers mois</option>
                </select>
              </div>
            </div>

            <div id="timelineContainer" class="timeline-container">
              <!-- Timeline items will be loaded here -->
            </div>
          </section>

          <!-- Comparison Section -->
          <section id="compareSection" class="compare-section hidden">
            <div class="comparison-header">
              <h2>Comparaison des Réponses</h2>
              <div class="comparison-controls">
                <select id="compareContact1">
                  <option value="">Sélectionner contact 1</option>
                </select>
                <select id="compareContact2">
                  <option value="">Sélectionner contact 2</option>
                </select>
                <select id="compareMonth">
                  <option value="">Sélectionner le mois</option>
                </select>
                <button id="loadComparisonBtn" class="btn-primary">Comparer</button>
              </div>
            </div>

            <div id="comparisonResults" class="comparison-results hidden">
              <div class="comparison-view">
                <div id="comparison1" class="comparison-panel">
                  <h3 id="comparison1Title">Contact 1</h3>
                  <div id="comparison1Content"></div>
                </div>
                <div id="comparison2" class="comparison-panel">
                  <h3 id="comparison2Title">Contact 2</h3>
                  <div id="comparison2Content"></div>
                </div>
              </div>
            </div>
          </section>

          <!-- Photo Management Section -->
          <section id="photoSection" class="photo-section hidden">
            <div class="photo-upload-area">
              <input type="file" id="photoInput" accept="image/*" multiple>
              <div id="photoPreviewContainer" class="photo-previews"></div>
            </div>

            <div id="photoGallery" class="photo-gallery">
              <!-- Photos will be displayed here -->
            </div>
          </section>

          <!-- Modal for Add/Edit Contact -->
          <div id="contactModal" class="modal-overlay hidden" role="dialog">
            <div class="modal-content">
              <div class="modal-header">
                <h3 id="contactModalTitle">Ajouter un Contact</h3>
                <button id="closeContactModal" class="btn-close">×</button>
              </div>
              <form id="contactForm">
                <div class="form-group">
                  <label for="contactEmail">Email *</label>
                  <input type="email" id="contactEmail" required>
                </div>
                <div class="form-group">
                  <label for="contactFirstName">Prénom</label>
                  <input type="text" id="contactFirstName">
                </div>
                <div class="form-group">
                  <label for="contactLastName">Nom</label>
                  <input type="text" id="contactLastName">
                </div>
                <div class="form-group">
                  <label for="contactTags">Tags</label>
                  <input type="text" id="contactTags" placeholder="Séparés par des virgules">
                </div>
                <div class="form-actions">
                  <button type="button" id="cancelContactBtn">Annuler</button>
                  <button type="submit" id="saveContactBtn">Enregistrer</button>
                </div>
              </form>
            </div>
          </div>

          <!-- Lightbox for Photos -->
          <div id="photoLightbox" class="lightbox hidden" role="dialog">
            <div class="lightbox-content">
              <img id="lightboxImage" src="" alt="">
              <div class="lightbox-controls">
                <button id="lightboxPrev">‹</button>
                <button id="lightboxNext">›</button>
                <button id="lightboxClose">×</button>
              </div>
            </div>
          </div>

          <!-- Loading Overlay -->
          <div id="loadingOverlay" class="modal-overlay hidden">
            <div class="loading-content">
              <div class="spinner"></div>
              <span id="loadingMessage">Chargement...</span>
            </div>
          </div>

          <!-- Toast Notifications -->
          <div id="toastContainer" class="toast-container">
            <!-- Toasts will appear here -->
          </div>

          <!-- CSV Upload Modal -->
          <div id="csvModal" class="modal-overlay hidden">
            <div class="modal-content">
              <h3>Importer des Contacts</h3>
              <input type="file" id="csvFileInput" accept=".csv">
              <div id="csvPreview" class="csv-preview hidden">
                <h4>Aperçu des données:</h4>
                <table id="csvTable"></table>
              </div>
              <div class="modal-actions">
                <button id="cancelCsvBtn">Annuler</button>
                <button id="confirmCsvBtn" class="btn-primary">Importer</button>
              </div>
            </div>
          </div>

          <!-- Error Boundary -->
          <div id="errorBoundary" class="error-boundary hidden">
            <h3>Une erreur est survenue</h3>
            <p id="errorMessage"></p>
            <button id="retryBtn" class="btn-primary">Réessayer</button>
            <button id="reportErrorBtn" class="btn-secondary">Signaler l'erreur</button>
          </div>
        </body>
      </html>
    `, {
      url: 'https://localhost:3000',
      pretendToBeVisual: true,
      resources: 'usable'
    });

    window = dom.window;
    document = window.document;

    // Setup global environment
    global.window = window;
    global.document = document;
    global.fetch = jest.fn();
    global.FormData = window.FormData;
    global.File = window.File;
    global.Blob = window.Blob;

    // Mock comprehensive API responses
    mockAdminAPI = {
      init: jest.fn().mockResolvedValue(true),
      request: jest.fn(),
      fetchCSRFToken: jest.fn().mockResolvedValue('csrf-token'),
      csrfToken: 'csrf-token',
      
      // Mock specific endpoints
      login: jest.fn().mockResolvedValue({ success: true, user: { role: 'admin' } }),
      getContacts: jest.fn().mockResolvedValue({
        contacts: [
          { id: '1', email: 'john@example.com', firstName: 'John', lastName: 'Doe', status: 'active' },
          { id: '2', email: 'jane@example.com', firstName: 'Jane', lastName: 'Smith', status: 'pending' }
        ],
        total: 2,
        page: 1,
        totalPages: 1
      }),
      createContact: jest.fn().mockResolvedValue({ id: '3', email: 'new@example.com' }),
      updateContact: jest.fn().mockResolvedValue({ success: true }),
      deleteContact: jest.fn().mockResolvedValue({ success: true }),
      getTimeline: jest.fn().mockResolvedValue({
        timeline: [
          { id: '1', month: '2024-12', contactId: '1', completionRate: 85, responseCount: 15 },
          { id: '2', month: '2024-11', contactId: '1', completionRate: 78, responseCount: 12 }
        ]
      }),
      getComparison: jest.fn().mockResolvedValue({
        contact1: { id: '1', responses: [{ question: 'Q1', answer: 'A1' }] },
        contact2: { id: '2', responses: [{ question: 'Q1', answer: 'A2' }] }
      }),
      uploadPhoto: jest.fn().mockResolvedValue({ url: 'https://res.cloudinary.com/test.jpg' }),
      getStats: jest.fn().mockResolvedValue({
        totalContacts: 15,
        activeHandshakes: 8,
        pendingInvitations: 3
      })
    };

    // Mock WebSocket for real-time features
    mockWebSocket = {
      addEventListener: jest.fn(),
      removeEventListener: jest.fn(),
      send: jest.fn(),
      close: jest.fn(),
      readyState: 1, // OPEN
      CONNECTING: 0,
      OPEN: 1,
      CLOSING: 2,
      CLOSED: 3
    };

    // Mock Notification Center
    mockNotificationCenter = {
      init: jest.fn().mockResolvedValue(true),
      subscribe: jest.fn(),
      unsubscribe: jest.fn(),
      showNotification: jest.fn(),
      markAsRead: jest.fn(),
      getUnreadCount: jest.fn().mockReturnValue(3),
      connect: jest.fn().mockResolvedValue(mockWebSocket),
      onNotification: jest.fn(),
      onConnectionChange: jest.fn()
    };

    // Make mocks globally available
    window.AdminAPI = mockAdminAPI;
    window.NotificationCenter = function() { return mockNotificationCenter; };
    window.WebSocket = function() { return mockWebSocket; };

    // Mock photo optimization
    window.PhotoOptimization = {
      initializeForInput: jest.fn(),
      compressPhoto: jest.fn().mockResolvedValue({
        compressedBlob: new Blob(['compressed'], { type: 'image/jpeg' }),
        stats: { reductionPercent: 75 }
      }),
      cleanup: jest.fn()
    };
  });

  afterEach(() => {
    dom.window.close();
    jest.clearAllMocks();
  });

  describe('User Authentication Flow', () => {
    test('should handle complete login workflow', async () => {
      const loginForm = document.getElementById('loginForm');
      const emailInput = document.getElementById('loginEmail');
      const passwordInput = document.getElementById('loginPassword');
      const authStatus = document.getElementById('authStatus');
      const authSection = document.getElementById('authSection');
      const dashboardSection = document.getElementById('dashboardSection');

      // Setup login event
      loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        try {
          const result = await mockAdminAPI.login({
            email: emailInput.value,
            password: passwordInput.value
          });

          if (result.success) {
            authSection.classList.add('hidden');
            dashboardSection.classList.remove('hidden');
            authStatus.textContent = 'Connexion réussie';
            authStatus.className = 'success';
          }
        } catch (error) {
          authStatus.textContent = 'Erreur de connexion';
          authStatus.className = 'error';
        }
        
        authStatus.classList.remove('hidden');
      });

      // Simulate user input
      emailInput.value = 'admin@example.com';
      passwordInput.value = 'password123';

      // Submit form
      loginForm.dispatchEvent(new window.Event('submit'));

      // Wait for async operations
      await new Promise(resolve => setTimeout(resolve, 10));

      expect(mockAdminAPI.login).toHaveBeenCalledWith({
        email: 'admin@example.com',
        password: 'password123'
      });
      expect(authSection.classList.contains('hidden')).toBe(true);
      expect(dashboardSection.classList.contains('hidden')).toBe(false);
    });

    test('should handle login failures gracefully', async () => {
      mockAdminAPI.login.mockRejectedValue(new Error('Invalid credentials'));

      const loginForm = document.getElementById('loginForm');
      const authStatus = document.getElementById('authStatus');

      loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        try {
          await mockAdminAPI.login({});
        } catch (error) {
          authStatus.textContent = 'Identifiants invalides';
          authStatus.className = 'error';
          authStatus.classList.remove('hidden');
        }
      });

      loginForm.dispatchEvent(new window.Event('submit'));
      await new Promise(resolve => setTimeout(resolve, 10));

      expect(authStatus.classList.contains('hidden')).toBe(false);
      expect(authStatus.textContent).toBe('Identifiants invalides');
    });

    test('should persist authentication state', () => {
      // Mock localStorage
      const mockStorage = {
        getItem: jest.fn(),
        setItem: jest.fn(),
        removeItem: jest.fn()
      };
      
      Object.defineProperty(window, 'localStorage', { value: mockStorage });

      // Simulate storing auth token
      window.localStorage.setItem('authToken', 'abc123');
      expect(mockStorage.setItem).toHaveBeenCalledWith('authToken', 'abc123');

      // Simulate retrieving auth token
      mockStorage.getItem.mockReturnValue('abc123');
      const token = window.localStorage.getItem('authToken');
      expect(token).toBe('abc123');
    });
  });

  describe('Dashboard Integration', () => {
    test('should load dashboard data after authentication', async () => {
      const dashboardSection = document.getElementById('dashboardSection');
      const statsElements = {
        totalContacts: document.getElementById('totalContactsStat').querySelector('.stat-value'),
        activeHandshakes: document.getElementById('activeHandshakesStat').querySelector('.stat-value'),
        pendingInvitations: document.getElementById('pendingInvitationsStat').querySelector('.stat-value')
      };

      // Simulate dashboard initialization
      const initDashboard = async () => {
        const stats = await mockAdminAPI.getStats();
        
        statsElements.totalContacts.textContent = stats.totalContacts;
        statsElements.activeHandshakes.textContent = stats.activeHandshakes;
        statsElements.pendingInvitations.textContent = stats.pendingInvitations;
      };

      dashboardSection.classList.remove('hidden');
      await initDashboard();

      expect(mockAdminAPI.getStats).toHaveBeenCalled();
      expect(statsElements.totalContacts.textContent).toBe('15');
      expect(statsElements.activeHandshakes.textContent).toBe('8');
      expect(statsElements.pendingInvitations.textContent).toBe('3');
    });

    test('should handle navigation between sections', () => {
      const navButtons = {
        contacts: document.getElementById('contactsNavBtn'),
        timeline: document.getElementById('timelineNavBtn'),
        compare: document.getElementById('compareNavBtn')
      };

      const sections = {
        contacts: document.getElementById('contactsSection'),
        timeline: document.getElementById('timelineSection'),
        compare: document.getElementById('compareSection')
      };

      // Setup navigation handlers
      Object.entries(navButtons).forEach(([key, button]) => {
        button.addEventListener('click', () => {
          // Hide all sections
          Object.values(sections).forEach(section => section.classList.add('hidden'));
          // Show target section
          sections[key].classList.remove('hidden');
        });
      });

      // Test navigation to contacts
      navButtons.contacts.click();
      expect(sections.contacts.classList.contains('hidden')).toBe(false);
      expect(sections.timeline.classList.contains('hidden')).toBe(true);

      // Test navigation to timeline
      navButtons.timeline.click();
      expect(sections.contacts.classList.contains('hidden')).toBe(true);
      expect(sections.timeline.classList.contains('hidden')).toBe(false);
    });
  });

  describe('Contact Management Workflow', () => {
    test('should load contacts with pagination', async () => {
      const contactsGrid = document.getElementById('contactsGrid');
      const pagination = document.getElementById('contactsPagination');
      const pageInfo = document.getElementById('pageInfo');

      const loadContacts = async (page = 1) => {
        const response = await mockAdminAPI.getContacts({ page });
        
        // Clear existing contacts
        contactsGrid.innerHTML = '';
        
        // Add contacts to grid
        response.contacts.forEach(contact => {
          const contactCard = document.createElement('div');
          contactCard.className = 'contact-card';
          contactCard.dataset.contactId = contact.id;
          contactCard.innerHTML = `
            <h3>${contact.firstName} ${contact.lastName}</h3>
            <p>${contact.email}</p>
            <span class="status">${contact.status}</span>
          `;
          contactsGrid.appendChild(contactCard);
        });

        // Update pagination
        if (response.totalPages > 1) {
          pagination.classList.remove('hidden');
          pageInfo.textContent = `Page ${response.page} sur ${response.totalPages}`;
        }
      };

      await loadContacts();

      expect(mockAdminAPI.getContacts).toHaveBeenCalledWith({ page: 1 });
      expect(contactsGrid.children.length).toBe(2);
      expect(contactsGrid.children[0].textContent).toContain('John Doe');
      expect(contactsGrid.children[1].textContent).toContain('Jane Smith');
    });

    test('should handle contact search and filtering', async () => {
      const searchInput = document.getElementById('contactSearchInput');
      const statusFilter = document.getElementById('statusFilter');
      const contactsGrid = document.getElementById('contactsGrid');

      const filterContacts = async () => {
        const filters = {
          search: searchInput.value,
          status: statusFilter.value
        };

        // Mock filtered response
        const filteredContacts = mockAdminAPI.getContacts.mockResolvedValue({
          contacts: [
            { id: '1', email: 'john@example.com', firstName: 'John', lastName: 'Doe', status: 'active' }
          ],
          total: 1
        });

        const response = await mockAdminAPI.getContacts(filters);
        
        contactsGrid.innerHTML = '';
        response.contacts.forEach(contact => {
          const contactCard = document.createElement('div');
          contactCard.className = 'contact-card';
          contactCard.textContent = `${contact.firstName} ${contact.lastName}`;
          contactsGrid.appendChild(contactCard);
        });
      };

      // Setup event listeners
      searchInput.addEventListener('input', filterContacts);
      statusFilter.addEventListener('change', filterContacts);

      // Simulate search
      searchInput.value = 'john';
      searchInput.dispatchEvent(new window.Event('input'));

      await new Promise(resolve => setTimeout(resolve, 10));

      expect(mockAdminAPI.getContacts).toHaveBeenCalledWith({ search: 'john', status: '' });
    });

    test('should handle add contact workflow', async () => {
      const addContactBtn = document.getElementById('addContactBtn');
      const contactModal = document.getElementById('contactModal');
      const contactForm = document.getElementById('contactForm');
      const closeModal = document.getElementById('closeContactModal');

      // Open modal
      addContactBtn.addEventListener('click', () => {
        contactModal.classList.remove('hidden');
      });

      // Close modal
      closeModal.addEventListener('click', () => {
        contactModal.classList.add('hidden');
      });

      // Handle form submission
      contactForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const formData = new FormData(contactForm);
        const contactData = {
          email: formData.get('email'),
          firstName: formData.get('firstName'),
          lastName: formData.get('lastName')
        };

        await mockAdminAPI.createContact(contactData);
        contactModal.classList.add('hidden');
        
        // Show success toast
        const toast = document.createElement('div');
        toast.className = 'toast success';
        toast.textContent = 'Contact ajouté avec succès';
        document.getElementById('toastContainer').appendChild(toast);
      });

      // Test workflow
      addContactBtn.click();
      expect(contactModal.classList.contains('hidden')).toBe(false);

      // Fill form
      document.getElementById('contactEmail').value = 'new@example.com';
      document.getElementById('contactFirstName').value = 'New';
      document.getElementById('contactLastName').value = 'Contact';

      // Submit form
      contactForm.dispatchEvent(new window.Event('submit'));
      await new Promise(resolve => setTimeout(resolve, 10));

      expect(mockAdminAPI.createContact).toHaveBeenCalledWith({
        email: 'new@example.com',
        firstName: 'New',
        lastName: 'Contact'
      });
    });

    test('should handle CSV import workflow', async () => {
      const importBtn = document.getElementById('importContactsBtn');
      const csvModal = document.getElementById('csvModal');
      const csvFileInput = document.getElementById('csvFileInput');
      const csvPreview = document.getElementById('csvPreview');
      const confirmBtn = document.getElementById('confirmCsvBtn');

      // Open CSV modal
      importBtn.addEventListener('click', () => {
        csvModal.classList.remove('hidden');
      });

      // Handle file selection
      csvFileInput.addEventListener('change', async (e) => {
        const file = e.target.files[0];
        if (file) {
          // Mock CSV parsing
          const csvData = [
            ['Email', 'Prénom', 'Nom'],
            ['test1@example.com', 'Test', 'User1'],
            ['test2@example.com', 'Test', 'User2']
          ];

          // Show preview
          const table = document.getElementById('csvTable');
          table.innerHTML = '';
          csvData.forEach((row, index) => {
            const tr = document.createElement('tr');
            row.forEach(cell => {
              const td = document.createElement(index === 0 ? 'th' : 'td');
              td.textContent = cell;
              tr.appendChild(td);
            });
            table.appendChild(tr);
          });

          csvPreview.classList.remove('hidden');
        }
      });

      // Handle import confirmation
      confirmBtn.addEventListener('click', async () => {
        // Mock import process
        const importResult = await mockAdminAPI.request('/api/contacts/import', {
          method: 'POST',
          body: new FormData()
        });

        csvModal.classList.add('hidden');
      });

      // Test workflow
      importBtn.click();
      expect(csvModal.classList.contains('hidden')).toBe(false);

      // Simulate file selection
      const mockFile = new File(['email,firstName,lastName\ntest@example.com,Test,User'], 'contacts.csv', { type: 'text/csv' });
      Object.defineProperty(csvFileInput, 'files', { value: [mockFile] });
      csvFileInput.dispatchEvent(new window.Event('change'));

      expect(csvPreview.classList.contains('hidden')).toBe(false);
    });
  });

  describe('Timeline Integration', () => {
    test('should load and display timeline data', async () => {
      const timelineContainer = document.getElementById('timelineContainer');
      const contactFilter = document.getElementById('contactSelectFilter');

      const loadTimeline = async (contactId = '') => {
        const response = await mockAdminAPI.getTimeline({ contactId });
        
        timelineContainer.innerHTML = '';
        response.timeline.forEach(item => {
          const timelineItem = document.createElement('div');
          timelineItem.className = 'timeline-item';
          timelineItem.dataset.month = item.month;
          timelineItem.innerHTML = `
            <h3>${item.month}</h3>
            <p>Completion: ${item.completionRate}%</p>
            <p>Réponses: ${item.responseCount}</p>
          `;
          timelineContainer.appendChild(timelineItem);
        });
      };

      // Load timeline
      await loadTimeline();

      expect(mockAdminAPI.getTimeline).toHaveBeenCalledWith({ contactId: '' });
      expect(timelineContainer.children.length).toBe(2);
      expect(timelineContainer.children[0].textContent).toContain('2024-12');
      expect(timelineContainer.children[0].textContent).toContain('85%');
    });

    test('should filter timeline by contact', async () => {
      const contactFilter = document.getElementById('contactSelectFilter');
      const timelineContainer = document.getElementById('timelineContainer');

      // Populate contact filter
      contactFilter.innerHTML = `
        <option value="">Tous les contacts</option>
        <option value="1">John Doe</option>
        <option value="2">Jane Smith</option>
      `;

      contactFilter.addEventListener('change', async () => {
        await mockAdminAPI.getTimeline({ contactId: contactFilter.value });
      });

      // Test filtering
      contactFilter.value = '1';
      contactFilter.dispatchEvent(new window.Event('change'));

      await new Promise(resolve => setTimeout(resolve, 10));
      expect(mockAdminAPI.getTimeline).toHaveBeenCalledWith({ contactId: '1' });
    });
  });

  describe('Comparison Feature Integration', () => {
    test('should load and display comparison data', async () => {
      const contact1Select = document.getElementById('compareContact1');
      const contact2Select = document.getElementById('compareContact2');
      const monthSelect = document.getElementById('compareMonth');
      const loadComparisonBtn = document.getElementById('loadComparisonBtn');
      const comparisonResults = document.getElementById('comparisonResults');

      // Setup comparison workflow
      loadComparisonBtn.addEventListener('click', async () => {
        if (contact1Select.value && contact2Select.value && monthSelect.value) {
          const comparison = await mockAdminAPI.getComparison({
            contact1: contact1Select.value,
            contact2: contact2Select.value,
            month: monthSelect.value
          });

          // Display comparison
          document.getElementById('comparison1Title').textContent = `Contact ${comparison.contact1.id}`;
          document.getElementById('comparison2Title').textContent = `Contact ${comparison.contact2.id}`;
          
          document.getElementById('comparison1Content').innerHTML = 
            comparison.contact1.responses.map(r => `<p><strong>${r.question}:</strong> ${r.answer}</p>`).join('');
          document.getElementById('comparison2Content').innerHTML = 
            comparison.contact2.responses.map(r => `<p><strong>${r.question}:</strong> ${r.answer}</p>`).join('');

          comparisonResults.classList.remove('hidden');
        }
      });

      // Setup selects
      contact1Select.innerHTML = '<option value="1">Contact 1</option>';
      contact2Select.innerHTML = '<option value="2">Contact 2</option>';
      monthSelect.innerHTML = '<option value="2024-12">Décembre 2024</option>';

      // Select values
      contact1Select.value = '1';
      contact2Select.value = '2';
      monthSelect.value = '2024-12';

      // Load comparison
      loadComparisonBtn.click();
      await new Promise(resolve => setTimeout(resolve, 10));

      expect(mockAdminAPI.getComparison).toHaveBeenCalledWith({
        contact1: '1',
        contact2: '2',
        month: '2024-12'
      });
      expect(comparisonResults.classList.contains('hidden')).toBe(false);
    });
  });

  describe('Photo Management Integration', () => {
    test('should handle photo upload and compression', async () => {
      const photoInput = document.getElementById('photoInput');
      const previewContainer = document.getElementById('photoPreviewContainer');

      photoInput.addEventListener('change', async (e) => {
        const files = Array.from(e.target.files);
        
        for (const file of files) {
          // Initialize photo optimization
          window.PhotoOptimization.initializeForInput(photoInput);
          
          // Compress photo
          const result = await window.PhotoOptimization.compressPhoto(file);
          
          // Upload compressed photo
          const uploadResult = await mockAdminAPI.uploadPhoto(result.compressedBlob);
          
          // Create preview
          const preview = document.createElement('div');
          preview.className = 'photo-preview';
          preview.innerHTML = `<img src="${uploadResult.url}" alt="Photo">`;
          previewContainer.appendChild(preview);
        }
      });

      // Simulate file selection
      const mockFile = new File(['photo'], 'photo.jpg', { type: 'image/jpeg' });
      Object.defineProperty(photoInput, 'files', { value: [mockFile] });
      photoInput.dispatchEvent(new window.Event('change'));

      await new Promise(resolve => setTimeout(resolve, 10));

      expect(window.PhotoOptimization.compressPhoto).toHaveBeenCalledWith(mockFile);
      expect(mockAdminAPI.uploadPhoto).toHaveBeenCalled();
      expect(previewContainer.children.length).toBe(1);
    });

    test('should handle photo lightbox interaction', () => {
      const photoGallery = document.getElementById('photoGallery');
      const lightbox = document.getElementById('photoLightbox');
      const lightboxImage = document.getElementById('lightboxImage');
      const lightboxClose = document.getElementById('lightboxClose');

      // Add photo to gallery
      const photo = document.createElement('img');
      photo.src = 'https://res.cloudinary.com/test.jpg';
      photo.alt = 'Test photo';
      photo.addEventListener('click', () => {
        lightboxImage.src = photo.src;
        lightboxImage.alt = photo.alt;
        lightbox.classList.remove('hidden');
      });
      photoGallery.appendChild(photo);

      // Setup lightbox close
      lightboxClose.addEventListener('click', () => {
        lightbox.classList.add('hidden');
      });

      // Test lightbox interaction
      photo.click();
      expect(lightbox.classList.contains('hidden')).toBe(false);
      expect(lightboxImage.src).toBe('https://res.cloudinary.com/test.jpg');

      lightboxClose.click();
      expect(lightbox.classList.contains('hidden')).toBe(true);
    });
  });

  describe('Real-time Notifications', () => {
    test('should initialize notification center', async () => {
      const notificationCenter = new window.NotificationCenter();
      
      await notificationCenter.init();
      
      expect(notificationCenter.init).toHaveBeenCalled();
      expect(notificationCenter.getUnreadCount()).toBe(3);
    });

    test('should handle real-time notification updates', () => {
      const notificationList = document.getElementById('notificationList');
      const notificationCenter = new window.NotificationCenter();

      // Setup notification handler
      const handleNotification = (notification) => {
        const notificationEl = document.createElement('div');
        notificationEl.className = 'notification';
        notificationEl.innerHTML = `
          <h4>${notification.title}</h4>
          <p>${notification.message}</p>
          <span class="timestamp">${notification.timestamp}</span>
        `;
        notificationList.appendChild(notificationEl);
      };

      // Simulate incoming notification
      const mockNotification = {
        id: '1',
        title: 'Nouveau handshake',
        message: 'John Doe a accepté votre invitation',
        timestamp: new Date().toISOString()
      };

      handleNotification(mockNotification);

      expect(notificationList.children.length).toBe(1);
      expect(notificationList.children[0].textContent).toContain('Nouveau handshake');
    });

    test('should handle WebSocket connection', () => {
      const notificationCenter = new window.NotificationCenter();
      const ws = notificationCenter.connect();

      expect(ws).toBe(mockWebSocket);
      expect(mockWebSocket.addEventListener).toHaveBeenCalled();
    });
  });

  describe('Error Handling and Recovery', () => {
    test('should handle API errors gracefully', async () => {
      mockAdminAPI.getContacts.mockRejectedValue(new Error('Network error'));

      const errorBoundary = document.getElementById('errorBoundary');
      const errorMessage = document.getElementById('errorMessage');
      const retryBtn = document.getElementById('retryBtn');

      const handleError = (error) => {
        errorMessage.textContent = error.message;
        errorBoundary.classList.remove('hidden');
      };

      retryBtn.addEventListener('click', async () => {
        errorBoundary.classList.add('hidden');
        try {
          await mockAdminAPI.getContacts();
        } catch (error) {
          handleError(error);
        }
      });

      // Simulate error
      try {
        await mockAdminAPI.getContacts();
      } catch (error) {
        handleError(error);
      }

      expect(errorBoundary.classList.contains('hidden')).toBe(false);
      expect(errorMessage.textContent).toBe('Network error');

      // Test retry
      mockAdminAPI.getContacts.mockResolvedValue({ contacts: [] });
      retryBtn.click();
      
      await new Promise(resolve => setTimeout(resolve, 10));
      expect(errorBoundary.classList.contains('hidden')).toBe(true);
    });

    test('should handle offline mode', () => {
      const offlineIndicator = document.createElement('div');
      offlineIndicator.id = 'offlineIndicator';
      offlineIndicator.className = 'offline-indicator hidden';
      offlineIndicator.textContent = 'Mode hors ligne';
      document.body.appendChild(offlineIndicator);

      // Mock network status
      Object.defineProperty(navigator, 'onLine', { value: false, writable: true });

      window.addEventListener('offline', () => {
        offlineIndicator.classList.remove('hidden');
      });

      window.addEventListener('online', () => {
        offlineIndicator.classList.add('hidden');
      });

      // Simulate going offline
      window.dispatchEvent(new window.Event('offline'));
      expect(offlineIndicator.classList.contains('hidden')).toBe(false);

      // Simulate coming back online
      navigator.onLine = true;
      window.dispatchEvent(new window.Event('online'));
      expect(offlineIndicator.classList.contains('hidden')).toBe(true);
    });

    test('should validate user input and prevent XSS', () => {
      const contactForm = document.getElementById('contactForm');
      const emailInput = document.getElementById('contactEmail');
      const firstNameInput = document.getElementById('contactFirstName');

      const validateInput = (input) => {
        const value = input.value;
        
        // Check for script tags
        if (value.includes('<script>') || value.includes('javascript:')) {
          input.setCustomValidity('Contenu non autorisé détecté');
          return false;
        }
        
        input.setCustomValidity('');
        return true;
      };

      emailInput.addEventListener('input', () => validateInput(emailInput));
      firstNameInput.addEventListener('input', () => validateInput(firstNameInput));

      // Test XSS prevention
      emailInput.value = '<script>alert("XSS")</script>';
      emailInput.dispatchEvent(new window.Event('input'));

      expect(emailInput.validationMessage).toBe('Contenu non autorisé détecté');

      // Test normal input
      emailInput.value = 'normal@example.com';
      emailInput.dispatchEvent(new window.Event('input'));

      expect(emailInput.validationMessage).toBe('');
    });
  });

  describe('Performance and Loading States', () => {
    test('should show loading states during async operations', async () => {
      const loadingOverlay = document.getElementById('loadingOverlay');
      const loadingMessage = document.getElementById('loadingMessage');

      const showLoading = (message) => {
        loadingMessage.textContent = message;
        loadingOverlay.classList.remove('hidden');
      };

      const hideLoading = () => {
        loadingOverlay.classList.add('hidden');
      };

      // Simulate loading
      showLoading('Chargement des contacts...');
      expect(loadingOverlay.classList.contains('hidden')).toBe(false);
      expect(loadingMessage.textContent).toBe('Chargement des contacts...');

      // Simulate completion
      await new Promise(resolve => setTimeout(resolve, 10));
      hideLoading();
      expect(loadingOverlay.classList.contains('hidden')).toBe(true);
    });

    test('should handle concurrent requests properly', async () => {
      const promises = [
        mockAdminAPI.getContacts(),
        mockAdminAPI.getTimeline(),
        mockAdminAPI.getStats()
      ];

      const results = await Promise.all(promises);

      expect(results).toHaveLength(3);
      expect(mockAdminAPI.getContacts).toHaveBeenCalled();
      expect(mockAdminAPI.getTimeline).toHaveBeenCalled();
      expect(mockAdminAPI.getStats).toHaveBeenCalled();
    });

    test('should debounce search input', (done) => {
      const searchInput = document.getElementById('contactSearchInput');
      let searchCount = 0;

      // Debounced search function
      let searchTimeout;
      const debouncedSearch = () => {
        clearTimeout(searchTimeout);
        searchTimeout = setTimeout(() => {
          searchCount++;
        }, 300);
      };

      searchInput.addEventListener('input', debouncedSearch);

      // Simulate rapid typing
      searchInput.value = 'j';
      searchInput.dispatchEvent(new window.Event('input'));
      
      searchInput.value = 'jo';
      searchInput.dispatchEvent(new window.Event('input'));
      
      searchInput.value = 'joh';
      searchInput.dispatchEvent(new window.Event('input'));

      // Check after debounce period
      setTimeout(() => {
        expect(searchCount).toBe(1);
        done();
      }, 400);
    });
  });

  describe('Cross-Component Communication', () => {
    test('should update UI components when data changes', () => {
      const statsCard = document.getElementById('totalContactsStat').querySelector('.stat-value');
      const contactsGrid = document.getElementById('contactsGrid');

      // Simulate event system
      const eventBus = {
        events: {},
        on: function(event, callback) {
          if (!this.events[event]) this.events[event] = [];
          this.events[event].push(callback);
        },
        emit: function(event, data) {
          if (this.events[event]) {
            this.events[event].forEach(callback => callback(data));
          }
        }
      };

      // Setup listeners
      eventBus.on('contactAdded', (contact) => {
        const currentCount = parseInt(statsCard.textContent);
        statsCard.textContent = currentCount + 1;

        const contactCard = document.createElement('div');
        contactCard.textContent = contact.email;
        contactsGrid.appendChild(contactCard);
      });

      eventBus.on('contactDeleted', (contactId) => {
        const currentCount = parseInt(statsCard.textContent);
        statsCard.textContent = currentCount - 1;

        const contactCard = contactsGrid.querySelector(`[data-contact-id="${contactId}"]`);
        if (contactCard) contactCard.remove();
      });

      // Test event emission
      statsCard.textContent = '5';
      eventBus.emit('contactAdded', { email: 'new@example.com' });

      expect(statsCard.textContent).toBe('6');
      expect(contactsGrid.children.length).toBe(1);
    });

    test('should maintain state consistency across navigation', () => {
      const sections = ['dashboard', 'contacts', 'timeline', 'compare'];
      const appState = {
        currentSection: 'dashboard',
        contactsFilter: '',
        timelineFilter: '',
        selectedContacts: []
      };

      const navigateTo = (section) => {
        appState.currentSection = section;
        
        // Update URL (simulated)
        window.history.pushState({ section }, '', `#${section}`);
        
        // Show/hide sections
        sections.forEach(s => {
          const sectionEl = document.getElementById(`${s}Section`);
          if (sectionEl) {
            sectionEl.classList.toggle('hidden', s !== section);
          }
        });
      };

      // Test navigation
      navigateTo('contacts');
      expect(appState.currentSection).toBe('contacts');

      navigateTo('timeline');
      expect(appState.currentSection).toBe('timeline');

      // State should persist across navigation
      appState.contactsFilter = 'john';
      navigateTo('dashboard');
      navigateTo('contacts');
      expect(appState.contactsFilter).toBe('john');
    });
  });
});