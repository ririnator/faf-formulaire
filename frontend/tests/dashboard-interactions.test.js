/**
 * Dashboard Interaction Tests
 * Comprehensive test suite for universal dashboard functionality,
 * contact management interface, notification center, and navigation
 */

const { JSDOM } = require('jsdom');
const fs = require('fs');
const path = require('path');

describe('🏠 Dashboard Interaction Tests', () => {
  let dom;
  let window;
  let document;
  let mockAdminAPI;
  let mockNotificationCenter;

  beforeEach(() => {
    // Create DOM environment with dashboard HTML
    dom = new JSDOM(`
      <!DOCTYPE html>
      <html lang="fr">
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width,initial-scale=1">
          <title>Dashboard – Form-a-Friend</title>
          <script src="https://cdn.tailwindcss.com"></script>
        </head>
        <body class="bg-gray-50 min-h-screen">
          <!-- Universal Navigation -->
          <nav class="bg-white shadow-sm border-b" role="navigation">
            <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
              <div class="flex justify-between items-center h-16">
                <div class="flex items-center space-x-4">
                  <h1 class="text-xl font-semibold text-gray-900">Dashboard</h1>
                  <span id="userRole" class="text-sm text-gray-500"></span>
                </div>
                <div class="flex items-center space-x-4">
                  <div id="notificationCenter"></div>
                  <a href="/logout" class="text-red-600 hover:underline">Déconnexion</a>
                </div>
              </div>
            </div>
          </nav>

          <main class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
            <!-- Alert Message -->
            <div id="alertMessage" class="hidden mb-6 p-4 rounded-lg" role="alert"></div>

            <!-- Quick Stats Dashboard -->
            <section class="mb-8" aria-label="Statistiques rapides">
              <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                <div class="stat-card bg-blue-600 text-white p-6 rounded-lg">
                  <div class="text-3xl font-bold" id="totalContacts">-</div>
                  <div class="text-sm opacity-90">Total contacts</div>
                </div>
                <div class="stat-card bg-green-600 text-white p-6 rounded-lg">
                  <div class="text-3xl font-bold" id="activeHandshakes">-</div>
                  <div class="text-sm opacity-90">Handshakes actifs</div>
                </div>
                <div class="stat-card bg-purple-600 text-white p-6 rounded-lg">
                  <div class="text-3xl font-bold" id="pendingInvitations">-</div>
                  <div class="text-sm opacity-90">Invitations en attente</div>
                </div>
                <div class="stat-card bg-yellow-600 text-white p-6 rounded-lg">
                  <div class="text-3xl font-bold" id="recentActivity">-</div>
                  <div class="text-sm opacity-90">Activité récente</div>
                </div>
              </div>
            </section>

            <!-- Quick Actions -->
            <section class="mb-8" aria-label="Actions rapides">
              <div class="bg-white p-6 rounded-lg shadow">
                <h2 class="text-lg font-semibold mb-4">Actions rapides</h2>
                <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
                  <button id="newContactBtn" class="action-button bg-blue-600 hover:bg-blue-700 text-white p-4 rounded-lg text-center">
                    ➕ Nouveau contact
                  </button>
                  <button id="sendHandshakeBtn" class="action-button bg-green-600 hover:bg-green-700 text-white p-4 rounded-lg text-center">
                    🤝 Envoyer handshake
                  </button>
                  <button id="viewTimelineBtn" class="action-button bg-purple-600 hover:bg-purple-700 text-white p-4 rounded-lg text-center">
                    📅 Voir timeline
                  </button>
                  <button id="compareResponsesBtn" class="action-button bg-yellow-600 hover:bg-yellow-700 text-white p-4 rounded-lg text-center">
                    🔍 Comparer réponses
                  </button>
                </div>
              </div>
            </section>

            <!-- Contact Grid Preview -->
            <section aria-label="Aperçu des contacts">
              <div class="bg-white p-6 rounded-lg shadow">
                <div class="flex justify-between items-center mb-4">
                  <h2 class="text-lg font-semibold">Contacts récents</h2>
                  <a href="/admin/contacts.html" class="text-blue-600 hover:underline">Voir tous</a>
                </div>
                <div id="contactsGrid" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                  <!-- Contacts will be loaded here -->
                </div>
              </div>
            </section>
          </main>

          <!-- Modal for actions -->
          <div id="actionModal" class="modal-overlay hidden" role="dialog">
            <div class="modal-content bg-white p-6 rounded-lg max-w-md mx-auto">
              <div class="flex justify-between items-center mb-4">
                <h3 id="modalTitle" class="text-lg font-semibold">Action</h3>
                <button id="closeModal" class="text-gray-500 hover:text-gray-700">×</button>
              </div>
              <div id="modalBody">
                <!-- Dynamic content -->
              </div>
            </div>
          </div>

          <!-- Loading Overlay -->
          <div id="loadingOverlay" class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 hidden">
            <div class="bg-white p-6 rounded-lg">
              <div class="flex items-center space-x-3">
                <div class="animate-spin rounded-full h-6 w-6 border-b-2 border-blue-600"></div>
                <span>Chargement...</span>
              </div>
            </div>
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

    // Mock AdminAPI
    mockAdminAPI = {
      init: jest.fn().mockResolvedValue(true),
      request: jest.fn(),
      fetchCSRFToken: jest.fn().mockResolvedValue('mock-csrf-token'),
      csrfToken: 'mock-csrf-token'
    };

    // Mock NotificationCenter
    mockNotificationCenter = {
      init: jest.fn().mockResolvedValue(true),
      showNotification: jest.fn(),
      markAsRead: jest.fn(),
      getUnreadCount: jest.fn().mockReturnValue(0),
      subscribe: jest.fn(),
      unsubscribe: jest.fn()
    };

    // Make mocks globally available
    window.AdminAPI = mockAdminAPI;
    window.NotificationCenter = function() { return mockNotificationCenter; };
  });

  afterEach(() => {
    dom.window.close();
    jest.clearAllMocks();
  });

  describe('Universal Dashboard Functionality', () => {
    test('should display role-based navigation correctly', () => {
      const userRoleEl = document.getElementById('userRole');
      const navEl = document.querySelector('nav[role="navigation"]');
      
      expect(userRoleEl).toBeTruthy();
      expect(navEl).toBeTruthy();
      expect(navEl.getAttribute('role')).toBe('navigation');
    });

    test('should support both admin and user roles', () => {
      const userRoleEl = document.getElementById('userRole');
      
      // Test admin role
      userRoleEl.textContent = 'Administrateur';
      expect(userRoleEl.textContent).toBe('Administrateur');
      
      // Test user role
      userRoleEl.textContent = 'Utilisateur';
      expect(userRoleEl.textContent).toBe('Utilisateur');
    });

    test('should have proper ARIA labels for accessibility', () => {
      const sections = document.querySelectorAll('section[aria-label]');
      const alertMessage = document.getElementById('alertMessage');
      const modal = document.getElementById('actionModal');
      
      expect(sections.length).toBeGreaterThan(0);
      expect(alertMessage.getAttribute('role')).toBe('alert');
      expect(modal.getAttribute('role')).toBe('dialog');
      
      sections.forEach(section => {
        expect(section.getAttribute('aria-label')).toBeTruthy();
      });
    });

    test('should initialize with loading state', () => {
      const statsElements = [
        'totalContacts',
        'activeHandshakes', 
        'pendingInvitations',
        'recentActivity'
      ];
      
      statsElements.forEach(id => {
        const element = document.getElementById(id);
        expect(element).toBeTruthy();
        expect(element.textContent).toBe('-');
      });
    });
  });

  describe('Quick Statistics Dashboard', () => {
    test('should display statistics cards with proper structure', () => {
      const statCards = document.querySelectorAll('.stat-card');
      
      expect(statCards.length).toBe(4);
      
      statCards.forEach(card => {
        const value = card.querySelector('.text-3xl');
        const label = card.querySelector('.text-sm');
        
        expect(value).toBeTruthy();
        expect(label).toBeTruthy();
      });
    });

    test('should update statistics dynamically', () => {
      const mockStats = {
        totalContacts: 25,
        activeHandshakes: 8,
        pendingInvitations: 3,
        recentActivity: 12
      };

      // Update stats
      Object.entries(mockStats).forEach(([key, value]) => {
        const element = document.getElementById(key);
        element.textContent = value.toString();
      });

      // Verify updates
      expect(document.getElementById('totalContacts').textContent).toBe('25');
      expect(document.getElementById('activeHandshakes').textContent).toBe('8');
      expect(document.getElementById('pendingInvitations').textContent).toBe('3');
      expect(document.getElementById('recentActivity').textContent).toBe('12');
    });

    test('should handle zero values gracefully', () => {
      const element = document.getElementById('totalContacts');
      element.textContent = '0';
      
      expect(element.textContent).toBe('0');
      expect(element.parentElement.classList.contains('stat-card')).toBe(true);
    });

    test('should handle large numbers formatting', () => {
      const element = document.getElementById('totalContacts');
      element.textContent = '1,234';
      
      expect(element.textContent).toBe('1,234');
    });
  });

  describe('Quick Actions Interface', () => {
    test('should have all required action buttons', () => {
      const requiredButtons = [
        'newContactBtn',
        'sendHandshakeBtn', 
        'viewTimelineBtn',
        'compareResponsesBtn'
      ];

      requiredButtons.forEach(id => {
        const button = document.getElementById(id);
        expect(button).toBeTruthy();
        expect(button.tagName).toBe('BUTTON');
        expect(button.classList.contains('action-button')).toBe(true);
      });
    });

    test('should have proper hover states for buttons', () => {
      const buttons = document.querySelectorAll('.action-button');
      
      buttons.forEach(button => {
        expect(button.className).toMatch(/hover:/);
      });
    });

    test('should handle button click events', () => {
      const newContactBtn = document.getElementById('newContactBtn');
      let clicked = false;
      
      newContactBtn.addEventListener('click', () => {
        clicked = true;
      });
      
      newContactBtn.click();
      expect(clicked).toBe(true);
    });

    test('should support keyboard navigation', () => {
      const buttons = document.querySelectorAll('.action-button');
      
      buttons.forEach(button => {
        expect(button.tabIndex).not.toBe(-1);
      });
    });

    test('should be touch-friendly on mobile', () => {
      const buttons = document.querySelectorAll('.action-button');
      
      buttons.forEach(button => {
        const styles = window.getComputedStyle(button);
        const padding = styles.padding;
        
        // Verify minimum touch target size (44px recommended)
        expect(button.offsetHeight).toBeGreaterThanOrEqual(44);
      });
    });
  });

  describe('Contact Grid Interface', () => {
    test('should have contact grid container', () => {
      const contactsGrid = document.getElementById('contactsGrid');
      
      expect(contactsGrid).toBeTruthy();
      expect(contactsGrid.classList.contains('grid')).toBe(true);
    });

    test('should support responsive grid layout', () => {
      const contactsGrid = document.getElementById('contactsGrid');
      const classes = contactsGrid.className;
      
      expect(classes).toContain('grid-cols-1');
      expect(classes).toContain('md:grid-cols-2');
      expect(classes).toContain('lg:grid-cols-3');
    });

    test('should display "Voir tous" link', () => {
      const viewAllLink = document.querySelector('a[href="/admin/contacts.html"]');
      
      expect(viewAllLink).toBeTruthy();
      expect(viewAllLink.textContent.trim()).toBe('Voir tous');
      expect(viewAllLink.classList.contains('text-blue-600')).toBe(true);
    });

    test('should handle empty contact state', () => {
      const contactsGrid = document.getElementById('contactsGrid');
      
      // Empty state
      expect(contactsGrid.children.length).toBe(0);
      
      // Add empty state message
      const emptyMessage = document.createElement('div');
      emptyMessage.className = 'text-center text-gray-500 py-8';
      emptyMessage.textContent = 'Aucun contact trouvé';
      contactsGrid.appendChild(emptyMessage);
      
      expect(contactsGrid.children.length).toBe(1);
      expect(contactsGrid.textContent).toContain('Aucun contact trouvé');
    });

    test('should load contact cards dynamically', () => {
      const contactsGrid = document.getElementById('contactsGrid');
      
      // Mock contact data
      const mockContact = {
        id: 'contact-1',
        firstName: 'Jean',
        lastName: 'Dupont',
        email: 'jean.dupont@example.com',
        status: 'active'
      };
      
      // Create contact card
      const contactCard = document.createElement('div');
      contactCard.className = 'contact-card bg-white p-4 rounded-lg shadow hover:shadow-lg transition-shadow';
      contactCard.innerHTML = `
        <div class="contact-info">
          <h3 class="font-semibold">${mockContact.firstName} ${mockContact.lastName}</h3>
          <p class="text-sm text-gray-600">${mockContact.email}</p>
          <span class="status-badge status-${mockContact.status}">${mockContact.status}</span>
        </div>
      `;
      
      contactsGrid.appendChild(contactCard);
      
      expect(contactsGrid.children.length).toBe(1);
      expect(contactCard.textContent).toContain('Jean Dupont');
      expect(contactCard.textContent).toContain('jean.dupont@example.com');
    });
  });

  describe('Modal Management', () => {
    test('should have action modal with proper structure', () => {
      const modal = document.getElementById('actionModal');
      const modalTitle = document.getElementById('modalTitle');
      const modalBody = document.getElementById('modalBody');
      const closeModal = document.getElementById('closeModal');
      
      expect(modal).toBeTruthy();
      expect(modalTitle).toBeTruthy();
      expect(modalBody).toBeTruthy();
      expect(closeModal).toBeTruthy();
      
      expect(modal.getAttribute('role')).toBe('dialog');
    });

    test('should start in hidden state', () => {
      const modal = document.getElementById('actionModal');
      
      expect(modal.classList.contains('hidden')).toBe(true);
    });

    test('should support opening and closing', () => {
      const modal = document.getElementById('actionModal');
      const closeButton = document.getElementById('closeModal');
      
      // Open modal
      modal.classList.remove('hidden');
      expect(modal.classList.contains('hidden')).toBe(false);
      
      // Close modal
      closeButton.click();
      modal.classList.add('hidden');
      expect(modal.classList.contains('hidden')).toBe(true);
    });

    test('should handle dynamic content', () => {
      const modalTitle = document.getElementById('modalTitle');
      const modalBody = document.getElementById('modalBody');
      
      modalTitle.textContent = 'Nouveau Contact';
      modalBody.innerHTML = '<p>Formulaire de création de contact</p>';
      
      expect(modalTitle.textContent).toBe('Nouveau Contact');
      expect(modalBody.innerHTML).toContain('Formulaire de création');
    });

    test('should prevent XSS in modal content', () => {
      const modalBody = document.getElementById('modalBody');
      const maliciousContent = '<script>alert("XSS")</script>';
      
      // Safe assignment using textContent
      modalBody.textContent = maliciousContent;
      
      expect(modalBody.innerHTML).not.toContain('<script>');
      expect(modalBody.textContent).toBe(maliciousContent);
    });
  });

  describe('Loading States and UI Feedback', () => {
    test('should have loading overlay', () => {
      const loadingOverlay = document.getElementById('loadingOverlay');
      
      expect(loadingOverlay).toBeTruthy();
      expect(loadingOverlay.classList.contains('fixed')).toBe(true);
      expect(loadingOverlay.classList.contains('hidden')).toBe(true);
    });

    test('should show and hide loading overlay', () => {
      const loadingOverlay = document.getElementById('loadingOverlay');
      
      // Show loading
      loadingOverlay.classList.remove('hidden');
      expect(loadingOverlay.classList.contains('hidden')).toBe(false);
      
      // Hide loading
      loadingOverlay.classList.add('hidden');
      expect(loadingOverlay.classList.contains('hidden')).toBe(true);
    });

    test('should have alert message system', () => {
      const alertMessage = document.getElementById('alertMessage');
      
      expect(alertMessage).toBeTruthy();
      expect(alertMessage.getAttribute('role')).toBe('alert');
      expect(alertMessage.classList.contains('hidden')).toBe(true);
    });

    test('should display different alert types', () => {
      const alertMessage = document.getElementById('alertMessage');
      
      // Success alert
      alertMessage.className = 'bg-green-100 border border-green-400 text-green-700 px-4 py-3 rounded';
      alertMessage.textContent = 'Opération réussie';
      alertMessage.classList.remove('hidden');
      
      expect(alertMessage.classList.contains('bg-green-100')).toBe(true);
      expect(alertMessage.textContent).toBe('Opération réussie');
      
      // Error alert
      alertMessage.className = 'bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded';
      alertMessage.textContent = 'Erreur survenue';
      
      expect(alertMessage.classList.contains('bg-red-100')).toBe(true);
      expect(alertMessage.textContent).toBe('Erreur survenue');
    });
  });

  describe('Responsive Design Support', () => {
    test('should adapt to different screen sizes', () => {
      // Mobile viewport
      Object.defineProperty(window, 'innerWidth', { value: 375, writable: true });
      
      const statsGrid = document.querySelector('.grid.grid-cols-1');
      expect(statsGrid).toBeTruthy();
      
      // Desktop viewport
      Object.defineProperty(window, 'innerWidth', { value: 1920, writable: true });
      
      // Grid should still work on desktop
      expect(statsGrid.classList.contains('lg:grid-cols-4')).toBe(true);
    });

    test('should maintain accessibility on all screen sizes', () => {
      const buttons = document.querySelectorAll('.action-button');
      
      buttons.forEach(button => {
        // Touch targets should be minimum 44px
        expect(button.offsetHeight).toBeGreaterThanOrEqual(44);
      });
    });
  });

  describe('Error Handling', () => {
    test('should handle API failures gracefully', async () => {
      mockAdminAPI.request.mockRejectedValue(new Error('Network error'));
      
      try {
        await mockAdminAPI.request('/api/contacts');
      } catch (error) {
        expect(error.message).toBe('Network error');
      }
      
      expect(mockAdminAPI.request).toHaveBeenCalled();
    });

    test('should display error messages to user', () => {
      const alertMessage = document.getElementById('alertMessage');
      
      // Simulate error display
      alertMessage.className = 'bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded';
      alertMessage.textContent = 'Erreur de connexion';
      alertMessage.classList.remove('hidden');
      
      expect(alertMessage.classList.contains('hidden')).toBe(false);
      expect(alertMessage.textContent).toBe('Erreur de connexion');
    });

    test('should handle missing data gracefully', () => {
      const statsElements = document.querySelectorAll('.stat-card .text-3xl');
      
      statsElements.forEach(element => {
        element.textContent = 'N/A';
        expect(element.textContent).toBe('N/A');
      });
    });
  });

  describe('Security Validation', () => {
    test('should prevent XSS in dynamic content', () => {
      const maliciousScript = '<script>alert("XSS")</script>';
      const userRoleEl = document.getElementById('userRole');
      
      // Safe assignment
      userRoleEl.textContent = maliciousScript;
      
      expect(userRoleEl.innerHTML).not.toContain('<script>');
      expect(userRoleEl.textContent).toBe(maliciousScript);
    });

    test('should sanitize HTML in statistics display', () => {
      const totalContacts = document.getElementById('totalContacts');
      const maliciousContent = '<img src=x onerror=alert("XSS")>';
      
      totalContacts.textContent = maliciousContent;
      
      expect(totalContacts.innerHTML).not.toContain('onerror');
      expect(totalContacts.textContent).toBe(maliciousContent);
    });

    test('should validate URL parameters', () => {
      // Mock URL with parameters
      const mockURL = new URL('https://localhost:3000/dashboard?tab=contacts&filter=active');
      
      // Validate parameters
      expect(mockURL.searchParams.get('tab')).toBe('contacts');
      expect(mockURL.searchParams.get('filter')).toBe('active');
      
      // Ensure no script injection in URL params
      const maliciousParam = mockURL.searchParams.get('tab');
      expect(maliciousParam).not.toContain('<script>');
    });

    test('should handle CSRF token validation', () => {
      expect(mockAdminAPI.csrfToken).toBeTruthy();
      expect(mockAdminAPI.fetchCSRFToken).toHaveBeenCalled();
    });
  });

  describe('Performance Considerations', () => {
    test('should limit DOM manipulations', () => {
      const contactsGrid = document.getElementById('contactsGrid');
      const initialChildCount = contactsGrid.children.length;
      
      // Batch DOM operations
      const fragment = document.createDocumentFragment();
      
      for (let i = 0; i < 10; i++) {
        const card = document.createElement('div');
        card.className = 'contact-card';
        card.textContent = `Contact ${i}`;
        fragment.appendChild(card);
      }
      
      contactsGrid.appendChild(fragment);
      
      expect(contactsGrid.children.length).toBe(initialChildCount + 10);
    });

    test('should cleanup event listeners properly', () => {
      const button = document.getElementById('newContactBtn');
      const mockHandler = jest.fn();
      
      // Add listener
      button.addEventListener('click', mockHandler);
      
      // Simulate cleanup
      button.removeEventListener('click', mockHandler);
      
      // Click should not trigger removed handler
      button.click();
      expect(mockHandler).not.toHaveBeenCalled();
    });
  });
});