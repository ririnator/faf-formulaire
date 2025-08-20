/**
 * Dashboard Module - ES6 module for Form-a-Friend dashboard functionality
 * Follows FAF architecture patterns from faf-admin.js with security-first approach
 */

// Import required modules from faf-admin.js
import { AdminAPI, Utils, UI, Charts, SAFE_HTML_ENTITIES } from '/admin/faf-admin.js';

// =============================================================================
// DASHBOARD API - Extends AdminAPI for dashboard-specific functionality
// =============================================================================

export class DashboardAPI extends AdminAPI {
  /**
   * Get user dashboard data
   */
  static async getDashboardData() {
    return await this.request('/api/dashboard', {}, 'Erreur lors du chargement du tableau de bord');
  }

  /**
   * Get user contacts with pagination and filtering
   */
  static async getContacts(options = {}) {
    const params = new URLSearchParams(options);
    return await this.request(`/api/contacts?${params}`, {}, 'Erreur lors du chargement des contacts');
  }

  /**
   * Create a new contact
   */
  static async createContact(contactData) {
    return await this.request('/api/contacts', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(contactData)
    }, 'Erreur lors de la création du contact');
  }

  /**
   * Update an existing contact
   */
  static async updateContact(contactId, contactData) {
    return await this.request(`/api/contacts/${contactId}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(contactData)
    }, 'Erreur lors de la mise à jour du contact');
  }

  /**
   * Delete a contact
   */
  static async deleteContact(contactId) {
    return await this.request(`/api/contacts/${contactId}`, {
      method: 'DELETE'
    }, 'Erreur lors de la suppression du contact');
  }

  /**
   * Send handshake to contact
   */
  static async sendHandshake(contactId) {
    return await this.request(`/api/handshakes`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ contactId })
    }, 'Erreur lors de l\'envoi du handshake');
  }

  /**
   * Get user responses with month filtering
   */
  static async getUserResponses(month = null) {
    const params = month ? `?month=${month}` : '';
    return await this.request(`/api/responses/user${params}`, {}, 'Erreur lors du chargement des réponses');
  }

  /**
   * Get comparison data between user and contact
   */
  static async getComparisonData(contactId, month) {
    return await this.request(`/api/responses/compare/${contactId}?month=${month}`, {}, 'Erreur lors du chargement de la comparaison');
  }

  /**
   * Submit monthly form response
   */
  static async submitResponse(responseData) {
    return await this.request('/api/responses', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(responseData)
    }, 'Erreur lors de la soumission du formulaire');
  }

  /**
   * Get current month form status
   */
  static async getFormStatus() {
    return await this.request('/api/responses/status', {}, 'Erreur lors de la vérification du statut du formulaire');
  }

  /**
   * Get current month status with submission info
   */
  static async getCurrentMonthStatus() {
    return await this.request('/api/responses/current', {}, 'Erreur lors de la vérification du statut du mois');
  }

  /**
   * Upload photo with compression
   */
  static async uploadPhoto(file, options = {}) {
    // Use photo compression if available
    let processedFile = file;
    if (window.PhotoOptimization) {
      try {
        const compressionResult = await window.PhotoOptimization.compressor.compressPhoto(file, {
          quality: options.quality || 'medium',
          maxWidth: options.maxWidth || 1920,
          maxHeight: options.maxHeight || 1080
        });
        processedFile = compressionResult.compressedBlob;
      } catch (error) {
        console.warn('Photo compression failed, using original file:', error);
      }
    }

    const formData = new FormData();
    formData.append('photo', processedFile);

    return await this.request('/api/upload', {
      method: 'POST',
      body: formData
    }, 'Erreur lors du téléchargement de la photo');
  }
}

// =============================================================================
// DASHBOARD UTILITIES - Extends Utils with dashboard-specific functions
// =============================================================================

export const DashboardUtils = {
  ...Utils,

  /**
   * Format contact name for display
   */
  formatContactName(contact) {
    if (!contact) return 'Contact inconnu';
    
    const firstName = Utils.unescapeHTML(contact.firstName || '');
    const lastName = Utils.unescapeHTML(contact.lastName || '');
    const email = Utils.unescapeHTML(contact.email || '');
    
    if (firstName || lastName) {
      return `${firstName} ${lastName}`.trim();
    }
    
    return email;
  },

  /**
   * Get contact initials for avatar
   */
  getContactInitials(contact) {
    if (!contact) return '?';
    
    const firstName = Utils.unescapeHTML(contact.firstName || '');
    const lastName = Utils.unescapeHTML(contact.lastName || '');
    const email = Utils.unescapeHTML(contact.email || '');
    
    if (firstName || lastName) {
      const firstInitial = firstName.charAt(0).toUpperCase();
      const lastInitial = lastName.charAt(0).toUpperCase();
      return `${firstInitial}${lastInitial}`.slice(0, 2);
    }
    
    return email.charAt(0).toUpperCase();
  },

  /**
   * Format month for display
   */
  formatMonth(monthString) {
    if (!monthString) return '';
    
    const [year, month] = monthString.split('-');
    const date = new Date(year, month - 1);
    
    return date.toLocaleDateString('fr-FR', {
      year: 'numeric',
      month: 'long'
    });
  },

  /**
   * Get current month in YYYY-MM format
   */
  getCurrentMonth() {
    const now = new Date();
    return `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;
  },

  /**
   * Get month offset (e.g., -1 for last month)
   */
  getMonthOffset(offset = 0) {
    const now = new Date();
    now.setMonth(now.getMonth() + offset);
    return `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;
  },

  /**
   * Validate email format
   */
  isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  },

  /**
   * Truncate text for display
   */
  truncateText(text, maxLength = 100) {
    if (!text || text.length <= maxLength) return text;
    return text.slice(0, maxLength) + '...';
  },

  /**
   * Get status color class
   */
  getStatusColorClass(status) {
    const statusColors = {
      'active': 'text-green-600 bg-green-100',
      'pending': 'text-yellow-600 bg-yellow-100',
      'declined': 'text-red-600 bg-red-100',
      'blocked': 'text-gray-600 bg-gray-100'
    };
    
    return statusColors[status] || 'text-gray-600 bg-gray-100';
  },

  /**
   * Generate shareable URL for response
   */
  generateShareUrl(responseId, token) {
    const baseUrl = window.location.origin;
    return `${baseUrl}/view.html?id=${responseId}&token=${token}`;
  }
};

// =============================================================================
// DASHBOARD UI COMPONENTS - Extends UI with dashboard-specific components
// =============================================================================

export const DashboardUI = {
  ...UI,

  /**
   * Create contact card element
   */
  createContactCard(contact) {
    const card = document.createElement('div');
    card.className = 'contact-card bg-white rounded-lg shadow-sm p-4 hover:shadow-md transition-shadow cursor-pointer';
    card.dataset.contactId = contact.id;

    // Avatar
    const avatar = document.createElement('div');
    avatar.className = 'contact-avatar w-12 h-12 rounded-full bg-gradient-to-br from-blue-500 to-purple-600 text-white flex items-center justify-center font-bold text-lg mb-3 mx-auto';
    avatar.textContent = DashboardUtils.getContactInitials(contact);

    // Name
    const name = document.createElement('h3');
    name.className = 'text-lg font-semibold text-gray-900 text-center mb-1';
    name.textContent = DashboardUtils.formatContactName(contact);

    // Email
    const email = document.createElement('p');
    email.className = 'text-sm text-gray-500 text-center mb-3';
    email.textContent = Utils.unescapeHTML(contact.email || '');

    // Status
    const status = document.createElement('div');
    status.className = 'flex items-center justify-center';
    
    const statusIndicator = document.createElement('span');
    statusIndicator.className = `status-indicator w-2 h-2 rounded-full mr-2 status-${contact.status || 'unknown'}`;
    
    const statusText = document.createElement('span');
    statusText.className = 'text-xs font-medium';
    statusText.textContent = contact.status || 'Inconnu';
    
    status.appendChild(statusIndicator);
    status.appendChild(statusText);

    // Assemble card
    card.appendChild(avatar);
    card.appendChild(name);
    card.appendChild(email);
    card.appendChild(status);

    return card;
  },

  /**
   * Create response timeline item
   */
  createTimelineItem(response) {
    const item = document.createElement('div');
    item.className = 'timeline-item flex items-start space-x-4 p-4 border-l-4 border-blue-200 bg-blue-50 rounded-r-lg mb-4';

    // Date indicator
    const dateIndicator = document.createElement('div');
    dateIndicator.className = 'flex-shrink-0 w-12 h-12 bg-blue-600 text-white rounded-full flex items-center justify-center font-bold';
    const month = response.month ? response.month.split('-')[1] : '?';
    dateIndicator.textContent = month;

    // Content
    const content = document.createElement('div');
    content.className = 'flex-1 min-w-0';

    const title = document.createElement('h4');
    title.className = 'text-lg font-semibold text-gray-900 mb-1';
    title.textContent = DashboardUtils.formatMonth(response.month);

    const date = document.createElement('p');
    date.className = 'text-sm text-gray-500 mb-2';
    date.textContent = `Soumis le ${Utils.formatDate(response.createdAt)}`;

    const summary = document.createElement('p');
    summary.className = 'text-gray-700';
    summary.textContent = `${response.responses?.length || 0} réponses`;

    content.appendChild(title);
    content.appendChild(date);
    content.appendChild(summary);

    item.appendChild(dateIndicator);
    item.appendChild(content);

    return item;
  },

  /**
   * Create comparison row for responses
   */
  createComparisonRow(question, userResponse, contactResponse) {
    const row = document.createElement('div');
    row.className = 'comparison-row';

    // User response
    const userCard = document.createElement('div');
    userCard.className = 'response-card user-response';
    
    if (userResponse) {
      const content = document.createElement('div');
      content.className = 'w-full';
      
      // Check if response contains an image URL
      const responseText = Utils.unescapeHTML(userResponse);
      if (Utils.isTrustedImageUrl(responseText)) {
        const img = document.createElement('img');
        img.src = responseText;
        img.alt = 'Réponse image';
        img.className = 'response-image max-w-full h-auto rounded';
        img.onclick = () => {
          if (window.PhotoLightbox) {
            window.PhotoLightbox.open([{
              url: responseText,
              title: 'Votre réponse',
              description: Utils.unescapeHTML(question)
            }]);
          }
        };
        content.appendChild(img);
      } else {
        content.textContent = DashboardUtils.truncateText(responseText, 200);
      }
      
      userCard.appendChild(content);
    } else {
      userCard.className = 'response-card empty';
      userCard.textContent = 'Pas de réponse';
    }

    // Divider
    const divider = document.createElement('div');
    divider.className = 'comparison-divider';
    divider.textContent = 'VS';

    // Contact response
    const contactCard = document.createElement('div');
    contactCard.className = 'response-card contact-response';
    
    if (contactResponse) {
      const content = document.createElement('div');
      content.className = 'w-full';
      
      // Check if response contains an image URL
      const responseText = Utils.unescapeHTML(contactResponse);
      if (Utils.isTrustedImageUrl(responseText)) {
        const img = document.createElement('img');
        img.src = responseText;
        img.alt = 'Réponse image du contact';
        img.className = 'response-image max-w-full h-auto rounded';
        img.onclick = () => {
          if (window.PhotoLightbox) {
            window.PhotoLightbox.open([{
              url: responseText,
              title: 'Réponse du contact',
              description: Utils.unescapeHTML(question)
            }]);
          }
        };
        content.appendChild(img);
      } else {
        content.textContent = DashboardUtils.truncateText(responseText, 200);
      }
      
      contactCard.appendChild(content);
    } else {
      contactCard.className = 'response-card empty';
      contactCard.textContent = 'Pas de réponse';
    }

    row.appendChild(userCard);
    row.appendChild(divider);
    row.appendChild(contactCard);

    return row;
  },

  /**
   * Show form modal with current month questions
   */
  async showFormModal() {
    try {
      UI.showLoading(true, 'Chargement du formulaire...');
      
      // Get current form questions (this would come from the backend)
      const formData = await DashboardAPI.request('/api/form/current', {}, 'Erreur lors du chargement du formulaire');
      
      if (!formData) return;

      const modal = document.getElementById('monthlyFormModal');
      const content = document.getElementById('formModalContent');
      
      // Clear existing content
      content.textContent = '';

      // Create form
      const form = document.createElement('form');
      form.id = 'monthlyForm';
      form.className = 'space-y-6';

      formData.questions?.forEach((question, index) => {
        const questionDiv = document.createElement('div');
        questionDiv.className = 'form-group';

        const label = document.createElement('label');
        label.className = 'block text-sm font-medium text-gray-700 mb-2';
        label.textContent = Utils.unescapeHTML(question.text);

        const input = document.createElement('textarea');
        input.name = `question_${index}`;
        input.className = 'w-full border border-gray-300 rounded-lg px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500';
        input.rows = 3;
        input.placeholder = 'Votre réponse...';

        questionDiv.appendChild(label);
        questionDiv.appendChild(input);
        form.appendChild(questionDiv);
      });

      // Submit button
      const submitBtn = document.createElement('button');
      submitBtn.type = 'submit';
      submitBtn.className = 'w-full bg-blue-600 text-white py-3 rounded-lg hover:bg-blue-700 transition-colors';
      submitBtn.textContent = 'Soumettre mes réponses';

      form.appendChild(submitBtn);
      content.appendChild(form);

      // Show modal
      modal.classList.add('active');
      modal.setAttribute('aria-hidden', 'false');

      // Handle form submission
      form.onsubmit = async (e) => {
        e.preventDefault();
        await this.handleFormSubmission(form, formData.questions);
      };

    } catch (error) {
      UI.showAlert('Impossible de charger le formulaire', 'error');
    } finally {
      UI.showLoading(false);
    }
  },

  /**
   * Handle form submission with validation
   */
  async handleFormSubmission(form, questions) {
    try {
      UI.showLoading(true, 'Envoi des réponses...');

      const formData = new FormData(form);
      const responses = [];

      questions.forEach((question, index) => {
        const answer = formData.get(`question_${index}`);
        if (answer && answer.trim()) {
          responses.push({
            question: question.text,
            answer: answer.trim()
          });
        }
      });

      if (responses.length === 0) {
        UI.showAlert('Veuillez répondre à au moins une question', 'error');
        return;
      }

      const result = await DashboardAPI.submitResponse({
        month: DashboardUtils.getCurrentMonth(),
        responses: responses
      });

      if (result) {
        UI.showAlert('Vos réponses ont été enregistrées avec succès !', 'success');
        
        // Close modal
        const modal = document.getElementById('monthlyFormModal');
        modal.classList.remove('active');
        modal.setAttribute('aria-hidden', 'true');

        // Refresh page data
        await this.refreshDashboardData();
      }

    } catch (error) {
      UI.showAlert('Erreur lors de l\'envoi des réponses', 'error');
    } finally {
      UI.showLoading(false);
    }
  },

  /**
   * Refresh dashboard data
   */
  async refreshDashboardData() {
    // This would refresh the current page's data
    if (window.location.pathname.includes('dashboard.html')) {
      window.location.reload();
    }
  }
};

// Configuration constants
const CONFIG = {
  pieQuestion: "En rapide, comment ça va ?", // Sync with PIE_CHART_QUESTION env var
  chart: {
    width: 1100,
    height: 320
  },
  image: {
    maxUrlLength: 1000,
    maxFallbackLength: 200,
    thumbnailSize: 'w-32 h-32',
    lightboxMaxSize: '90%',
    fallbackSvg: 'data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNjQiIGhlaWdodD0iNjQiIHZpZXdCb3g9IjAgMCA2NCA2NCIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPHJlY3Qgd2lkdGg9IjY0IiBoZWlnaHQ9IjY0IiBmaWxsPSIjRjNGNEY2Ii8+CjxwYXRoIGQ9Ik0yNCAyOEMyNiAyNiAyOCAyNiAzMCAyOEMzMiAzMCAzNCAzMCAzNiAyOEMzOCAyNiA0MCAyNiA0MiAyOFY0MEgyMlYyOFoiIGZpbGw9IiNEMUQ1REIiLz4KPHA+SW1hZ2UgaW5kaXNwb25pYmxlPC9wPgo8L3N2Zz4K'
  },
  lightbox: {
    zIndex: 9999
  }
};

// Global user profile and permissions
let userProfile = null;
let userPermissions = null;

// Initialize CSS variables from CONFIG
document.documentElement.style.setProperty('--lightbox-z-index', CONFIG.lightbox.zIndex);

// =============================================================================
// PAGE CONTROLLERS - Manage different dashboard pages
// =============================================================================

export const DashboardController = {
  currentPage: null,
  userRole: null,

  /**
   * Initialize the dashboard based on current page
   */
  async init() {
    await DashboardAPI.init();
    
    // Detect current page
    const path = window.location.pathname;
    if (path.includes('dashboard-contacts.html')) {
      this.currentPage = 'contacts';
      await this.initContactsPage();
    } else if (path.includes('dashboard-responses.html')) {
      this.currentPage = 'responses';
      await this.initResponsesPage();
    } else if (path.includes('dashboard-contact-view.html')) {
      this.currentPage = 'contact-view';
      await this.initContactViewPage();
    } else {
      this.currentPage = 'main';
      await this.initMainDashboard();
    }

    // Initialize common elements
    await this.initCommonElements();
    this.initEventListeners();
  },

  /**
   * Initialize common elements across all pages
   */
  async initCommonElements() {
    try {
      // Get user info and dashboard data
      const dashboardData = await DashboardAPI.getDashboardData();
      
      if (dashboardData) {
        this.userRole = dashboardData.user?.role;
        
        // Update user welcome message
        const userWelcome = document.getElementById('userWelcome');
        if (userWelcome) {
          userWelcome.textContent = `Bonjour, ${Utils.unescapeHTML(dashboardData.user?.username || 'Utilisateur')}`;
        }

        // Update user role display
        const userRole = document.getElementById('userRole');
        if (userRole) {
          userRole.textContent = dashboardData.user?.role === 'admin' ? '(Administrateur)' : '';
        }

        // Show/hide admin-only elements
        this.updateRoleBasedVisibility();
      }
    } catch (error) {
      console.error('Error initializing common elements:', error);
    }
  },

  /**
   * Update visibility of role-based elements
   */
  updateRoleBasedVisibility() {
    const adminElements = document.querySelectorAll('.admin-only');
    const userElements = document.querySelectorAll('.user-only');

    if (this.userRole === 'admin') {
      adminElements.forEach(el => el.classList.remove('hidden'));
      userElements.forEach(el => el.classList.remove('hidden')); // Admins see everything
    } else {
      adminElements.forEach(el => el.classList.add('hidden'));
      userElements.forEach(el => el.classList.remove('hidden'));
    }
  },

  /**
   * Initialize main dashboard page
   */
  async initMainDashboard() {
    try {
      const dashboardData = await DashboardAPI.getDashboardData();
      
      if (dashboardData) {
        // Update stats
        this.updateElement('contactCount', dashboardData.stats?.totalContacts || 0);
        this.updateElement('activeHandshakes', dashboardData.stats?.activeHandshakes || 0);
        this.updateElement('responseCount', dashboardData.stats?.userResponses || 0);
        this.updateElement('totalUsers', dashboardData.stats?.totalUsers || 0);

        // Update form status
        await this.updateFormStatus();

        // Load recent activity
        await this.loadRecentActivity(dashboardData.recentActivity || []);

        // Load recent contacts
        await this.loadRecentContacts(dashboardData.recentContacts || []);
      }
    } catch (error) {
      console.error('Error initializing main dashboard:', error);
    }
  },

  /**
   * Initialize contacts page
   */
  async initContactsPage() {
    await this.loadContacts();
  },

  /**
   * Initialize responses page  
   */
  async initResponsesPage() {
    await this.loadUserResponses();
  },

  /**
   * Initialize contact view page
   */
  async initContactViewPage() {
    await this.loadContactsForComparison();
  },

  /**
   * Helper method to update element content safely
   */
  updateElement(id, content) {
    const element = document.getElementById(id);
    if (element) {
      element.textContent = content;
    }
  },

  /**
   * Update form submission status for current month
   */
  async updateFormStatus() {
    try {
      const response = await DashboardAPI.getCurrentMonthStatus();
      if (response) {
        const statusElement = document.getElementById('formStatus');
        const fillFormBtn = document.getElementById('fillFormBtn');
        
        if (statusElement) {
          if (response.hasSubmitted) {
            statusElement.innerHTML = `
              <span class="text-green-600">✓ Formulaire soumis pour ${response.month}</span>
            `;
            if (fillFormBtn) {
              fillFormBtn.textContent = 'Modifier ma réponse';
            }
          } else {
            statusElement.innerHTML = `
              <span class="text-yellow-600">⏳ En attente pour ${response.month}</span>
            `;
            if (fillFormBtn) {
              fillFormBtn.textContent = 'Remplir le formulaire';
            }
          }
        }
      }
    } catch (error) {
      console.error('Error updating form status:', error);
    }
  },

  /**
   * Initialize event listeners
   */
  initEventListeners() {
    // Fill form button
    const fillFormBtn = document.getElementById('fillFormBtn');
    if (fillFormBtn) {
      fillFormBtn.addEventListener('click', () => DashboardUI.showFormModal());
    }

    // Modal close buttons
    document.querySelectorAll('[id*="close"][id*="Modal"], [id*="Modal"] [aria-label="Fermer la modal"]').forEach(btn => {
      btn.addEventListener('click', this.closeModal);
    });

    // Contact form
    const contactForm = document.getElementById('contactForm');
    if (contactForm) {
      contactForm.addEventListener('submit', this.handleContactFormSubmit.bind(this));
    }

    // Search input with debounce
    const searchInput = document.getElementById('searchInput');
    if (searchInput) {
      searchInput.addEventListener('input', Utils.debounce((e) => {
        this.handleSearch(e.target.value);
      }, 300));
    }

    // Filter tabs
    document.querySelectorAll('.filter-tab').forEach(tab => {
      tab.addEventListener('click', (e) => {
        this.handleFilterChange(e.target.dataset.filter);
      });
    });

    // Month selector
    const monthSelector = document.getElementById('monthSelector');
    if (monthSelector) {
      monthSelector.addEventListener('change', (e) => {
        this.handleMonthChange(e.target.value);
      });
    }

    // Month navigation buttons
    const prevMonth = document.getElementById('prevMonth');
    const nextMonth = document.getElementById('nextMonth');
    if (prevMonth) prevMonth.addEventListener('click', () => this.navigateMonth(-1));
    if (nextMonth) nextMonth.addEventListener('click', () => this.navigateMonth(1));

    // Contact selector for comparison
    const contactSelector = document.getElementById('contactSelector');
    if (contactSelector) {
      contactSelector.addEventListener('change', (e) => {
        this.handleContactSelection(e.target.value);
      });
    }
  },

  /**
   * Close modal helper
   */
  closeModal(e) {
    const modal = e.target.closest('.modal-overlay');
    if (modal) {
      modal.classList.remove('active');
      modal.setAttribute('aria-hidden', 'true');
    }
  },

};

// =============================================================================
// AUTO-INITIALIZATION
// =============================================================================

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
  DashboardController.init();
});

// Make modules available globally for debugging
if (typeof window !== 'undefined') {
  window.DashboardAPI = DashboardAPI;
  window.DashboardUtils = DashboardUtils;
  window.DashboardUI = DashboardUI;
  window.DashboardController = DashboardController;
}