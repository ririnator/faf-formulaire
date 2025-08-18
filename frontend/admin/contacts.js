/**
 * Contact Management Module - Comprehensive interface for managing contacts and handshakes
 * Integrates with Form-a-Friend v2 universal dashboard architecture
 */

import { AdminAPI, Utils, UI, Charts } from '/admin/faf-admin.js';

// =============================================================================
// CONFIGURATION AND STATE
// =============================================================================

const CONFIG = {
  pagination: {
    defaultLimit: 20,
    maxLimit: 100
  },
  debounce: {
    search: 300,
    filter: 150
  },
  charts: {
    animationDuration: 1000
  },
  touch: {
    swipeThreshold: 100,
    longPressDelay: 500
  }
};

const STATE = {
  contacts: [],
  filteredContacts: [],
  selectedContacts: new Set(),
  currentFilter: 'all',
  currentSearch: '',
  currentPage: 1,
  totalPages: 0,
  totalContacts: 0,
  userPermissions: null,
  charts: {
    status: null,
    activity: null
  },
  isLoading: false
};

// =============================================================================
// API INTERFACE
// =============================================================================

class ContactAPI {
  static async getContacts(filters = {}) {
    const params = new URLSearchParams({
      page: filters.page || 1,
      limit: filters.limit || CONFIG.pagination.defaultLimit,
      search: filters.search || '',
      status: filters.status || '',
      tags: Array.isArray(filters.tags) ? filters.tags.join(',') : (filters.tags || '')
    });

    return AdminAPI.request(
      `/api/contacts?${params}`,
      { method: 'GET' },
      'Erreur lors de la récupération des contacts'
    );
  }

  static async getContactStats() {
    return AdminAPI.request(
      '/api/contacts/stats/global',
      { method: 'GET' },
      'Erreur lors de la récupération des statistiques'
    );
  }

  static async addContact(contactData) {
    return AdminAPI.request(
      '/api/contacts',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(contactData)
      },
      'Erreur lors de l\'ajout du contact'
    );
  }

  static async updateContact(contactId, updateData) {
    return AdminAPI.request(
      `/api/contacts/${contactId}`,
      {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(updateData)
      },
      'Erreur lors de la mise à jour du contact'
    );
  }

  static async deleteContact(contactId) {
    return AdminAPI.request(
      `/api/contacts/${contactId}`,
      { method: 'DELETE' },
      'Erreur lors de la suppression du contact'
    );
  }

  static async importContacts(csvData, options = {}) {
    return AdminAPI.request(
      '/api/contacts/import',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ csvData, options })
      },
      'Erreur lors de l\'importation des contacts'
    );
  }

  static async exportContacts(filters = {}) {
    const params = new URLSearchParams(filters);
    return AdminAPI.request(
      `/api/contacts/export/csv?${params}`,
      { method: 'GET' },
      'Erreur lors de l\'exportation des contacts'
    );
  }

  static async sendHandshake(contactEmail, message = '') {
    return AdminAPI.request(
      '/api/handshakes/request',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: contactEmail, message })
      },
      'Erreur lors de l\'envoi de la demande de handshake'
    );
  }

  static async getHandshakeStats() {
    return AdminAPI.request(
      '/api/handshakes/stats',
      { method: 'GET' },
      'Erreur lors de la récupération des statistiques handshake'
    );
  }
}

// =============================================================================
// UI COMPONENTS
// =============================================================================

class ContactCard {
  static create(contact, permissions) {
    const card = document.createElement('div');
    card.className = 'contact-card bg-white rounded-lg shadow p-4 cursor-pointer contact-card-swipeable';
    card.dataset.contactId = contact._id;
    
    // Status indicator
    const statusIndicator = document.createElement('div');
    statusIndicator.className = `contact-status-indicator status-${contact.status}`;
    statusIndicator.title = `Statut: ${this.getStatusLabel(contact.status)}`;
    
    // Avatar
    const avatar = document.createElement('div');
    avatar.className = 'contact-avatar mx-auto mb-3';
    avatar.textContent = this.getInitials(contact);
    
    // Contact info
    const name = document.createElement('h3');
    name.className = 'text-lg font-semibold text-center mb-1';
    name.textContent = this.getDisplayName(contact);
    
    const email = document.createElement('p');
    email.className = 'text-sm text-gray-600 text-center mb-2';
    email.textContent = contact.email;
    
    // Tags
    const tagsContainer = document.createElement('div');
    tagsContainer.className = 'flex flex-wrap justify-center gap-1 mb-3';
    if (contact.tags && contact.tags.length > 0) {
      contact.tags.slice(0, 3).forEach(tag => {
        const tagEl = document.createElement('span');
        tagEl.className = 'contact-tag';
        tagEl.textContent = tag;
        tagsContainer.appendChild(tagEl);
      });
      
      if (contact.tags.length > 3) {
        const moreTag = document.createElement('span');
        moreTag.className = 'contact-tag';
        moreTag.textContent = `+${contact.tags.length - 3}`;
        tagsContainer.appendChild(moreTag);
      }
    }
    
    // Stats
    const stats = document.createElement('div');
    stats.className = 'text-xs text-gray-500 text-center space-y-1';
    
    if (contact.tracking) {
      const responseRate = document.createElement('div');
      responseRate.textContent = `Taux de réponse: ${contact.tracking.responseRate || 0}%`;
      stats.appendChild(responseRate);
      
      if (contact.tracking.lastInteractionAt) {
        const lastActivity = document.createElement('div');
        const lastDate = new Date(contact.tracking.lastInteractionAt);
        lastActivity.textContent = `Dernière activité: ${lastDate.toLocaleDateString('fr-FR')}`;
        stats.appendChild(lastActivity);
      }
    }
    
    // Actions
    const actions = document.createElement('div');
    actions.className = 'flex justify-center gap-2 mt-3';
    
    const editBtn = document.createElement('button');
    editBtn.className = 'action-button bg-blue-100 hover:bg-blue-200 text-blue-600 w-8 h-8 rounded-full';
    editBtn.innerHTML = '✏️';
    editBtn.title = 'Modifier le contact';
    editBtn.onclick = (e) => {
      e.stopPropagation();
      ContactManager.editContact(contact._id);
    };
    
    const handshakeBtn = document.createElement('button');
    handshakeBtn.className = 'action-button bg-green-100 hover:bg-green-200 text-green-600 w-8 h-8 rounded-full';
    handshakeBtn.innerHTML = '🤝';
    handshakeBtn.title = 'Envoyer un handshake';
    handshakeBtn.onclick = (e) => {
      e.stopPropagation();
      ContactManager.sendHandshakeRequest(contact.email);
    };
    
    // Comparison button (only for accepted handshakes)
    const compareBtn = document.createElement('button');
    compareBtn.className = 'action-button bg-purple-100 hover:bg-purple-200 text-purple-600 w-8 h-8 rounded-full';
    compareBtn.innerHTML = '📊';
    compareBtn.title = 'Comparer les réponses';
    compareBtn.onclick = (e) => {
      e.stopPropagation();
      ContactManager.openComparison(contact._id);
    };
    
    // Timeline button (for all contacts with submissions)
    const timelineBtn = document.createElement('button');
    timelineBtn.className = 'action-button bg-indigo-100 hover:bg-indigo-200 text-indigo-600 w-8 h-8 rounded-full';
    timelineBtn.innerHTML = '📅';
    timelineBtn.title = 'Voir la timeline';
    timelineBtn.onclick = (e) => {
      e.stopPropagation();
      ContactManager.openTimeline(contact._id);
    };
    
    const deleteBtn = document.createElement('button');
    deleteBtn.className = 'action-button bg-red-100 hover:bg-red-200 text-red-600 w-8 h-8 rounded-full';
    deleteBtn.innerHTML = '🗑️';
    deleteBtn.title = 'Supprimer le contact';
    deleteBtn.onclick = (e) => {
      e.stopPropagation();
      ContactManager.deleteContact(contact._id);
    };
    
    actions.appendChild(editBtn);
    actions.appendChild(handshakeBtn);
    
    // Show timeline for all contacts (shows submission history)
    actions.appendChild(timelineBtn);
    
    // Only show comparison for contacts with accepted handshakes
    if (contact.handshakeStatus === 'accepted') {
      actions.appendChild(compareBtn);
    }
    
    if (permissions.canManage) {
      actions.appendChild(deleteBtn);
    }
    
    // Swipe actions for mobile
    const swipeActions = document.createElement('div');
    swipeActions.className = 'swipe-actions';
    
    const swipeEdit = document.createElement('div');
    swipeEdit.className = 'swipe-action swipe-edit';
    swipeEdit.innerHTML = '✏️';
    swipeEdit.onclick = () => ContactManager.editContact(contact._id);
    
    const swipeTimeline = document.createElement('div');
    swipeTimeline.className = 'swipe-action swipe-timeline';
    swipeTimeline.innerHTML = '📅';
    swipeTimeline.onclick = () => ContactManager.openTimeline(contact._id);
    
    const swipeCompare = document.createElement('div');
    swipeCompare.className = 'swipe-action swipe-compare';
    swipeCompare.innerHTML = '📊';
    swipeCompare.onclick = () => ContactManager.openComparison(contact._id);
    
    const swipeDelete = document.createElement('div');
    swipeDelete.className = 'swipe-action swipe-delete';
    swipeDelete.innerHTML = '🗑️';
    swipeDelete.onclick = () => ContactManager.deleteContact(contact._id);
    
    swipeActions.appendChild(swipeEdit);
    swipeActions.appendChild(swipeTimeline);
    
    // Only show comparison for contacts with accepted handshakes
    if (contact.handshakeStatus === 'accepted') {
      swipeActions.appendChild(swipeCompare);
    }
    
    if (permissions.canManage) {
      swipeActions.appendChild(swipeDelete);
    }
    
    // Assemble card
    card.appendChild(statusIndicator);
    card.appendChild(avatar);
    card.appendChild(name);
    card.appendChild(email);
    card.appendChild(tagsContainer);
    card.appendChild(stats);
    card.appendChild(actions);
    card.appendChild(swipeActions);
    
    // Event listeners
    this.setupCardEvents(card, contact);
    
    return card;
  }
  
  static getInitials(contact) {
    const firstName = contact.firstName || '';
    const lastName = contact.lastName || '';
    
    if (firstName && lastName) {
      return (firstName[0] + lastName[0]).toUpperCase();
    } else if (firstName) {
      return firstName.substring(0, 2).toUpperCase();
    } else if (lastName) {
      return lastName.substring(0, 2).toUpperCase();
    } else {
      return contact.email.substring(0, 2).toUpperCase();
    }
  }
  
  static getDisplayName(contact) {
    const firstName = contact.firstName || '';
    const lastName = contact.lastName || '';
    
    if (firstName && lastName) {
      return `${firstName} ${lastName}`;
    } else if (firstName) {
      return firstName;
    } else if (lastName) {
      return lastName;
    } else {
      return contact.email.split('@')[0];
    }
  }
  
  static getStatusLabel(status) {
    const labels = {
      active: 'Actif',
      pending: 'En attente',
      declined: 'Refusé',
      blocked: 'Bloqué',
      opted_out: 'Désabonné',
      bounced: 'Email invalide'
    };
    return labels[status] || status;
  }
  
  static setupCardEvents(card, contact) {
    let startX = 0;
    let currentX = 0;
    let isDragging = false;
    let longPressTimer = null;
    
    // Touch events for swipe
    card.addEventListener('touchstart', (e) => {
      startX = e.touches[0].clientX;
      isDragging = true;
      
      // Long press for selection
      longPressTimer = setTimeout(() => {
        ContactManager.toggleContactSelection(contact._id);
        navigator.vibrate && navigator.vibrate(50);
      }, CONFIG.touch.longPressDelay);
    });
    
    card.addEventListener('touchmove', (e) => {
      if (!isDragging) return;
      
      clearTimeout(longPressTimer);
      currentX = e.touches[0].clientX;
      const diffX = startX - currentX;
      
      if (Math.abs(diffX) > 10) {
        e.preventDefault();
        
        if (diffX > CONFIG.touch.swipeThreshold) {
          card.classList.add('swiped');
        } else {
          card.classList.remove('swiped');
        }
      }
    });
    
    card.addEventListener('touchend', () => {
      isDragging = false;
      clearTimeout(longPressTimer);
    });
    
    // Click events
    card.addEventListener('click', (e) => {
      if (e.target.closest('.action-button')) return;
      
      if (STATE.selectedContacts.size > 0) {
        ContactManager.toggleContactSelection(contact._id);
      } else {
        ContactManager.viewContactDetails(contact._id);
      }
    });
    
    // Context menu
    card.addEventListener('contextmenu', (e) => {
      e.preventDefault();
      ContextMenu.show(e, contact);
    });
  }
}

// =============================================================================
// CONTACT MANAGER
// =============================================================================

class ContactManager {
  static async init() {
    try {
      // Initialize user permissions
      const profile = await AdminAPI.request('/api/dashboard/profile');
      STATE.userPermissions = profile.permissions;
      
      // Update UI based on permissions
      this.updateUIForPermissions();
      
      // Load initial data
      await this.loadContacts();
      await this.loadStatistics();
      
      // Setup event listeners
      this.setupEventListeners();
      
      // Setup filters
      this.setupFilters();
      
    } catch (error) {
      console.error('Failed to initialize contact manager:', error);
      UI.showAlert('Erreur lors de l\'initialisation de la gestion des contacts', 'error');
    }
  }
  
  static updateUIForPermissions() {
    const adminElements = document.querySelectorAll('.admin-only');
    const userElements = document.querySelectorAll('.user-only');
    
    if (STATE.userPermissions.canViewAdminFeatures) {
      adminElements.forEach(el => el.classList.remove('hidden'));
      userElements.forEach(el => el.classList.add('hidden'));
      document.getElementById('userRole').textContent = '(Administrateur)';
    } else {
      adminElements.forEach(el => el.classList.add('hidden'));
      userElements.forEach(el => el.classList.remove('hidden'));
      document.getElementById('userRole').textContent = '(Utilisateur)';
    }
  }
  
  static async loadContacts(filters = {}) {
    try {
      STATE.isLoading = true;
      this.showLoadingState(true);
      
      const response = await ContactAPI.getContacts({
        page: STATE.currentPage,
        limit: CONFIG.pagination.defaultLimit,
        search: STATE.currentSearch,
        status: STATE.currentFilter === 'all' ? '' : STATE.currentFilter,
        ...filters
      });
      
      if (response) {
        STATE.contacts = response.contacts || [];
        STATE.totalContacts = response.total || 0;
        STATE.totalPages = Math.ceil(STATE.totalContacts / CONFIG.pagination.defaultLimit);
        
        this.applyFiltersAndSort();
        this.renderContacts();
        this.updatePagination();
      }
      
    } catch (error) {
      console.error('Failed to load contacts:', error);
      UI.showAlert('Erreur lors du chargement des contacts', 'error');
    } finally {
      STATE.isLoading = false;
      this.showLoadingState(false);
    }
  }
  
  static async loadStatistics() {
    try {
      const [contactStats, handshakeStats] = await Promise.all([
        ContactAPI.getContactStats(),
        ContactAPI.getHandshakeStats()
      ]);
      
      if (contactStats) {
        this.updateStatisticsDisplay(contactStats, handshakeStats);
        this.updateCharts(contactStats);
      }
      
    } catch (error) {
      console.error('Failed to load statistics:', error);
      // Don't show error for stats as it's not critical
    }
  }
  
  static updateStatisticsDisplay(contactStats, handshakeStats) {
    document.getElementById('totalContacts').textContent = contactStats.totalContacts || 0;
    document.getElementById('activeContacts').textContent = contactStats.activeContacts || 0;
    document.getElementById('pendingHandshakes').textContent = handshakeStats?.pendingRequests || 0;
    document.getElementById('responseRate').textContent = `${contactStats.averageResponseRate || 0}%`;
  }
  
  static updateCharts(stats) {
    // Status distribution chart
    const statusCtx = document.getElementById('statusChart').getContext('2d');
    
    if (STATE.charts.status) {
      STATE.charts.status.destroy();
    }
    
    STATE.charts.status = new Chart(statusCtx, {
      type: 'doughnut',
      data: {
        labels: ['Actifs', 'En attente', 'Refusés', 'Bloqués', 'Autres'],
        datasets: [{
          data: [
            stats.statusBreakdown?.active || 0,
            stats.statusBreakdown?.pending || 0,
            stats.statusBreakdown?.declined || 0,
            stats.statusBreakdown?.blocked || 0,
            stats.statusBreakdown?.other || 0
          ],
          backgroundColor: [
            '#10b981',
            '#f59e0b',
            '#ef4444',
            '#6b7280',
            '#9ca3af'
          ]
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'bottom'
          }
        },
        animation: {
          duration: CONFIG.charts.animationDuration
        }
      }
    });
    
    // Activity chart
    const activityCtx = document.getElementById('activityChart').getContext('2d');
    
    if (STATE.charts.activity) {
      STATE.charts.activity.destroy();
    }
    
    const activityData = stats.activityTimeline || [];
    
    STATE.charts.activity = new Chart(activityCtx, {
      type: 'line',
      data: {
        labels: activityData.map(item => item.date),
        datasets: [{
          label: 'Nouveaux contacts',
          data: activityData.map(item => item.newContacts),
          borderColor: '#3b82f6',
          backgroundColor: 'rgba(59, 130, 246, 0.1)',
          tension: 0.4
        }, {
          label: 'Handshakes envoyés',
          data: activityData.map(item => item.handshakesSent),
          borderColor: '#10b981',
          backgroundColor: 'rgba(16, 185, 129, 0.1)',
          tension: 0.4
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          y: {
            beginAtZero: true
          }
        },
        animation: {
          duration: CONFIG.charts.animationDuration
        }
      }
    });
  }
  
  static applyFiltersAndSort() {
    let filtered = [...STATE.contacts];
    
    // Apply status filter
    if (STATE.currentFilter !== 'all') {
      filtered = filtered.filter(contact => contact.status === STATE.currentFilter);
    }
    
    // Apply search filter
    if (STATE.currentSearch) {
      const searchTerm = STATE.currentSearch.toLowerCase();
      filtered = filtered.filter(contact => {
        const fullName = `${contact.firstName || ''} ${contact.lastName || ''}`.toLowerCase();
        const email = contact.email.toLowerCase();
        const tags = (contact.tags || []).join(' ').toLowerCase();
        
        return fullName.includes(searchTerm) || 
               email.includes(searchTerm) || 
               tags.includes(searchTerm);
      });
    }
    
    // Apply sorting
    const sortBy = document.getElementById('sortBy').value;
    filtered.sort((a, b) => {
      switch (sortBy) {
        case 'name':
          const nameA = `${a.firstName || ''} ${a.lastName || ''}`.trim() || a.email;
          const nameB = `${b.firstName || ''} ${b.lastName || ''}`.trim() || b.email;
          return nameA.localeCompare(nameB);
        case 'email':
          return a.email.localeCompare(b.email);
        case 'status':
          return a.status.localeCompare(b.status);
        case 'lastActivity':
          const dateA = new Date(a.tracking?.lastInteractionAt || 0);
          const dateB = new Date(b.tracking?.lastInteractionAt || 0);
          return dateB - dateA;
        case 'responseRate':
          const rateA = a.tracking?.responseRate || 0;
          const rateB = b.tracking?.responseRate || 0;
          return rateB - rateA;
        default:
          return 0;
      }
    });
    
    STATE.filteredContacts = filtered;
  }
  
  static renderContacts() {
    const container = document.getElementById('contactsContainer');
    const emptyState = document.getElementById('emptyState');
    
    container.innerHTML = '';
    
    if (STATE.filteredContacts.length === 0) {
      container.classList.add('hidden');
      emptyState.classList.remove('hidden');
      return;
    }
    
    container.classList.remove('hidden');
    emptyState.classList.add('hidden');
    
    STATE.filteredContacts.forEach(contact => {
      const card = ContactCard.create(contact, STATE.userPermissions);
      container.appendChild(card);
    });
  }
  
  static showLoadingState(show) {
    const loadingState = document.getElementById('loadingState');
    const contactsContainer = document.getElementById('contactsContainer');
    
    if (show) {
      loadingState.classList.remove('hidden');
      contactsContainer.classList.add('hidden');
    } else {
      loadingState.classList.add('hidden');
      contactsContainer.classList.remove('hidden');
    }
  }
  
  static setupEventListeners() {
    // Search input with debounce
    const searchInput = document.getElementById('searchInput');
    searchInput.addEventListener('input', Utils.debounce((e) => {
      STATE.currentSearch = e.target.value;
      this.applyFiltersAndSort();
      this.renderContacts();
    }, CONFIG.debounce.search));
    
    // Filter tabs
    document.querySelectorAll('.filter-tab').forEach(tab => {
      tab.addEventListener('click', (e) => {
        document.querySelectorAll('.filter-tab').forEach(t => {
          t.classList.remove('active');
          t.setAttribute('aria-selected', 'false');
        });
        
        e.target.classList.add('active');
        e.target.setAttribute('aria-selected', 'true');
        
        STATE.currentFilter = e.target.dataset.filter;
        this.applyFiltersAndSort();
        this.renderContacts();
      });
    });
    
    // Sort dropdown
    document.getElementById('sortBy').addEventListener('change', () => {
      this.applyFiltersAndSort();
      this.renderContacts();
    });
    
    // Clear filters
    document.getElementById('clearFilters').addEventListener('click', () => {
      this.clearAllFilters();
    });
    
    // Add contact button
    document.getElementById('addContactBtn').addEventListener('click', () => {
      this.showContactModal();
    });
    
    // CSV import
    document.getElementById('csvImport').addEventListener('change', (e) => {
      this.handleCSVImport(e.target.files[0]);
    });
    
    // CSV export
    document.getElementById('exportCsvBtn').addEventListener('click', () => {
      this.exportContacts();
    });
    
    // Bulk actions
    document.getElementById('bulkDeleteBtn').addEventListener('click', () => {
      this.bulkDeleteContacts();
    });
    
    document.getElementById('bulkTagBtn').addEventListener('click', () => {
      this.showBulkTagModal();
    });
    
    // Modal close buttons
    document.querySelectorAll('.modal-overlay').forEach(modal => {
      const closeBtn = modal.querySelector('[aria-label="Fermer la modal"]');
      if (closeBtn) {
        closeBtn.addEventListener('click', () => {
          this.hideModal(modal);
        });
      }
      
      // Close on overlay click
      modal.addEventListener('click', (e) => {
        if (e.target === modal) {
          this.hideModal(modal);
        }
      });
    });
    
    // Contact form
    document.getElementById('contactForm').addEventListener('submit', (e) => {
      e.preventDefault();
      this.saveContact();
    });
    
    // Bulk tag form
    document.getElementById('bulkTagForm').addEventListener('submit', (e) => {
      e.preventDefault();
      this.applyBulkTags();
    });
    
    // Click outside to close context menu
    document.addEventListener('click', () => {
      ContextMenu.hide();
    });
  }
  
  static setupFilters() {
    // Load unique tags for tag filter
    const allTags = new Set();
    STATE.contacts.forEach(contact => {
      if (contact.tags) {
        contact.tags.forEach(tag => allTags.add(tag));
      }
    });
    
    const tagFilter = document.getElementById('tagFilter');
    tagFilter.innerHTML = '<option value="">Tous les tags</option>';
    
    Array.from(allTags).sort().forEach(tag => {
      const option = document.createElement('option');
      option.value = tag;
      option.textContent = tag;
      tagFilter.appendChild(option);
    });
    
    tagFilter.addEventListener('change', (e) => {
      const selectedTag = e.target.value;
      if (selectedTag) {
        STATE.filteredContacts = STATE.filteredContacts.filter(contact => 
          contact.tags && contact.tags.includes(selectedTag)
        );
      } else {
        this.applyFiltersAndSort();
      }
      this.renderContacts();
    });
  }
  
  static clearAllFilters() {
    document.getElementById('searchInput').value = '';
    document.getElementById('tagFilter').value = '';
    document.getElementById('sortBy').value = 'name';
    
    document.querySelectorAll('.filter-tab').forEach(tab => {
      tab.classList.remove('active');
      tab.setAttribute('aria-selected', 'false');
    });
    
    document.querySelector('.filter-tab[data-filter="all"]').classList.add('active');
    document.querySelector('.filter-tab[data-filter="all"]').setAttribute('aria-selected', 'true');
    
    STATE.currentFilter = 'all';
    STATE.currentSearch = '';
    
    this.applyFiltersAndSort();
    this.renderContacts();
  }
  
  static updatePagination() {
    const itemsRange = document.getElementById('itemsRange');
    const totalItems = document.getElementById('totalItems');
    const paginationButtons = document.getElementById('paginationButtons');
    
    const start = (STATE.currentPage - 1) * CONFIG.pagination.defaultLimit + 1;
    const end = Math.min(STATE.currentPage * CONFIG.pagination.defaultLimit, STATE.totalContacts);
    
    itemsRange.textContent = `${start}-${end}`;
    totalItems.textContent = STATE.totalContacts;
    
    // Generate pagination buttons
    paginationButtons.innerHTML = '';
    
    if (STATE.totalPages > 1) {
      const prevBtn = document.createElement('button');
      prevBtn.textContent = '← Précédent';
      prevBtn.disabled = STATE.currentPage === 1;
      prevBtn.className = `px-3 py-1 rounded ${STATE.currentPage === 1 ? 'bg-gray-200 text-gray-400' : 'bg-blue-600 text-white hover:bg-blue-700'}`;
      prevBtn.onclick = () => this.changePage(STATE.currentPage - 1);
      paginationButtons.appendChild(prevBtn);
      
      const nextBtn = document.createElement('button');
      nextBtn.textContent = 'Suivant →';
      nextBtn.disabled = STATE.currentPage === STATE.totalPages;
      nextBtn.className = `px-3 py-1 rounded ${STATE.currentPage === STATE.totalPages ? 'bg-gray-200 text-gray-400' : 'bg-blue-600 text-white hover:bg-blue-700'}`;
      nextBtn.onclick = () => this.changePage(STATE.currentPage + 1);
      paginationButtons.appendChild(nextBtn);
    }
  }
  
  static changePage(newPage) {
    if (newPage >= 1 && newPage <= STATE.totalPages) {
      STATE.currentPage = newPage;
      this.loadContacts();
    }
  }
  
  static showContactModal(contactId = null) {
    const modal = document.getElementById('contactModal');
    const title = document.getElementById('contactModalTitle');
    const form = document.getElementById('contactForm');
    
    form.reset();
    
    if (contactId) {
      title.textContent = 'Modifier le contact';
      // Load contact data
      const contact = STATE.contacts.find(c => c._id === contactId);
      if (contact) {
        document.getElementById('contactEmail').value = contact.email;
        document.getElementById('contactFirstName').value = contact.firstName || '';
        document.getElementById('contactLastName').value = contact.lastName || '';
        document.getElementById('contactTags').value = (contact.tags || []).join(', ');
        document.getElementById('contactNotes').value = contact.notes || '';
      }
      form.dataset.contactId = contactId;
    } else {
      title.textContent = 'Ajouter un contact';
      delete form.dataset.contactId;
    }
    
    this.showModal(modal);
  }
  
  static showBulkTagModal() {
    const modal = document.getElementById('bulkTagModal');
    this.showModal(modal);
  }
  
  static showModal(modal) {
    modal.classList.add('active');
    modal.setAttribute('aria-hidden', 'false');
    
    // Focus first input
    const firstInput = modal.querySelector('input, textarea, select');
    if (firstInput) {
      setTimeout(() => firstInput.focus(), 100);
    }
  }
  
  static hideModal(modal) {
    modal.classList.remove('active');
    modal.setAttribute('aria-hidden', 'true');
  }
  
  static async saveContact() {
    const form = document.getElementById('contactForm');
    const formData = new FormData(form);
    
    const contactData = {
      email: formData.get('email'),
      firstName: formData.get('firstName'),
      lastName: formData.get('lastName'),
      tags: formData.get('tags').split(',').map(tag => tag.trim()).filter(tag => tag),
      notes: formData.get('notes')
    };
    
    try {
      const contactId = form.dataset.contactId;
      
      if (contactId) {
        await ContactAPI.updateContact(contactId, contactData);
        UI.showAlert('Contact mis à jour avec succès', 'success');
      } else {
        await ContactAPI.addContact(contactData);
        UI.showAlert('Contact ajouté avec succès', 'success');
      }
      
      this.hideModal(document.getElementById('contactModal'));
      await this.loadContacts();
      await this.loadStatistics();
      
    } catch (error) {
      console.error('Failed to save contact:', error);
    }
  }
  
  static async editContact(contactId) {
    this.showContactModal(contactId);
  }
  
  static async deleteContact(contactId) {
    if (!confirm('Êtes-vous sûr de vouloir supprimer ce contact ?')) {
      return;
    }
    
    try {
      await ContactAPI.deleteContact(contactId);
      UI.showAlert('Contact supprimé avec succès', 'success');
      
      await this.loadContacts();
      await this.loadStatistics();
      
    } catch (error) {
      console.error('Failed to delete contact:', error);
    }
  }
  
  static async sendHandshakeRequest(email) {
    const message = prompt('Message optionnel pour le handshake :');
    if (message === null) return; // User cancelled
    
    try {
      await ContactAPI.sendHandshake(email, message);
      UI.showAlert('Demande de handshake envoyée avec succès', 'success');
      
    } catch (error) {
      console.error('Failed to send handshake:', error);
    }
  }
  
  static openComparison(contactId) {
    // Navigate to comparison page with contact ID
    const currentMonth = new Date().toISOString().slice(0, 7); // YYYY-MM format
    const comparisonUrl = `/admin/compare?contactId=${contactId}&month=${currentMonth}`;
    
    // Open in current tab
    window.location.href = comparisonUrl;
  }
  
  static openTimeline(contactId) {
    // Navigate to timeline page with contact ID
    const timelineUrl = `/admin/timeline.html?contactId=${contactId}`;
    
    // Open in current tab
    window.location.href = timelineUrl;
  }
  
  static viewContactDetails(contactId) {
    const contact = STATE.contacts.find(c => c._id === contactId);
    if (!contact) return;
    
    // Simple alert for now - could be expanded to a detailed modal
    const details = [
      `Email: ${contact.email}`,
      `Nom: ${ContactCard.getDisplayName(contact)}`,
      `Statut: ${ContactCard.getStatusLabel(contact.status)}`,
      `Tags: ${(contact.tags || []).join(', ') || 'Aucun'}`,
      `Taux de réponse: ${contact.tracking?.responseRate || 0}%`,
      contact.notes ? `Notes: ${contact.notes}` : ''
    ].filter(Boolean).join('\n');
    
    alert(details);
  }
  
  static toggleContactSelection(contactId) {
    if (STATE.selectedContacts.has(contactId)) {
      STATE.selectedContacts.delete(contactId);
    } else {
      STATE.selectedContacts.add(contactId);
    }
    
    this.updateBulkActions();
    this.updateContactCardSelection();
  }
  
  static updateBulkActions() {
    const bulkActions = document.getElementById('bulkActions');
    const selectedCount = document.getElementById('selectedCount');
    
    selectedCount.textContent = `${STATE.selectedContacts.size} sélectionné(s)`;
    
    if (STATE.selectedContacts.size > 0) {
      bulkActions.style.display = 'flex';
    } else {
      bulkActions.style.display = 'none';
    }
  }
  
  static updateContactCardSelection() {
    document.querySelectorAll('.contact-card').forEach(card => {
      const contactId = card.dataset.contactId;
      if (STATE.selectedContacts.has(contactId)) {
        card.classList.add('selected');
      } else {
        card.classList.remove('selected');
      }
    });
  }
  
  static async bulkDeleteContacts() {
    if (STATE.selectedContacts.size === 0) return;
    
    if (!confirm(`Êtes-vous sûr de vouloir supprimer ${STATE.selectedContacts.size} contact(s) ?`)) {
      return;
    }
    
    try {
      const promises = Array.from(STATE.selectedContacts).map(contactId => 
        ContactAPI.deleteContact(contactId)
      );
      
      await Promise.all(promises);
      
      UI.showAlert(`${STATE.selectedContacts.size} contact(s) supprimé(s) avec succès`, 'success');
      
      STATE.selectedContacts.clear();
      this.updateBulkActions();
      
      await this.loadContacts();
      await this.loadStatistics();
      
    } catch (error) {
      console.error('Failed to bulk delete contacts:', error);
    }
  }
  
  static async applyBulkTags() {
    const form = document.getElementById('bulkTagForm');
    const formData = new FormData(form);
    const tags = formData.get('tags').split(',').map(tag => tag.trim()).filter(tag => tag);
    
    if (tags.length === 0 || STATE.selectedContacts.size === 0) {
      return;
    }
    
    try {
      const promises = Array.from(STATE.selectedContacts).map(contactId => {
        const contact = STATE.contacts.find(c => c._id === contactId);
        if (contact) {
          const updatedTags = [...new Set([...(contact.tags || []), ...tags])];
          return ContactAPI.updateContact(contactId, { tags: updatedTags });
        }
      });
      
      await Promise.all(promises);
      
      UI.showAlert(`Tags ajoutés à ${STATE.selectedContacts.size} contact(s)`, 'success');
      
      this.hideModal(document.getElementById('bulkTagModal'));
      STATE.selectedContacts.clear();
      this.updateBulkActions();
      
      await this.loadContacts();
      
    } catch (error) {
      console.error('Failed to apply bulk tags:', error);
    }
  }
  
  static async handleCSVImport(file) {
    if (!file) return;
    
    try {
      const csvText = await this.readFileAsText(file);
      const result = await ContactAPI.importContacts(csvText, {
        skipDuplicates: true,
        updateExisting: false
      });
      
      if (result) {
        UI.showAlert(
          `Import terminé: ${result.imported.length} contacts ajoutés, ${result.duplicates.length} doublons ignorés`,
          'success'
        );
        
        await this.loadContacts();
        await this.loadStatistics();
      }
      
    } catch (error) {
      console.error('Failed to import CSV:', error);
    }
  }
  
  static readFileAsText(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = e => resolve(e.target.result);
      reader.onerror = reject;
      reader.readAsText(file);
    });
  }
  
  static async exportContacts() {
    try {
      const filters = {
        status: STATE.currentFilter === 'all' ? '' : STATE.currentFilter
      };
      
      const csvData = await ContactAPI.exportContacts(filters);
      
      if (csvData) {
        const blob = new Blob([csvData], { type: 'text/csv' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `contacts-${new Date().toISOString().split('T')[0]}.csv`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        
        UI.showAlert('Export terminé avec succès', 'success');
      }
      
    } catch (error) {
      console.error('Failed to export contacts:', error);
    }
  }
}

// =============================================================================
// CONTEXT MENU
// =============================================================================

class ContextMenu {
  static show(event, contact) {
    const menu = document.getElementById('contextMenu');
    
    // Position menu
    menu.style.left = `${event.pageX}px`;
    menu.style.top = `${event.pageY}px`;
    menu.classList.remove('hidden');
    
    // Setup menu actions
    menu.querySelectorAll('[data-action]').forEach(item => {
      item.onclick = () => {
        this.hide();
        this.handleAction(item.dataset.action, contact);
      };
    });
  }
  
  static hide() {
    const menu = document.getElementById('contextMenu');
    menu.classList.add('hidden');
  }
  
  static handleAction(action, contact) {
    switch (action) {
      case 'edit':
        ContactManager.editContact(contact._id);
        break;
      case 'handshake':
        ContactManager.sendHandshakeRequest(contact.email);
        break;
      case 'timeline':
        ContactManager.openTimeline(contact._id);
        break;
      case 'view-stats':
        ContactManager.viewContactDetails(contact._id);
        break;
      case 'delete':
        ContactManager.deleteContact(contact._id);
        break;
    }
  }
}

// =============================================================================
// INITIALIZATION
// =============================================================================

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', async () => {
  try {
    await AdminAPI.init();
    await ContactManager.init();
  } catch (error) {
    console.error('Failed to initialize contacts page:', error);
    UI.showAlert('Erreur lors de l\'initialisation de la page', 'error');
  }
});

// Export for global access
window.ContactManager = ContactManager;