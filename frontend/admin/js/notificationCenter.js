// notificationCenter.js - Real-time notification center for Form-a-Friend v2
class NotificationCenter {
  constructor(config = {}) {
    this.config = {
      apiBaseUrl: config.apiBaseUrl || '/api/notifications',
      updateInterval: config.updateInterval || 30000, // 30 seconds
      maxNotifications: config.maxNotifications || 50,
      enableSSE: config.enableSSE !== false, // Default true
      enableBrowserNotifications: config.enableBrowserNotifications || false,
      ...config
    };
    
    this.isInitialized = false;
    this.notifications = [];
    this.unreadCounts = {};
    this.eventSource = null;
    this.updateTimer = null;
    this.retryCount = 0;
    this.maxRetries = 5;
    
    // UI elements will be set during initialization
    this.elements = {};
    
    // Event handlers
    this.eventHandlers = new Map();
    
    // Request queue for optimistic updates
    this.requestQueue = [];
    this.isProcessingQueue = false;
  }

  /**
   * Initialize the notification center
   */
  async init() {
    try {
      if (this.isInitialized) {
        console.warn('NotificationCenter already initialized');
        return;
      }

      // Create UI elements
      this.createUI();
      
      // Load initial data
      await this.loadNotifications();
      await this.loadUnreadCounts();
      
      // Set up real-time updates
      if (this.config.enableSSE) {
        this.setupSSE();
      } else {
        this.setupPolling();
      }
      
      // Request browser notification permission
      if (this.config.enableBrowserNotifications) {
        await this.requestNotificationPermission();
      }
      
      // Set up event listeners
      this.setupEventListeners();
      
      this.isInitialized = true;
      this.emit('initialized');
      
      console.log('✅ NotificationCenter initialized successfully');
      
    } catch (error) {
      console.error('❌ Failed to initialize NotificationCenter:', error);
      throw error;
    }
  }

  /**
   * Create notification center UI elements
   */
  createUI() {
    // Create notification dropdown
    const notificationDropdown = document.createElement('div');
    notificationDropdown.id = 'notificationCenter';
    notificationDropdown.className = 'notification-center';
    notificationDropdown.innerHTML = `
      <div class="notification-trigger" id="notificationTrigger">
        <span class="notification-icon">🔔</span>
        <span class="notification-badge" id="notificationBadge">0</span>
      </div>
      
      <div class="notification-dropdown" id="notificationDropdown">
        <div class="notification-header">
          <h3>Notifications</h3>
          <div class="notification-actions">
            <button class="mark-all-read-btn" id="markAllReadBtn" title="Marquer tout comme lu">
              ✓ Tout lire
            </button>
            <button class="refresh-btn" id="refreshBtn" title="Actualiser">
              🔄
            </button>
          </div>
        </div>
        
        <div class="notification-filters">
          <button class="filter-btn active" data-filter="all">Toutes</button>
          <button class="filter-btn" data-filter="handshake_request">Demandes</button>
          <button class="filter-btn" data-filter="handshake_accepted">Acceptées</button>
          <button class="filter-btn" data-filter="unread">Non lues</button>
        </div>
        
        <div class="notification-list" id="notificationList">
          <div class="loading-indicator">Chargement...</div>
        </div>
        
        <div class="notification-footer">
          <button class="load-more-btn" id="loadMoreBtn" style="display: none;">
            Charger plus
          </button>
        </div>
      </div>
    `;
    
    // Add to navigation
    const navigation = document.querySelector('.dashboard-nav .nav-links') || 
                      document.querySelector('nav') || 
                      document.body;
    
    if (navigation) {
      navigation.insertBefore(notificationDropdown, navigation.firstChild);
    }
    
    // Store element references
    this.elements = {
      container: notificationDropdown,
      trigger: document.getElementById('notificationTrigger'),
      badge: document.getElementById('notificationBadge'),
      dropdown: document.getElementById('notificationDropdown'),
      list: document.getElementById('notificationList'),
      markAllReadBtn: document.getElementById('markAllReadBtn'),
      refreshBtn: document.getElementById('refreshBtn'),
      loadMoreBtn: document.getElementById('loadMoreBtn'),
      filterBtns: document.querySelectorAll('.filter-btn')
    };
    
    // Add CSS styles
    this.addStyles();
  }

  /**
   * Add notification center styles
   */
  addStyles() {
    const style = document.createElement('style');
    style.textContent = `
      .notification-center {
        position: relative;
        display: inline-block;
      }
      
      .notification-trigger {
        position: relative;
        background: #f8f9fa;
        border: 1px solid #dee2e6;
        border-radius: 8px;
        padding: 8px 12px;
        cursor: pointer;
        display: flex;
        align-items: center;
        gap: 4px;
        transition: all 0.2s ease;
      }
      
      .notification-trigger:hover {
        background: #e9ecef;
        border-color: #adb5bd;
      }
      
      .notification-icon {
        font-size: 18px;
        filter: grayscale(1);
        transition: filter 0.2s ease;
      }
      
      .notification-trigger.has-unread .notification-icon {
        filter: none;
        animation: pulse 2s infinite;
      }
      
      .notification-badge {
        background: #dc3545;
        color: white;
        border-radius: 10px;
        padding: 2px 6px;
        font-size: 11px;
        font-weight: bold;
        min-width: 18px;
        text-align: center;
        display: none;
      }
      
      .notification-badge.visible {
        display: block;
      }
      
      .notification-dropdown {
        position: absolute;
        top: 100%;
        right: 0;
        width: 380px;
        max-height: 500px;
        background: white;
        border: 1px solid #dee2e6;
        border-radius: 8px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        z-index: 1000;
        display: none;
        flex-direction: column;
      }
      
      .notification-dropdown.open {
        display: flex;
      }
      
      .notification-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 12px 16px;
        border-bottom: 1px solid #dee2e6;
        background: #f8f9fa;
        border-radius: 8px 8px 0 0;
      }
      
      .notification-header h3 {
        margin: 0;
        font-size: 16px;
        font-weight: 600;
        color: #495057;
      }
      
      .notification-actions {
        display: flex;
        gap: 8px;
      }
      
      .notification-actions button {
        background: none;
        border: 1px solid #dee2e6;
        border-radius: 4px;
        padding: 4px 8px;
        font-size: 12px;
        cursor: pointer;
        transition: all 0.2s ease;
      }
      
      .notification-actions button:hover {
        background: #e9ecef;
      }
      
      .notification-filters {
        display: flex;
        padding: 8px 16px;
        border-bottom: 1px solid #dee2e6;
        gap: 4px;
      }
      
      .filter-btn {
        background: none;
        border: 1px solid transparent;
        border-radius: 4px;
        padding: 4px 8px;
        font-size: 12px;
        cursor: pointer;
        transition: all 0.2s ease;
      }
      
      .filter-btn:hover {
        background: #f8f9fa;
        border-color: #dee2e6;
      }
      
      .filter-btn.active {
        background: #007bff;
        color: white;
        border-color: #007bff;
      }
      
      .notification-list {
        flex: 1;
        overflow-y: auto;
        max-height: 350px;
      }
      
      .notification-item {
        padding: 12px 16px;
        border-bottom: 1px solid #f8f9fa;
        cursor: pointer;
        transition: background 0.2s ease;
        position: relative;
      }
      
      .notification-item:hover {
        background: #f8f9fa;
      }
      
      .notification-item.unread {
        background: #fff3cd;
        border-left: 4px solid #ffc107;
      }
      
      .notification-item.high-priority {
        border-left: 4px solid #dc3545;
      }
      
      .notification-item.urgent {
        border-left: 4px solid #dc3545;
        background: #f8d7da;
      }
      
      .notification-title {
        font-weight: 600;
        font-size: 14px;
        color: #495057;
        margin-bottom: 4px;
        display: flex;
        justify-content: space-between;
        align-items: center;
      }
      
      .notification-message {
        font-size: 13px;
        color: #6c757d;
        margin-bottom: 8px;
        line-height: 1.4;
      }
      
      .notification-meta {
        display: flex;
        justify-content: space-between;
        align-items: center;
        font-size: 11px;
        color: #adb5bd;
      }
      
      .notification-actions-inline {
        display: flex;
        gap: 8px;
        margin-top: 8px;
      }
      
      .notification-action-btn {
        background: #007bff;
        color: white;
        border: none;
        border-radius: 4px;
        padding: 4px 12px;
        font-size: 12px;
        cursor: pointer;
        transition: all 0.2s ease;
      }
      
      .notification-action-btn:hover {
        background: #0056b3;
      }
      
      .notification-action-btn.decline {
        background: #6c757d;
      }
      
      .notification-action-btn.decline:hover {
        background: #545b62;
      }
      
      .notification-footer {
        padding: 12px 16px;
        border-top: 1px solid #dee2e6;
        text-align: center;
      }
      
      .load-more-btn {
        background: #f8f9fa;
        border: 1px solid #dee2e6;
        border-radius: 4px;
        padding: 8px 16px;
        font-size: 13px;
        cursor: pointer;
        transition: all 0.2s ease;
        width: 100%;
      }
      
      .load-more-btn:hover {
        background: #e9ecef;
      }
      
      .loading-indicator {
        text-align: center;
        padding: 20px;
        color: #6c757d;
        font-size: 14px;
      }
      
      .empty-state {
        text-align: center;
        padding: 40px 20px;
        color: #6c757d;
      }
      
      .empty-state-icon {
        font-size: 48px;
        margin-bottom: 12px;
        opacity: 0.5;
      }
      
      @keyframes pulse {
        0%, 100% { transform: scale(1); }
        50% { transform: scale(1.1); }
      }
      
      /* Mobile responsive */
      @media (max-width: 768px) {
        .notification-dropdown {
          width: 100vw;
          max-width: 350px;
          right: -16px;
        }
        
        .notification-header {
          padding: 10px 12px;
        }
        
        .notification-filters {
          padding: 6px 12px;
          flex-wrap: wrap;
        }
        
        .notification-item {
          padding: 10px 12px;
        }
      }
      
      /* Touch interactions */
      @media (hover: none) {
        .notification-item {
          padding: 14px 16px;
        }
        
        .notification-action-btn {
          padding: 8px 16px;
          font-size: 14px;
        }
      }
    `;
    
    document.head.appendChild(style);
  }

  /**
   * Set up event listeners
   */
  setupEventListeners() {
    // Toggle dropdown
    this.elements.trigger.addEventListener('click', (e) => {
      e.stopPropagation();
      this.toggleDropdown();
    });
    
    // Close dropdown when clicking outside
    document.addEventListener('click', (e) => {
      if (!this.elements.container.contains(e.target)) {
        this.closeDropdown();
      }
    });
    
    // Mark all as read
    this.elements.markAllReadBtn.addEventListener('click', () => {
      this.markAllAsRead();
    });
    
    // Refresh notifications
    this.elements.refreshBtn.addEventListener('click', () => {
      this.refresh();
    });
    
    // Filter buttons
    this.elements.filterBtns.forEach(btn => {
      btn.addEventListener('click', () => {
        this.setFilter(btn.dataset.filter);
      });
    });
    
    // Load more
    this.elements.loadMoreBtn.addEventListener('click', () => {
      this.loadMoreNotifications();
    });
    
    // Keyboard navigation
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && this.isDropdownOpen()) {
        this.closeDropdown();
      }
    });
  }

  /**
   * Load notifications from API
   */
  async loadNotifications(options = {}) {
    try {
      const params = new URLSearchParams({
        page: options.page || 1,
        limit: options.limit || 20,
        ...options
      });
      
      const response = await this.apiRequest(`${this.config.apiBaseUrl}?${params}`);
      
      if (options.page > 1) {
        // Append to existing notifications
        this.notifications = [...this.notifications, ...response.notifications];
      } else {
        // Replace notifications
        this.notifications = response.notifications;
      }
      
      this.renderNotifications();
      this.updateLoadMoreButton(response.pagination);
      
      return response;
      
    } catch (error) {
      console.error('❌ Failed to load notifications:', error);
      this.showError('Impossible de charger les notifications');
      throw error;
    }
  }

  /**
   * Load unread counts
   */
  async loadUnreadCounts() {
    try {
      const response = await this.apiRequest(`${this.config.apiBaseUrl}/counts`);
      this.unreadCounts = response.counts;
      this.updateBadge();
      
      return response.counts;
      
    } catch (error) {
      console.error('❌ Failed to load unread counts:', error);
      throw error;
    }
  }

  /**
   * Mark notification as read
   */
  async markAsRead(notificationId, optimistic = true) {
    try {
      // Optimistic update
      if (optimistic) {
        const notification = this.notifications.find(n => n.id === notificationId);
        if (notification && notification.status === 'unread') {
          notification.status = 'read';
          notification.readAt = new Date().toISOString();
          this.decrementUnreadCount(notification.type);
          this.renderNotifications();
          this.updateBadge();
        }
      }
      
      const response = await this.apiRequest(
        `${this.config.apiBaseUrl}/${notificationId}/read`,
        { method: 'POST' }
      );
      
      if (!optimistic) {
        // Update from server response
        const notification = this.notifications.find(n => n.id === notificationId);
        if (notification) {
          Object.assign(notification, response.notification);
          this.renderNotifications();
          this.updateBadge();
        }
      }
      
      this.emit('notificationRead', { notificationId, notification: response.notification });
      
      return response;
      
    } catch (error) {
      console.error('❌ Failed to mark notification as read:', error);
      
      // Revert optimistic update on error
      if (optimistic) {
        await this.loadNotifications();
        await this.loadUnreadCounts();
      }
      
      throw error;
    }
  }

  /**
   * Mark all notifications as read
   */
  async markAllAsRead(type = null) {
    try {
      const body = type ? { type } : {};
      
      const response = await this.apiRequest(
        `${this.config.apiBaseUrl}/mark-all-read`,
        {
          method: 'POST',
          body: JSON.stringify(body)
        }
      );
      
      // Update local state
      this.notifications.forEach(notification => {
        if (!type || notification.type === type) {
          if (notification.status === 'unread') {
            notification.status = 'read';
            notification.readAt = new Date().toISOString();
          }
        }
      });
      
      // Reset unread counts
      if (type) {
        this.unreadCounts[type] = 0;
      } else {
        Object.keys(this.unreadCounts).forEach(key => {
          if (key !== 'total' && key !== 'highPriorityTotal') {
            this.unreadCounts[key] = 0;
          }
        });
        this.unreadCounts.total = 0;
        this.unreadCounts.highPriorityTotal = 0;
      }
      
      this.renderNotifications();
      this.updateBadge();
      
      this.emit('allNotificationsRead', { type, count: response.modifiedCount });
      
      return response;
      
    } catch (error) {
      console.error('❌ Failed to mark all notifications as read:', error);
      this.showError('Impossible de marquer toutes les notifications comme lues');
      throw error;
    }
  }

  /**
   * Handle handshake action (accept/decline)
   */
  async handleHandshakeAction(handshakeId, action, responseMessage = '') {
    try {
      const body = responseMessage ? { responseMessage } : {};
      
      const response = await this.apiRequest(
        `${this.config.apiBaseUrl}/handshake/${handshakeId}/${action}`,
        {
          method: 'POST',
          body: JSON.stringify(body)
        }
      );
      
      // Remove or update the notification
      const notificationIndex = this.notifications.findIndex(n => 
        n.relatedHandshakeId === handshakeId && n.type === 'handshake_request'
      );
      
      if (notificationIndex >= 0) {
        const notification = this.notifications[notificationIndex];
        if (notification.status === 'unread') {
          this.decrementUnreadCount(notification.type);
        }
        this.notifications.splice(notificationIndex, 1);
      }
      
      this.renderNotifications();
      this.updateBadge();
      
      this.emit('handshakeAction', { handshakeId, action, result: response });
      
      // Show success message
      this.showSuccess(`Handshake ${action === 'accept' ? 'accepté' : 'refusé'} avec succès`);
      
      return response;
      
    } catch (error) {
      console.error(`❌ Failed to ${action} handshake:`, error);
      this.showError(`Impossible de ${action === 'accept' ? 'accepter' : 'refuser'} le handshake`);
      throw error;
    }
  }

  /**
   * Set up Server-Sent Events for real-time updates
   */
  setupSSE() {
    if (!this.config.enableSSE) return;
    
    try {
      this.eventSource = new EventSource(`${this.config.apiBaseUrl}/stream`);
      
      this.eventSource.onopen = () => {
        console.log('✅ SSE connection established');
        this.retryCount = 0;
      };
      
      this.eventSource.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          this.handleSSEMessage(data);
        } catch (error) {
          console.error('❌ Failed to parse SSE message:', error);
        }
      };
      
      this.eventSource.onerror = (error) => {
        console.error('❌ SSE connection error:', error);
        this.eventSource.close();
        
        // Retry connection with exponential backoff
        if (this.retryCount < this.maxRetries) {
          const delay = Math.pow(2, this.retryCount) * 1000;
          setTimeout(() => {
            this.retryCount++;
            this.setupSSE();
          }, delay);
        } else {
          console.warn('❌ Max SSE retries reached, falling back to polling');
          this.setupPolling();
        }
      };
      
    } catch (error) {
      console.error('❌ Failed to setup SSE:', error);
      this.setupPolling();
    }
  }

  /**
   * Handle SSE messages
   */
  handleSSEMessage(message) {
    switch (message.type) {
      case 'notification_created':
        this.handleNewNotification(message.data);
        break;
        
      case 'notification_read':
        this.handleNotificationRead(message.data);
        break;
        
      case 'notifications_read_all':
        this.handleAllNotificationsRead(message.data);
        break;
        
      case 'handshake_action_completed':
      case 'handshake_response_received':
        this.handleHandshakeUpdate(message.data);
        break;
        
      case 'connection_established':
        console.log('📡 SSE connection confirmed');
        break;
        
      case 'heartbeat':
        // Keep connection alive
        break;
        
      default:
        console.log('📨 Unknown SSE message type:', message.type);
    }
  }

  /**
   * Handle new notification from SSE
   */
  handleNewNotification(notification) {
    // Add to beginning of notifications list
    this.notifications.unshift(notification);
    
    // Limit notifications in memory
    if (this.notifications.length > this.config.maxNotifications) {
      this.notifications = this.notifications.slice(0, this.config.maxNotifications);
    }
    
    // Update unread counts
    if (notification.status === 'unread') {
      this.incrementUnreadCount(notification.type);
    }
    
    this.renderNotifications();
    this.updateBadge();
    
    // Show browser notification if enabled
    if (this.config.enableBrowserNotifications && notification.status === 'unread') {
      this.showBrowserNotification(notification);
    }
    
    this.emit('newNotification', notification);
  }

  /**
   * Handle notification read from SSE
   */
  handleNotificationRead(data) {
    const notification = this.notifications.find(n => n.id === data.notificationId);
    if (notification && notification.status === 'unread') {
      notification.status = 'read';
      notification.readAt = new Date().toISOString();
      this.decrementUnreadCount(notification.type);
      this.renderNotifications();
      this.updateBadge();
    }
  }

  /**
   * Handle all notifications read from SSE
   */
  handleAllNotificationsRead(data) {
    this.notifications.forEach(notification => {
      if (!data.type || notification.type === data.type) {
        if (notification.status === 'unread') {
          notification.status = 'read';
          notification.readAt = new Date().toISOString();
        }
      }
    });
    
    if (data.type) {
      this.unreadCounts[data.type] = 0;
    } else {
      Object.keys(this.unreadCounts).forEach(key => {
        if (key !== 'total' && key !== 'highPriorityTotal') {
          this.unreadCounts[key] = 0;
        }
      });
      this.unreadCounts.total = 0;
      this.unreadCounts.highPriorityTotal = 0;
    }
    
    this.renderNotifications();
    this.updateBadge();
  }

  /**
   * Set up polling fallback
   */
  setupPolling() {
    if (this.updateTimer) {
      clearInterval(this.updateTimer);
    }
    
    this.updateTimer = setInterval(async () => {
      try {
        await this.loadUnreadCounts();
        
        // Only reload notifications if dropdown is open
        if (this.isDropdownOpen()) {
          await this.loadNotifications();
        }
      } catch (error) {
        console.error('❌ Polling update failed:', error);
      }
    }, this.config.updateInterval);
  }

  /**
   * Render notifications in the dropdown
   */
  renderNotifications() {
    if (!this.elements.list) return;
    
    const activeFilter = document.querySelector('.filter-btn.active')?.dataset.filter || 'all';
    const filteredNotifications = this.filterNotifications(activeFilter);
    
    if (filteredNotifications.length === 0) {
      this.elements.list.innerHTML = `
        <div class="empty-state">
          <div class="empty-state-icon">📭</div>
          <div>Aucune notification</div>
        </div>
      `;
      return;
    }
    
    this.elements.list.innerHTML = filteredNotifications
      .map(notification => this.renderNotificationItem(notification))
      .join('');
    
    // Add click handlers
    this.elements.list.querySelectorAll('.notification-item').forEach((item, index) => {
      const notification = filteredNotifications[index];
      
      item.addEventListener('click', () => {
        if (notification.status === 'unread') {
          this.markAsRead(notification.id);
        }
        
        this.emit('notificationClick', notification);
      });
      
      // Handle action buttons
      const acceptBtn = item.querySelector('.accept-btn');
      const declineBtn = item.querySelector('.decline-btn');
      
      if (acceptBtn) {
        acceptBtn.addEventListener('click', (e) => {
          e.stopPropagation();
          this.handleHandshakeAction(notification.relatedHandshakeId, 'accept');
        });
      }
      
      if (declineBtn) {
        declineBtn.addEventListener('click', (e) => {
          e.stopPropagation();
          this.handleHandshakeAction(notification.relatedHandshakeId, 'decline');
        });
      }
    });
  }

  /**
   * Render individual notification item
   */
  renderNotificationItem(notification) {
    const isUnread = notification.status === 'unread';
    const timeAgo = this.getTimeAgo(notification.createdAt);
    const priorityClass = notification.priority === 'high' || notification.priority === 'urgent' 
      ? notification.priority + '-priority' : '';
    
    let actionsHtml = '';
    if (notification.isActionable && notification.type === 'handshake_request' && !notification.isExpired) {
      actionsHtml = `
        <div class="notification-actions-inline">
          <button class="notification-action-btn accept-btn">Accepter</button>
          <button class="notification-action-btn decline-btn decline">Refuser</button>
        </div>
      `;
    }
    
    return `
      <div class="notification-item ${isUnread ? 'unread' : ''} ${priorityClass}" data-id="${notification.id}">
        <div class="notification-title">
          <span>${this.escapeHtml(notification.title)}</span>
          ${notification.priority === 'high' || notification.priority === 'urgent' ? '<span style="color: #dc3545;">⚠️</span>' : ''}
        </div>
        <div class="notification-message">${this.escapeHtml(notification.message)}</div>
        <div class="notification-meta">
          <span>${timeAgo}</span>
          <span>${isUnread ? '●' : ''}</span>
        </div>
        ${actionsHtml}
      </div>
    `;
  }

  /**
   * Filter notifications based on active filter
   */
  filterNotifications(filter) {
    switch (filter) {
      case 'unread':
        return this.notifications.filter(n => n.status === 'unread');
      case 'all':
        return this.notifications;
      default:
        return this.notifications.filter(n => n.type === filter);
    }
  }

  /**
   * Set active filter
   */
  setFilter(filter) {
    this.elements.filterBtns.forEach(btn => {
      btn.classList.toggle('active', btn.dataset.filter === filter);
    });
    this.renderNotifications();
  }

  /**
   * Update notification badge
   */
  updateBadge() {
    const total = this.unreadCounts.total || 0;
    
    if (total > 0) {
      this.elements.badge.textContent = total > 99 ? '99+' : total.toString();
      this.elements.badge.classList.add('visible');
      this.elements.trigger.classList.add('has-unread');
    } else {
      this.elements.badge.classList.remove('visible');
      this.elements.trigger.classList.remove('has-unread');
    }
  }

  /**
   * Toggle dropdown visibility
   */
  toggleDropdown() {
    if (this.isDropdownOpen()) {
      this.closeDropdown();
    } else {
      this.openDropdown();
    }
  }

  /**
   * Open dropdown
   */
  async openDropdown() {
    this.elements.dropdown.classList.add('open');
    
    // Load latest notifications when opening
    try {
      await this.loadNotifications();
    } catch (error) {
      console.error('Failed to load notifications on dropdown open:', error);
    }
    
    this.emit('dropdownOpened');
  }

  /**
   * Close dropdown
   */
  closeDropdown() {
    this.elements.dropdown.classList.remove('open');
    this.emit('dropdownClosed');
  }

  /**
   * Check if dropdown is open
   */
  isDropdownOpen() {
    return this.elements.dropdown.classList.contains('open');
  }

  /**
   * Refresh notifications
   */
  async refresh() {
    try {
      this.elements.refreshBtn.style.animation = 'spin 1s linear infinite';
      
      await Promise.all([
        this.loadNotifications(),
        this.loadUnreadCounts()
      ]);
      
      this.emit('refreshed');
      
    } catch (error) {
      console.error('Failed to refresh notifications:', error);
      this.showError('Impossible d\'actualiser les notifications');
    } finally {
      this.elements.refreshBtn.style.animation = '';
    }
  }

  /**
   * Load more notifications
   */
  async loadMoreNotifications() {
    try {
      const currentPage = Math.ceil(this.notifications.length / 20);
      await this.loadNotifications({ page: currentPage + 1 });
    } catch (error) {
      console.error('Failed to load more notifications:', error);
      this.showError('Impossible de charger plus de notifications');
    }
  }

  /**
   * Update load more button visibility
   */
  updateLoadMoreButton(pagination) {
    if (pagination.hasNext) {
      this.elements.loadMoreBtn.style.display = 'block';
    } else {
      this.elements.loadMoreBtn.style.display = 'none';
    }
  }

  /**
   * Increment unread count for type
   */
  incrementUnreadCount(type) {
    this.unreadCounts[type] = (this.unreadCounts[type] || 0) + 1;
    this.unreadCounts.total = (this.unreadCounts.total || 0) + 1;
    this.updateBadge();
  }

  /**
   * Decrement unread count for type
   */
  decrementUnreadCount(type) {
    if (this.unreadCounts[type] > 0) {
      this.unreadCounts[type]--;
    }
    if (this.unreadCounts.total > 0) {
      this.unreadCounts.total--;
    }
    this.updateBadge();
  }

  /**
   * Request browser notification permission
   */
  async requestNotificationPermission() {
    if ('Notification' in window) {
      const permission = await Notification.requestPermission();
      return permission === 'granted';
    }
    return false;
  }

  /**
   * Show browser notification
   */
  showBrowserNotification(notification) {
    if ('Notification' in window && Notification.permission === 'granted') {
      const browserNotification = new Notification(notification.title, {
        body: notification.message,
        icon: '/favicon.ico',
        tag: notification.id,
        requireInteraction: notification.priority === 'high' || notification.priority === 'urgent'
      });
      
      browserNotification.onclick = () => {
        window.focus();
        this.openDropdown();
        this.markAsRead(notification.id);
        browserNotification.close();
      };
      
      // Auto close after 5 seconds
      setTimeout(() => {
        browserNotification.close();
      }, 5000);
    }
  }

  /**
   * Show success message
   */
  showSuccess(message) {
    this.showToast(message, 'success');
  }

  /**
   * Show error message
   */
  showError(message) {
    this.showToast(message, 'error');
  }

  /**
   * Show toast notification
   */
  showToast(message, type = 'info') {
    // Use existing UI.showAlert if available, otherwise create simple toast
    if (window.UI && window.UI.showAlert) {
      window.UI.showAlert(message, type);
    } else {
      console.log(`${type.toUpperCase()}: ${message}`);
    }
  }

  /**
   * Make API request with CSRF protection
   */
  async apiRequest(url, options = {}) {
    const defaultOptions = {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
      credentials: 'include'
    };
    
    // Add CSRF token for POST requests
    if (options.method === 'POST' && window.csrfToken) {
      defaultOptions.headers['X-CSRF-Token'] = window.csrfToken;
    }
    
    const finalOptions = { ...defaultOptions, ...options };
    
    const response = await fetch(url, finalOptions);
    
    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(errorData.error || `HTTP ${response.status}`);
    }
    
    return response.json();
  }

  /**
   * Get relative time string
   */
  getTimeAgo(dateString) {
    const date = new Date(dateString);
    const now = new Date();
    const diffMs = now - date;
    const diffMinutes = Math.floor(diffMs / (1000 * 60));
    const diffHours = Math.floor(diffMs / (1000 * 60 * 60));
    const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));
    
    if (diffMinutes < 1) return 'À l\'instant';
    if (diffMinutes < 60) return `Il y a ${diffMinutes}min`;
    if (diffHours < 24) return `Il y a ${diffHours}h`;
    if (diffDays < 7) return `Il y a ${diffDays}j`;
    
    return date.toLocaleDateString('fr-FR');
  }

  /**
   * Escape HTML to prevent XSS
   */
  escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }

  /**
   * Event emitter methods
   */
  on(event, handler) {
    if (!this.eventHandlers.has(event)) {
      this.eventHandlers.set(event, []);
    }
    this.eventHandlers.get(event).push(handler);
  }

  off(event, handler) {
    const handlers = this.eventHandlers.get(event);
    if (handlers) {
      const index = handlers.indexOf(handler);
      if (index > -1) {
        handlers.splice(index, 1);
      }
    }
  }

  emit(event, data) {
    const handlers = this.eventHandlers.get(event);
    if (handlers) {
      handlers.forEach(handler => {
        try {
          handler(data);
        } catch (error) {
          console.error(`Error in event handler for ${event}:`, error);
        }
      });
    }
  }

  /**
   * Cleanup and destroy notification center
   */
  destroy() {
    // Close SSE connection
    if (this.eventSource) {
      this.eventSource.close();
      this.eventSource = null;
    }
    
    // Clear polling timer
    if (this.updateTimer) {
      clearInterval(this.updateTimer);
      this.updateTimer = null;
    }
    
    // Remove UI elements
    if (this.elements.container) {
      this.elements.container.remove();
    }
    
    // Clear event handlers
    this.eventHandlers.clear();
    
    this.isInitialized = false;
    
    this.emit('destroyed');
  }
}

// Export for module usage
if (typeof module !== 'undefined' && module.exports) {
  module.exports = NotificationCenter;
}

// Global usage
if (typeof window !== 'undefined') {
  window.NotificationCenter = NotificationCenter;
}