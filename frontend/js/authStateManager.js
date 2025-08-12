// Frontend Auth State Management
class AuthStateManager {
  constructor() {
    this.state = {
      isAuthenticated: false,
      user: null,
      loading: true,
      error: null
    };
    this.listeners = [];
    this.init();
  }

  // Input sanitization helpers
  sanitizeInput(input) {
    if (typeof input !== 'string') return '';
    // Remove any HTML tags and trim whitespace
    return input.replace(/<[^>]*>/g, '').trim();
  }

  sanitizeCredentials(credentials) {
    const sanitized = {};
    for (const [key, value] of Object.entries(credentials)) {
      if (typeof value === 'string') {
        // For passwords, only trim whitespace (don't alter special chars)
        if (key === 'password' || key === 'confirmPassword') {
          sanitized[key] = value.trim();
        } else {
          // For other fields, sanitize more strictly
          sanitized[key] = this.sanitizeInput(value);
        }
      } else {
        sanitized[key] = value;
      }
    }
    return sanitized;
  }

  validateEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }

  validateUsername(username) {
    // Username: 3-50 chars, alphanumeric + underscore/dash
    const usernameRegex = /^[a-zA-Z0-9_-]{3,50}$/;
    return usernameRegex.test(username);
  }

  validatePassword(password) {
    // Password: minimum 8 chars
    return password && password.length >= 8;
  }

  // Initialize auth state on page load
  async init() {
    this.setState({ loading: true });
    
    try {
      const authData = await this.checkAuthStatus();
      if (authData && authData.user) {
        this.setState({
          isAuthenticated: true,
          user: authData.user,
          loading: false,
          error: null
        });
      } else {
        this.setState({
          isAuthenticated: false,
          user: null,
          loading: false,
          error: null
        });
      }
    } catch (error) {
      this.setState({
        isAuthenticated: false,
        user: null,
        loading: false,
        error: error.message
      });
    }
  }

  // Check authentication status with server
  async checkAuthStatus() {
    try {
      const response = await fetch('/api/auth/me', {
        credentials: 'include',
        headers: {
          'Accept': 'application/json'
        }
      });
      
      if (response.ok) {
        return await response.json();
      }
      
      return null;
    } catch (error) {
      console.error('Auth status check failed:', error);
      return null;
    }
  }

  // Login with credentials
  async login(credentials) {
    this.setState({ loading: true, error: null });
    
    // Sanitize input
    const sanitizedCredentials = this.sanitizeCredentials(credentials);
    
    // Validate input
    if (!sanitizedCredentials.username || !sanitizedCredentials.password) {
      const error = 'Username and password are required';
      this.setState({ loading: false, error });
      return { success: false, error };
    }
    
    try {
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        credentials: 'include',
        body: JSON.stringify(sanitizedCredentials)
      });

      const result = await response.json();

      if (response.ok) {
        this.setState({
          isAuthenticated: true,
          user: result.user,
          loading: false,
          error: null
        });
        return { success: true, user: result.user };
      } else {
        this.setState({
          isAuthenticated: false,
          user: null,
          loading: false,
          error: result.error
        });
        return { success: false, error: result.error };
      }
    } catch (error) {
      this.setState({
        isAuthenticated: false,
        user: null,
        loading: false,
        error: error.message
      });
      return { success: false, error: error.message };
    }
  }

  // Register new user
  async register(userData) {
    this.setState({ loading: true, error: null });
    
    // Sanitize input
    const sanitizedData = this.sanitizeCredentials(userData);
    
    // Validate input
    if (!sanitizedData.username || !sanitizedData.password) {
      const error = 'Username and password are required';
      this.setState({ loading: false, error });
      return { success: false, error };
    }
    
    if (!this.validateUsername(sanitizedData.username)) {
      const error = 'Username must be 3-50 characters and contain only letters, numbers, underscore, or dash';
      this.setState({ loading: false, error });
      return { success: false, error };
    }
    
    if (!this.validatePassword(sanitizedData.password)) {
      const error = 'Password must be at least 8 characters long';
      this.setState({ loading: false, error });
      return { success: false, error };
    }
    
    if (sanitizedData.email && !this.validateEmail(sanitizedData.email)) {
      const error = 'Please provide a valid email address';
      this.setState({ loading: false, error });
      return { success: false, error };
    }
    
    try {
      const response = await fetch('/api/auth/register', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        credentials: 'include',
        body: JSON.stringify(sanitizedData)
      });

      const result = await response.json();

      if (response.ok) {
        this.setState({
          isAuthenticated: true,
          user: result.user,
          loading: false,
          error: null
        });
        return { 
          success: true, 
          user: result.user,
          migrated: result.migrated,
          migratedCount: result.migratedCount
        };
      } else {
        this.setState({
          isAuthenticated: false,
          user: null,
          loading: false,
          error: result.error
        });
        return { success: false, error: result.error, details: result.details };
      }
    } catch (error) {
      this.setState({
        isAuthenticated: false,
        user: null,
        loading: false,
        error: error.message
      });
      return { success: false, error: error.message };
    }
  }

  // Logout user
  async logout() {
    this.setState({ loading: true });
    
    try {
      await fetch('/api/auth/logout', {
        method: 'POST',
        credentials: 'include'
      });
    } catch (error) {
      console.error('Logout request failed:', error);
    }
    
    this.setState({
      isAuthenticated: false,
      user: null,
      loading: false,
      error: null
    });
    
    // Redirect to auth choice page
    window.location.href = '/auth-choice';
  }

  // Update user profile
  async updateProfile(profileData) {
    this.setState({ loading: true, error: null });
    
    // Sanitize input
    const sanitizedData = this.sanitizeCredentials(profileData);
    
    // Validate email if provided
    if (sanitizedData.email && !this.validateEmail(sanitizedData.email)) {
      const error = 'Please provide a valid email address';
      this.setState({ loading: false, error });
      return { success: false, error };
    }
    
    try {
      const response = await fetch('/api/auth/profile', {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json'
        },
        credentials: 'include',
        body: JSON.stringify(sanitizedData)
      });

      const result = await response.json();

      if (response.ok) {
        this.setState({
          user: result.user,
          loading: false,
          error: null
        });
        return { success: true, user: result.user };
      } else {
        this.setState({
          loading: false,
          error: result.error
        });
        return { success: false, error: result.error, details: result.details };
      }
    } catch (error) {
      this.setState({
        loading: false,
        error: error.message
      });
      return { success: false, error: error.message };
    }
  }

  // State management
  setState(newState) {
    this.state = { ...this.state, ...newState };
    this.notifyListeners();
  }

  getState() {
    return { ...this.state };
  }

  // Subscribe to state changes
  subscribe(callback) {
    this.listeners.push(callback);
    return () => {
      this.listeners = this.listeners.filter(listener => listener !== callback);
    };
  }

  notifyListeners() {
    this.listeners.forEach(callback => callback(this.state));
  }

  // Utility methods
  isAuthenticated() {
    return this.state.isAuthenticated;
  }

  getUser() {
    return this.state.user;
  }

  isLoading() {
    return this.state.loading;
  }

  getError() {
    return this.state.error;
  }

  clearError() {
    this.setState({ error: null });
  }

  // Check if user has specific role
  hasRole(role) {
    return this.state.user && this.state.user.role === role;
  }

  isAdmin() {
    return this.hasRole('admin');
  }

  // Redirect helpers
  redirectIfAuthenticated() {
    if (this.isAuthenticated() && !this.isLoading()) {
      if (this.isAdmin()) {
        window.location.href = '/admin';
      } else {
        window.location.href = '/dashboard';
      }
      return true;
    }
    return false;
  }

  redirectIfNotAuthenticated() {
    if (!this.isAuthenticated() && !this.isLoading()) {
      window.location.href = '/auth-choice';
      return true;
    }
    return false;
  }
}

// Global auth state manager instance
const authStateManager = new AuthStateManager();

// Export for use in modules
if (typeof module !== 'undefined' && module.exports) {
  module.exports = AuthStateManager;
}