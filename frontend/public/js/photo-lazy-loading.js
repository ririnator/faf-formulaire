/**
 * Photo Lazy Loading Module for Form-a-Friend
 * Implements progressive image loading, memory management, and performance optimization
 * Designed for mobile-first experience with bandwidth awareness
 */

// =============================================================================
// LAZY LOADING CONFIGURATION
// =============================================================================

const LAZY_LOADING_CONFIG = {
  // Intersection Observer options
  observer: {
    rootMargin: '50px 0px', // Start loading 50px before image enters viewport
    threshold: 0.01 // Trigger when 1% of image is visible
  },
  
  // Image loading strategies
  strategies: {
    eager: 0,      // Load immediately
    lazy: 1,       // Load when entering viewport
    progressive: 2  // Load low-quality first, then high-quality
  },
  
  // Progressive loading quality levels
  progressive: {
    lowQuality: 0.3,    // 30% quality for initial load
    highQuality: 0.8,   // 80% quality for final load
    placeholderBlur: 10 // Blur radius for placeholder
  },
  
  // Memory management
  memory: {
    maxCachedImages: 50,    // Maximum images to keep in memory
    maxImageSize: 2048,     // Maximum image dimension for caching
    cleanupInterval: 30000  // Cleanup interval in milliseconds
  },
  
  // Network-aware loading
  network: {
    slowConnection: ['slow-2g', '2g', '3g'],
    fastConnection: ['4g']
  }
};

// =============================================================================
// NETWORK CONDITION DETECTOR
// =============================================================================

class NetworkConditionDetector {
  constructor() {
    this.connection = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
    this.isSlowConnection = this.detectSlowConnection();
  }
  
  detectSlowConnection() {
    if (!this.connection) {
      // Fallback: assume slow connection on mobile
      return window.innerWidth < 768;
    }
    
    const effectiveType = this.connection.effectiveType;
    return LAZY_LOADING_CONFIG.network.slowConnection.includes(effectiveType);
  }
  
  getOptimalStrategy() {
    if (this.isSlowConnection) {
      return LAZY_LOADING_CONFIG.strategies.progressive;
    }
    return LAZY_LOADING_CONFIG.strategies.lazy;
  }
  
  shouldUseProgressiveLoading() {
    return this.isSlowConnection || (this.connection && this.connection.saveData);
  }
}

// =============================================================================
// IMAGE CACHE MANAGER
// =============================================================================

class ImageCacheManager {
  constructor() {
    this.cache = new Map();
    this.accessTimes = new Map();
    this.maxSize = LAZY_LOADING_CONFIG.memory.maxCachedImages;
    
    // Start periodic cleanup
    this.startCleanupInterval();
  }
  
  set(url, imageElement) {
    // Remove oldest entries if cache is full
    if (this.cache.size >= this.maxSize) {
      this.evictOldest();
    }
    
    this.cache.set(url, imageElement);
    this.accessTimes.set(url, Date.now());
  }
  
  get(url) {
    if (this.cache.has(url)) {
      this.accessTimes.set(url, Date.now()); // Update access time
      return this.cache.get(url);
    }
    return null;
  }
  
  has(url) {
    return this.cache.has(url);
  }
  
  evictOldest() {
    let oldestTime = Date.now();
    let oldestUrl = null;
    
    for (const [url, time] of this.accessTimes) {
      if (time < oldestTime) {
        oldestTime = time;
        oldestUrl = url;
      }
    }
    
    if (oldestUrl) {
      this.cache.delete(oldestUrl);
      this.accessTimes.delete(oldestUrl);
    }
  }
  
  startCleanupInterval() {
    setInterval(() => {
      this.performCleanup();
    }, LAZY_LOADING_CONFIG.memory.cleanupInterval);
  }
  
  performCleanup() {
    const now = Date.now();
    const maxAge = 5 * 60 * 1000; // 5 minutes
    
    for (const [url, accessTime] of this.accessTimes) {
      if (now - accessTime > maxAge) {
        this.cache.delete(url);
        this.accessTimes.delete(url);
      }
    }
  }
  
  clear() {
    this.cache.clear();
    this.accessTimes.clear();
  }
}

// =============================================================================
// PROGRESSIVE IMAGE LOADER
// =============================================================================

class ProgressiveImageLoader {
  constructor() {
    this.networkDetector = new NetworkConditionDetector();
    this.cache = new ImageCacheManager();
  }
  
  /**
   * Creates a progressive loading placeholder
   */
  createPlaceholder(originalSrc, width, height) {
    const canvas = document.createElement('canvas');
    canvas.width = Math.min(width, 40);
    canvas.height = Math.min(height, 40);
    canvas.style.filter = `blur(${LAZY_LOADING_CONFIG.progressive.placeholderBlur}px)`;
    canvas.style.transform = 'scale(1.1)'; // Slightly larger to hide blur edges
    
    const ctx = canvas.getContext('2d');
    
    // Create a simple gradient placeholder
    const gradient = ctx.createLinearGradient(0, 0, canvas.width, canvas.height);
    gradient.addColorStop(0, '#f0f0f0');
    gradient.addColorStop(1, '#e0e0e0');
    
    ctx.fillStyle = gradient;
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    
    return canvas.toDataURL('image/jpeg', 0.1);
  }
  
  /**
   * Generates a low-quality version URL for Cloudinary images
   */
  generateLowQualityUrl(originalUrl) {
    if (!originalUrl.includes('res.cloudinary.com')) {
      return originalUrl; // Not a Cloudinary URL
    }
    
    try {
      // Cloudinary URL transformation for low quality
      const url = new URL(originalUrl);
      const pathParts = url.pathname.split('/');
      
      // Find the upload part and add quality transformation
      const uploadIndex = pathParts.indexOf('upload');
      if (uploadIndex !== -1) {
        // Insert quality and format transformations
        pathParts.splice(uploadIndex + 1, 0, 'q_30,f_auto');
        url.pathname = pathParts.join('/');
        return url.toString();
      }
    } catch (error) {
      console.error('Error generating low quality URL:', error);
    }
    
    return originalUrl;
  }
  
  /**
   * Loads an image progressively (low quality first, then high quality)
   */
  async loadProgressive(imageElement, originalSrc, options = {}) {
    const container = imageElement.parentElement;
    const shouldUseProgressive = this.networkDetector.shouldUseProgressiveLoading();
    
    if (!shouldUseProgressive) {
      // Direct loading for fast connections
      return this.loadDirect(imageElement, originalSrc, options);
    }
    
    try {
      // Step 1: Show placeholder
      const placeholder = this.createPlaceholder(originalSrc, 
        imageElement.naturalWidth || 300, 
        imageElement.naturalHeight || 200);
      
      imageElement.src = placeholder;
      imageElement.style.transition = 'filter 0.3s ease';
      
      // Step 2: Load low quality version
      const lowQualityUrl = this.generateLowQualityUrl(originalSrc);
      const lowQualityImg = await this.loadImage(lowQualityUrl);
      
      imageElement.src = lowQualityUrl;
      imageElement.style.filter = 'blur(1px)';
      
      // Step 3: Load high quality version
      const highQualityImg = await this.loadImage(originalSrc);
      
      // Smooth transition to high quality
      const transition = () => {
        imageElement.src = originalSrc;
        imageElement.style.filter = 'none';
        
        // Cache the high quality image
        this.cache.set(originalSrc, highQualityImg);
        
        // Trigger load event
        imageElement.dispatchEvent(new Event('load'));
      };
      
      // Use requestAnimationFrame for smooth transition
      requestAnimationFrame(transition);
      
    } catch (error) {
      console.error('Progressive loading failed:', error);
      // Fallback to direct loading
      this.loadDirect(imageElement, originalSrc, options);
    }
  }
  
  /**
   * Loads an image directly
   */
  async loadDirect(imageElement, src, options = {}) {
    try {
      // Check cache first
      if (this.cache.has(src)) {
        const cachedImg = this.cache.get(src);
        imageElement.src = src;
        imageElement.dispatchEvent(new Event('load'));
        return;
      }
      
      // Load image
      const img = await this.loadImage(src);
      imageElement.src = src;
      
      // Cache the image
      this.cache.set(src, img);
      
    } catch (error) {
      console.error('Direct loading failed:', error);
      imageElement.dispatchEvent(new Event('error'));
    }
  }
  
  /**
   * Promise-based image loading
   */
  loadImage(src) {
    return new Promise((resolve, reject) => {
      const img = new Image();
      img.onload = () => resolve(img);
      img.onerror = () => reject(new Error(`Failed to load image: ${src}`));
      img.src = src;
    });
  }
}

// =============================================================================
// INTERSECTION OBSERVER LAZY LOADER
// =============================================================================

class LazyImageLoader {
  constructor() {
    this.progressiveLoader = new ProgressiveImageLoader();
    this.observer = null;
    this.pendingImages = new Set();
    
    this.initializeObserver();
  }
  
  initializeObserver() {
    if (!('IntersectionObserver' in window)) {
      // Fallback for browsers without IntersectionObserver
      this.loadAllImages();
      return;
    }
    
    this.observer = new IntersectionObserver(
      this.handleIntersection.bind(this),
      LAZY_LOADING_CONFIG.observer
    );
  }
  
  handleIntersection(entries) {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        const img = entry.target;
        this.loadImage(img);
        this.observer.unobserve(img);
        this.pendingImages.delete(img);
      }
    });
  }
  
  /**
   * Observes an image for lazy loading
   */
  observe(imageElement, options = {}) {
    if (!imageElement.dataset.lazySrc) {
      console.warn('Image element missing data-lazy-src attribute');
      return;
    }
    
    // Add loading placeholder
    this.addLoadingPlaceholder(imageElement);
    
    // Add to observer
    if (this.observer) {
      this.observer.observe(imageElement);
      this.pendingImages.add(imageElement);
    } else {
      // Fallback: load immediately
      this.loadImage(imageElement, options);
    }
  }
  
  /**
   * Loads a specific image
   */
  async loadImage(imageElement, options = {}) {
    const src = imageElement.dataset.lazySrc;
    if (!src) return;
    
    // Add loading class
    imageElement.classList.add('lazy-loading');
    
    try {
      // Use progressive loading if enabled
      if (options.progressive !== false) {
        await this.progressiveLoader.loadProgressive(imageElement, src, options);
      } else {
        await this.progressiveLoader.loadDirect(imageElement, src, options);
      }
      
      // Success
      imageElement.classList.remove('lazy-loading');
      imageElement.classList.add('lazy-loaded');
      
    } catch (error) {
      console.error('Lazy loading failed:', error);
      imageElement.classList.remove('lazy-loading');
      imageElement.classList.add('lazy-error');
      
      // Show error placeholder
      this.showErrorPlaceholder(imageElement);
    }
  }
  
  /**
   * Adds a loading placeholder to the image
   */
  addLoadingPlaceholder(imageElement) {
    imageElement.style.backgroundColor = '#f0f0f0';
    imageElement.style.backgroundImage = `url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='%23ccc'%3E%3Cpath d='M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z'/%3E%3C/svg%3E")`;
    imageElement.style.backgroundRepeat = 'no-repeat';
    imageElement.style.backgroundPosition = 'center';
    imageElement.style.backgroundSize = '48px';
  }
  
  /**
   * Shows an error placeholder
   */
  showErrorPlaceholder(imageElement) {
    imageElement.style.backgroundColor = '#ffebee';
    imageElement.style.backgroundImage = `url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='%23f44336'%3E%3Cpath d='M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z'/%3E%3C/svg%3E")`;
    imageElement.alt = 'Image non disponible';
  }
  
  /**
   * Loads all images immediately (fallback)
   */
  loadAllImages() {
    const lazyImages = document.querySelectorAll('[data-lazy-src]');
    lazyImages.forEach(img => {
      this.loadImage(img, { progressive: false });
    });
  }
  
  /**
   * Preloads images that are likely to be viewed next
   */
  preloadNextImages(currentIndex, imageElements, range = 2) {
    const startIndex = Math.max(0, currentIndex - range);
    const endIndex = Math.min(imageElements.length - 1, currentIndex + range);
    
    for (let i = startIndex; i <= endIndex; i++) {
      if (i !== currentIndex && imageElements[i]) {
        const img = imageElements[i];
        if (img.dataset.lazySrc && !img.classList.contains('lazy-loaded')) {
          this.loadImage(img, { progressive: false });
        }
      }
    }
  }
  
  /**
   * Cleanup when component is destroyed
   */
  destroy() {
    if (this.observer) {
      this.observer.disconnect();
    }
    
    this.pendingImages.clear();
    this.progressiveLoader.cache.clear();
  }
}

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

/**
 * Converts regular images to lazy-loaded images
 */
function convertToLazyLoading(selector = 'img[src*="res.cloudinary.com"]') {
  const images = document.querySelectorAll(selector);
  
  images.forEach(img => {
    if (!img.dataset.lazySrc && img.src) {
      // Convert to lazy loading
      img.dataset.lazySrc = img.src;
      img.removeAttribute('src');
      
      // Initialize lazy loading
      window.LazyImageLoader.observe(img);
    }
  });
}

/**
 * Preloads critical images
 */
function preloadCriticalImages(urls) {
  urls.forEach(url => {
    const link = document.createElement('link');
    link.rel = 'preload';
    link.as = 'image';
    link.href = url;
    document.head.appendChild(link);
  });
}

/**
 * Optimizes images for current viewport
 */
function optimizeForViewport() {
  const images = document.querySelectorAll('img[data-lazy-src]');
  const viewportWidth = window.innerWidth;
  const pixelRatio = window.devicePixelRatio || 1;
  
  images.forEach(img => {
    const originalUrl = img.dataset.lazySrc;
    
    if (originalUrl.includes('res.cloudinary.com')) {
      // Calculate optimal size
      const imgWidth = img.offsetWidth || img.naturalWidth || 300;
      const optimalWidth = Math.ceil(imgWidth * pixelRatio);
      
      // Cloudinary transformation for optimal size
      try {
        const url = new URL(originalUrl);
        const pathParts = url.pathname.split('/');
        const uploadIndex = pathParts.indexOf('upload');
        
        if (uploadIndex !== -1) {
          // Add width transformation
          const transform = `w_${optimalWidth},c_scale,f_auto,q_auto`;
          pathParts.splice(uploadIndex + 1, 0, transform);
          
          img.dataset.lazySrc = url.toString();
        }
      } catch (error) {
        console.error('Error optimizing image URL:', error);
      }
    }
  });
}

// =============================================================================
// GLOBAL INITIALIZATION
// =============================================================================

// Create global lazy loader instance
window.LazyImageLoader = new LazyImageLoader();

// Auto-initialize on DOM ready
document.addEventListener('DOMContentLoaded', () => {
  // Convert existing images to lazy loading
  convertToLazyLoading();
  
  // Optimize for current viewport
  optimizeForViewport();
  
  // Re-optimize on window resize (debounced)
  let resizeTimer;
  window.addEventListener('resize', () => {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(optimizeForViewport, 250);
  });
});

// Export for ES6 modules
export {
  LazyImageLoader,
  ProgressiveImageLoader,
  NetworkConditionDetector,
  ImageCacheManager,
  convertToLazyLoading,
  preloadCriticalImages,
  optimizeForViewport
};