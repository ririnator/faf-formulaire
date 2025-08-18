/**
 * Photo Lightbox Component for Form-a-Friend
 * Responsive lightbox with zoom/pan functionality, touch gestures, and keyboard navigation
 * Integrates with existing photo system and security validation
 */

// =============================================================================
// LIGHTBOX CONFIGURATION
// =============================================================================

const LIGHTBOX_CONFIG = {
  // Zoom settings
  zoom: {
    min: 0.5,
    max: 5,
    step: 0.5,
    wheelSensitivity: 0.1,
    doubleTapZoom: 2
  },
  
  // Touch gesture settings
  touch: {
    pinchSensitivity: 0.02,
    panThreshold: 10,
    swipeThreshold: 50,
    swipeVelocity: 0.3
  },
  
  // Animation settings
  animation: {
    duration: 300,
    easing: 'cubic-bezier(0.25, 0.46, 0.45, 0.94)'
  },
  
  // Preloading settings
  preload: {
    enabled: true,
    range: 2 // Preload 2 images before and after current
  },
  
  // Trusted domains for security (inherited from view.js)
  trustedDomains: [
    'res.cloudinary.com',
    'images.unsplash.com',
    'via.placeholder.com'
  ]
};

// =============================================================================
// TOUCH GESTURE HANDLER
// =============================================================================

class TouchGestureHandler {
  constructor(element, callbacks) {
    this.element = element;
    this.callbacks = callbacks;
    this.isTouch = false;
    this.touches = new Map();
    this.lastTap = 0;
    this.lastPinchDistance = 0;
    this.lastPan = { x: 0, y: 0 };
    this.velocity = { x: 0, y: 0 };
    this.lastMoveTime = 0;
    
    this.initializeEventListeners();
  }
  
  initializeEventListeners() {
    // Touch events
    this.element.addEventListener('touchstart', this.handleTouchStart.bind(this), { passive: false });
    this.element.addEventListener('touchmove', this.handleTouchMove.bind(this), { passive: false });
    this.element.addEventListener('touchend', this.handleTouchEnd.bind(this), { passive: false });
    
    // Mouse events (for desktop compatibility)
    this.element.addEventListener('mousedown', this.handleMouseDown.bind(this));
    this.element.addEventListener('mousemove', this.handleMouseMove.bind(this));
    this.element.addEventListener('mouseup', this.handleMouseUp.bind(this));
    this.element.addEventListener('wheel', this.handleWheel.bind(this), { passive: false });
    
    // Prevent context menu on long press
    this.element.addEventListener('contextmenu', (e) => e.preventDefault());
  }
  
  handleTouchStart(e) {
    e.preventDefault();
    this.isTouch = true;
    
    // Store touch points
    Array.from(e.changedTouches).forEach(touch => {
      this.touches.set(touch.identifier, {
        x: touch.clientX,
        y: touch.clientY,
        startX: touch.clientX,
        startY: touch.clientY,
        startTime: Date.now()
      });
    });
    
    // Handle double tap
    if (e.touches.length === 1) {
      const now = Date.now();
      if (now - this.lastTap < 300) {
        this.handleDoubleTap(e.touches[0]);
      }
      this.lastTap = now;
    }
    
    // Initialize pinch gesture
    if (e.touches.length === 2) {
      this.lastPinchDistance = this.getPinchDistance(e.touches);
      this.callbacks.onPinchStart?.(this.lastPinchDistance);
    }
  }
  
  handleTouchMove(e) {
    e.preventDefault();
    
    const currentTime = Date.now();
    
    if (e.touches.length === 1) {
      // Single touch - pan
      const touch = e.touches[0];
      const stored = this.touches.get(touch.identifier);
      
      if (stored) {
        const deltaX = touch.clientX - stored.x;
        const deltaY = touch.clientY - stored.y;
        
        // Calculate velocity for momentum
        if (currentTime - this.lastMoveTime > 0) {
          this.velocity = {
            x: deltaX / (currentTime - this.lastMoveTime),
            y: deltaY / (currentTime - this.lastMoveTime)
          };
        }
        
        this.callbacks.onPan?.(deltaX, deltaY);
        
        // Update stored position
        stored.x = touch.clientX;
        stored.y = touch.clientY;
        this.lastMoveTime = currentTime;
      }
    } else if (e.touches.length === 2) {
      // Two touches - pinch zoom
      const currentDistance = this.getPinchDistance(e.touches);
      const scale = currentDistance / this.lastPinchDistance;
      
      this.callbacks.onPinch?.(scale);
      this.lastPinchDistance = currentDistance;
    }
  }
  
  handleTouchEnd(e) {
    // Remove ended touches
    Array.from(e.changedTouches).forEach(touch => {
      const stored = this.touches.get(touch.identifier);
      
      if (stored && e.touches.length === 0) {
        // Check for swipe gesture
        const deltaX = touch.clientX - stored.startX;
        const deltaY = touch.clientY - stored.startY;
        const deltaTime = Date.now() - stored.startTime;
        const distance = Math.sqrt(deltaX * deltaX + deltaY * deltaY);
        const velocity = distance / deltaTime;
        
        if (velocity > LIGHTBOX_CONFIG.touch.swipeVelocity && 
            distance > LIGHTBOX_CONFIG.touch.swipeThreshold) {
          
          if (Math.abs(deltaX) > Math.abs(deltaY)) {
            // Horizontal swipe
            if (deltaX > 0) {
              this.callbacks.onSwipeRight?.();
            } else {
              this.callbacks.onSwipeLeft?.();
            }
          }
        }
        
        // Apply momentum to pan
        if (Math.abs(this.velocity.x) > 0.1 || Math.abs(this.velocity.y) > 0.1) {
          this.callbacks.onMomentum?.(this.velocity);
        }
      }
      
      this.touches.delete(touch.identifier);
    });
    
    if (e.touches.length === 0) {
      this.isTouch = false;
    }
  }
  
  handleDoubleTap(touch) {
    this.callbacks.onDoubleTap?.(touch.clientX, touch.clientY);
  }
  
  handleMouseDown(e) {
    if (this.isTouch) return;
    
    this.isMouseDown = true;
    this.lastMousePos = { x: e.clientX, y: e.clientY };
  }
  
  handleMouseMove(e) {
    if (this.isTouch || !this.isMouseDown) return;
    
    const deltaX = e.clientX - this.lastMousePos.x;
    const deltaY = e.clientY - this.lastMousePos.y;
    
    this.callbacks.onPan?.(deltaX, deltaY);
    
    this.lastMousePos = { x: e.clientX, y: e.clientY };
  }
  
  handleMouseUp(e) {
    this.isMouseDown = false;
  }
  
  handleWheel(e) {
    e.preventDefault();
    
    const delta = e.deltaY * -LIGHTBOX_CONFIG.zoom.wheelSensitivity;
    this.callbacks.onZoom?.(delta, e.clientX, e.clientY);
  }
  
  getPinchDistance(touches) {
    const touch1 = touches[0];
    const touch2 = touches[1];
    
    const dx = touch2.clientX - touch1.clientX;
    const dy = touch2.clientY - touch1.clientY;
    
    return Math.sqrt(dx * dx + dy * dy);
  }
  
  destroy() {
    // Remove all event listeners
    this.element.removeEventListener('touchstart', this.handleTouchStart);
    this.element.removeEventListener('touchmove', this.handleTouchMove);
    this.element.removeEventListener('touchend', this.handleTouchEnd);
    this.element.removeEventListener('mousedown', this.handleMouseDown);
    this.element.removeEventListener('mousemove', this.handleMouseMove);
    this.element.removeEventListener('mouseup', this.handleMouseUp);
    this.element.removeEventListener('wheel', this.handleWheel);
  }
}

// =============================================================================
// PHOTO LIGHTBOX COMPONENT
// =============================================================================

class PhotoLightbox {
  constructor() {
    this.isOpen = false;
    this.currentIndex = 0;
    this.photos = [];
    this.scale = 1;
    this.translateX = 0;
    this.translateY = 0;
    this.gestureHandler = null;
    this.preloadedImages = new Map();
    this.animationId = null;
    
    this.createLightboxHTML();
    this.initializeEventListeners();
  }
  
  createLightboxHTML() {
    const lightbox = document.createElement('div');
    lightbox.id = 'photo-lightbox';
    lightbox.className = 'photo-lightbox';
    lightbox.innerHTML = `
      <div class="lightbox-backdrop"></div>
      <div class="lightbox-container">
        <div class="lightbox-header">
          <div class="lightbox-counter">
            <span class="current-index">1</span> / <span class="total-count">1</span>
          </div>
          <div class="lightbox-title"></div>
          <button class="lightbox-close" aria-label="Fermer la lightbox">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <line x1="18" y1="6" x2="6" y2="18"></line>
              <line x1="6" y1="6" x2="18" y2="18"></line>
            </svg>
          </button>
        </div>
        
        <div class="lightbox-content">
          <button class="lightbox-nav lightbox-prev" aria-label="Image précédente">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <polyline points="15,18 9,12 15,6"></polyline>
            </svg>
          </button>
          
          <div class="lightbox-image-container">
            <div class="lightbox-image-wrapper">
              <img class="lightbox-image" alt="Photo en cours de visualisation">
              <div class="lightbox-loading">
                <div class="loading-spinner"></div>
                <div class="loading-text">Chargement...</div>
              </div>
            </div>
          </div>
          
          <button class="lightbox-nav lightbox-next" aria-label="Image suivante">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <polyline points="9,18 15,12 9,6"></polyline>
            </svg>
          </button>
        </div>
        
        <div class="lightbox-footer">
          <div class="lightbox-controls">
            <button class="control-btn zoom-out" aria-label="Dézoomer">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <circle cx="11" cy="11" r="8"></circle>
                <path d="m21 21-4.35-4.35"></path>
                <line x1="8" y1="11" x2="14" y2="11"></line>
              </svg>
            </button>
            
            <button class="control-btn zoom-reset" aria-label="Réinitialiser le zoom">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"></path>
                <path d="M3 3v5h5"></path>
              </svg>
            </button>
            
            <button class="control-btn zoom-in" aria-label="Zoomer">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <circle cx="11" cy="11" r="8"></circle>
                <path d="m21 21-4.35-4.35"></path>
                <line x1="11" y1="8" x2="11" y2="14"></line>
                <line x1="8" y1="11" x2="14" y2="11"></line>
              </svg>
            </button>
            
            <div class="zoom-indicator">
              <span class="zoom-level">100%</span>
            </div>
          </div>
          
          <div class="lightbox-info">
            <div class="photo-description"></div>
          </div>
        </div>
      </div>
    `;
    
    document.body.appendChild(lightbox);
    this.lightboxElement = lightbox;
    this.imageElement = lightbox.querySelector('.lightbox-image');
    this.imageWrapper = lightbox.querySelector('.lightbox-image-wrapper');
    this.loadingElement = lightbox.querySelector('.lightbox-loading');
  }
  
  initializeEventListeners() {
    // Close button
    this.lightboxElement.querySelector('.lightbox-close').addEventListener('click', () => {
      this.close();
    });
    
    // Backdrop click to close
    this.lightboxElement.querySelector('.lightbox-backdrop').addEventListener('click', () => {
      this.close();
    });
    
    // Navigation buttons
    this.lightboxElement.querySelector('.lightbox-prev').addEventListener('click', () => {
      this.previousPhoto();
    });
    
    this.lightboxElement.querySelector('.lightbox-next').addEventListener('click', () => {
      this.nextPhoto();
    });
    
    // Zoom controls
    this.lightboxElement.querySelector('.zoom-out').addEventListener('click', () => {
      this.zoomOut();
    });
    
    this.lightboxElement.querySelector('.zoom-in').addEventListener('click', () => {
      this.zoomIn();
    });
    
    this.lightboxElement.querySelector('.zoom-reset').addEventListener('click', () => {
      this.resetZoom();
    });
    
    // Keyboard navigation
    document.addEventListener('keydown', this.handleKeydown.bind(this));
    
    // Prevent scroll on mobile when lightbox is open
    document.addEventListener('touchmove', this.preventScroll.bind(this), { passive: false });
  }
  
  open(photos, startIndex = 0, options = {}) {
    this.photos = this.validatePhotos(photos);
    this.currentIndex = Math.max(0, Math.min(startIndex, this.photos.length - 1));
    this.options = options;
    
    if (this.photos.length === 0) {
      console.error('Aucune photo valide à afficher');
      return;
    }
    
    this.isOpen = true;
    this.lightboxElement.classList.add('active');
    document.body.classList.add('lightbox-open');
    
    // Initialize gesture handler
    this.gestureHandler = new TouchGestureHandler(this.imageWrapper, {
      onPan: this.handlePan.bind(this),
      onPinch: this.handlePinch.bind(this),
      onZoom: this.handleZoom.bind(this),
      onDoubleTap: this.handleDoubleTap.bind(this),
      onSwipeLeft: this.nextPhoto.bind(this),
      onSwipeRight: this.previousPhoto.bind(this),
      onMomentum: this.handleMomentum.bind(this)
    });
    
    this.updateUI();
    this.loadCurrentPhoto();
    this.preloadAdjacentPhotos();
    
    // Focus management for accessibility
    this.lightboxElement.focus();
  }
  
  close() {
    if (!this.isOpen) return;
    
    this.isOpen = false;
    this.lightboxElement.classList.remove('active');
    document.body.classList.remove('lightbox-open');
    
    // Cleanup
    if (this.gestureHandler) {
      this.gestureHandler.destroy();
      this.gestureHandler = null;
    }
    
    this.resetTransform();
    this.clearPreloadedImages();
    
    // Cancel any pending animations
    if (this.animationId) {
      cancelAnimationFrame(this.animationId);
      this.animationId = null;
    }
  }
  
  validatePhotos(photos) {
    return photos.filter(photo => {
      if (typeof photo === 'string') {
        return this.isValidImageUrl(photo);
      } else if (photo && typeof photo === 'object') {
        return photo.url && this.isValidImageUrl(photo.url);
      }
      return false;
    }).map(photo => {
      if (typeof photo === 'string') {
        return { url: photo, title: '', description: '' };
      }
      return photo;
    });
  }
  
  isValidImageUrl(url) {
    try {
      const urlObj = new URL(url);
      return urlObj.protocol === 'https:' && 
             LIGHTBOX_CONFIG.trustedDomains.some(domain => 
               urlObj.hostname.endsWith(domain)
             );
    } catch {
      return false;
    }
  }
  
  loadCurrentPhoto() {
    if (!this.photos[this.currentIndex]) return;
    
    const photo = this.photos[this.currentIndex];
    this.showLoading(true);
    
    // Check if image is already preloaded
    if (this.preloadedImages.has(photo.url)) {
      this.displayPhoto(this.preloadedImages.get(photo.url), photo);
      return;
    }
    
    // Load new image
    const img = new Image();
    img.onload = () => {
      this.preloadedImages.set(photo.url, img);
      this.displayPhoto(img, photo);
    };
    
    img.onerror = () => {
      this.showLoadingError();
    };
    
    img.src = photo.url;
  }
  
  displayPhoto(img, photo) {
    this.imageElement.src = img.src;
    this.imageElement.alt = photo.title || 'Photo';
    
    this.showLoading(false);
    this.resetTransform();
    this.updatePhotoInfo(photo);
  }
  
  showLoading(show) {
    if (show) {
      this.loadingElement.style.display = 'flex';
      this.imageElement.style.opacity = '0';
    } else {
      this.loadingElement.style.display = 'none';
      this.imageElement.style.opacity = '1';
    }
  }
  
  showLoadingError() {
    this.loadingElement.innerHTML = `
      <div class="error-icon">❌</div>
      <div class="error-text">Impossible de charger l'image</div>
    `;
  }
  
  updateUI() {
    // Update counter
    this.lightboxElement.querySelector('.current-index').textContent = this.currentIndex + 1;
    this.lightboxElement.querySelector('.total-count').textContent = this.photos.length;
    
    // Update navigation buttons
    const prevBtn = this.lightboxElement.querySelector('.lightbox-prev');
    const nextBtn = this.lightboxElement.querySelector('.lightbox-next');
    
    prevBtn.style.display = this.photos.length > 1 ? 'flex' : 'none';
    nextBtn.style.display = this.photos.length > 1 ? 'flex' : 'none';
    
    prevBtn.disabled = this.currentIndex === 0;
    nextBtn.disabled = this.currentIndex === this.photos.length - 1;
  }
  
  updatePhotoInfo(photo) {
    const titleElement = this.lightboxElement.querySelector('.lightbox-title');
    const descriptionElement = this.lightboxElement.querySelector('.photo-description');
    
    titleElement.textContent = photo.title || '';
    descriptionElement.textContent = photo.description || '';
  }
  
  preloadAdjacentPhotos() {
    if (!LIGHTBOX_CONFIG.preload.enabled) return;
    
    const range = LIGHTBOX_CONFIG.preload.range;
    
    for (let i = -range; i <= range; i++) {
      const index = this.currentIndex + i;
      if (index >= 0 && index < this.photos.length && index !== this.currentIndex) {
        this.preloadPhoto(this.photos[index].url);
      }
    }
  }
  
  preloadPhoto(url) {
    if (this.preloadedImages.has(url)) return;
    
    const img = new Image();
    img.onload = () => {
      this.preloadedImages.set(url, img);
    };
    img.src = url;
  }
  
  clearPreloadedImages() {
    this.preloadedImages.clear();
  }
  
  // Navigation methods
  nextPhoto() {
    if (this.currentIndex < this.photos.length - 1) {
      this.currentIndex++;
      this.updateUI();
      this.loadCurrentPhoto();
      this.preloadAdjacentPhotos();
    }
  }
  
  previousPhoto() {
    if (this.currentIndex > 0) {
      this.currentIndex--;
      this.updateUI();
      this.loadCurrentPhoto();
      this.preloadAdjacentPhotos();
    }
  }
  
  // Zoom and pan methods
  zoomIn(centerX, centerY) {
    this.setZoom(this.scale + LIGHTBOX_CONFIG.zoom.step, centerX, centerY);
  }
  
  zoomOut(centerX, centerY) {
    this.setZoom(this.scale - LIGHTBOX_CONFIG.zoom.step, centerX, centerY);
  }
  
  resetZoom() {
    this.scale = 1;
    this.translateX = 0;
    this.translateY = 0;
    this.updateTransform();
  }
  
  setZoom(newScale, centerX, centerY) {
    const oldScale = this.scale;
    this.scale = Math.max(LIGHTBOX_CONFIG.zoom.min, 
                         Math.min(LIGHTBOX_CONFIG.zoom.max, newScale));
    
    // Adjust pan to zoom towards center point
    if (centerX !== undefined && centerY !== undefined) {
      const rect = this.imageWrapper.getBoundingClientRect();
      const offsetX = centerX - rect.left - rect.width / 2;
      const offsetY = centerY - rect.top - rect.height / 2;
      
      const scaleChange = this.scale / oldScale - 1;
      this.translateX -= offsetX * scaleChange;
      this.translateY -= offsetY * scaleChange;
    }
    
    this.constrainPan();
    this.updateTransform();
  }
  
  constrainPan() {
    const rect = this.imageWrapper.getBoundingClientRect();
    const scaledWidth = rect.width * this.scale;
    const scaledHeight = rect.height * this.scale;
    
    const maxX = Math.max(0, (scaledWidth - rect.width) / 2);
    const maxY = Math.max(0, (scaledHeight - rect.height) / 2);
    
    this.translateX = Math.max(-maxX, Math.min(maxX, this.translateX));
    this.translateY = Math.max(-maxY, Math.min(maxY, this.translateY));
  }
  
  updateTransform() {
    const transform = `translate(${this.translateX}px, ${this.translateY}px) scale(${this.scale})`;
    this.imageElement.style.transform = transform;
    
    // Update zoom indicator
    const zoomPercent = Math.round(this.scale * 100);
    this.lightboxElement.querySelector('.zoom-level').textContent = `${zoomPercent}%`;
  }
  
  resetTransform() {
    this.scale = 1;
    this.translateX = 0;
    this.translateY = 0;
    this.updateTransform();
  }
  
  // Gesture handlers
  handlePan(deltaX, deltaY) {
    if (this.scale > 1) {
      this.translateX += deltaX;
      this.translateY += deltaY;
      this.constrainPan();
      this.updateTransform();
    }
  }
  
  handlePinch(scale) {
    this.setZoom(this.scale * scale);
  }
  
  handleZoom(delta, centerX, centerY) {
    const newScale = this.scale + delta;
    this.setZoom(newScale, centerX, centerY);
  }
  
  handleDoubleTap(x, y) {
    if (this.scale === 1) {
      this.setZoom(LIGHTBOX_CONFIG.zoom.doubleTapZoom, x, y);
    } else {
      this.resetZoom();
    }
  }
  
  handleMomentum(velocity) {
    // Apply momentum scrolling for smooth pan experience
    const friction = 0.95;
    let vx = velocity.x * 20;
    let vy = velocity.y * 20;
    
    const animate = () => {
      if (Math.abs(vx) < 0.1 && Math.abs(vy) < 0.1) return;
      
      this.translateX += vx;
      this.translateY += vy;
      this.constrainPan();
      this.updateTransform();
      
      vx *= friction;
      vy *= friction;
      
      this.animationId = requestAnimationFrame(animate);
    };
    
    animate();
  }
  
  // Event handlers
  handleKeydown(e) {
    if (!this.isOpen) return;
    
    switch (e.key) {
      case 'Escape':
        this.close();
        break;
      case 'ArrowLeft':
        this.previousPhoto();
        break;
      case 'ArrowRight':
        this.nextPhoto();
        break;
      case '+':
      case '=':
        this.zoomIn();
        break;
      case '-':
        this.zoomOut();
        break;
      case '0':
        this.resetZoom();
        break;
    }
  }
  
  preventScroll(e) {
    if (this.isOpen && e.target.closest('.photo-lightbox')) {
      e.preventDefault();
    }
  }
  
  // Public API
  destroy() {
    this.close();
    
    if (this.lightboxElement) {
      this.lightboxElement.remove();
    }
    
    document.removeEventListener('keydown', this.handleKeydown);
    document.removeEventListener('touchmove', this.preventScroll);
  }
}

// =============================================================================
// LIGHTBOX INTEGRATION HELPERS
// =============================================================================

/**
 * Creates a lightbox from image elements in the DOM
 */
function createLightboxFromImages(selector, options = {}) {
  const images = document.querySelectorAll(selector);
  const photos = Array.from(images).map((img, index) => ({
    url: img.src,
    title: img.alt || img.title || `Image ${index + 1}`,
    description: img.dataset.description || ''
  }));
  
  images.forEach((img, index) => {
    img.addEventListener('click', (e) => {
      e.preventDefault();
      window.PhotoLightbox.open(photos, index, options);
    });
    
    // Add cursor pointer
    img.style.cursor = 'pointer';
  });
  
  return photos;
}

/**
 * Creates a lightbox from Cloudinary URLs (for Form-a-Friend responses)
 */
function createLightboxFromResponses(responses, options = {}) {
  const photos = [];
  
  responses.forEach(response => {
    if (response.answer && typeof response.answer === 'string') {
      // Check if answer is an image URL
      if (response.answer.includes('res.cloudinary.com') || 
          /\.(jpg|jpeg|png|gif|webp)(\?|$)/i.test(response.answer)) {
        
        photos.push({
          url: response.answer,
          title: response.question || 'Réponse photo',
          description: response.description || ''
        });
      }
    }
  });
  
  return photos;
}

// =============================================================================
// GLOBAL INITIALIZATION
// =============================================================================

// Create global lightbox instance
window.PhotoLightbox = new PhotoLightbox();

// Export helper functions
window.PhotoLightbox.createFromImages = createLightboxFromImages;
window.PhotoLightbox.createFromResponses = createLightboxFromResponses;

// Auto-initialize lightbox for images with data-lightbox attribute
document.addEventListener('DOMContentLoaded', () => {
  const lightboxImages = document.querySelectorAll('[data-lightbox]');
  if (lightboxImages.length > 0) {
    createLightboxFromImages('[data-lightbox]');
  }
});

// Export for ES6 modules (commented out for browser compatibility)
// export { PhotoLightbox, createLightboxFromImages, createLightboxFromResponses };

// Browser-compatible exports via global object
window.PhotoLightbox = PhotoLightbox;
window.createLightboxFromImages = createLightboxFromImages;
window.createLightboxFromResponses = createLightboxFromResponses;