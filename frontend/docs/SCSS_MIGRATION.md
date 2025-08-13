# SCSS Migration Guide

## Overview
This guide explains how to migrate the FAF project from CSS to SCSS for better maintainability and theme management.

## Current Structure
```
frontend/public/css/
├── faf-base.css         # Base styles with CSS variables
├── form.css             # Form-specific styles
├── variables.css        # Consolidated CSS variables
└── styles/
    └── modern-theme.css # Theme-specific styles
```

## Proposed SCSS Structure
```
frontend/public/scss/
├── _variables.scss      # All variables and maps
├── _mixins.scss         # Reusable mixins
├── _functions.scss      # Utility functions
├── _base.scss           # Base styles
├── _components.scss     # Component styles
├── _layout.scss         # Layout utilities
├── _themes.scss         # Theme variations
└── main.scss           # Main import file
```

## Migration Benefits

### 1. Better Theme Management
```scss
// Easy theme switching with maps
$themes: (
  gray: (
    primary: #6b7280,
    gradient: linear-gradient(135deg, #6b7280, #374151)
  ),
  blue: (
    primary: #3b82f6,
    gradient: linear-gradient(135deg, #3b82f6, #1e40af)
  )
);

@mixin theme($name) {
  $theme: map-get($themes, $name);
  @each $key, $value in $theme {
    --#{$key}: #{$value};
  }
}
```

### 2. Component Mixins
```scss
@mixin button-base {
  padding: spacing(3) spacing(6);
  border-radius: $border-radius-lg;
  font-weight: $font-weight-semibold;
  transition: $transition-base;
}

@mixin button-primary {
  @include button-base;
  @include button-variant($primary-color);
}
```

### 3. Responsive Utilities
```scss
.container {
  @include respond-to(sm) { max-width: 640px; }
  @include respond-to(md) { max-width: 768px; }
  @include respond-to(lg) { max-width: 1024px; }
}
```

## Migration Steps

### Step 1: Install SCSS Compiler
```bash
npm install -D sass
```

### Step 2: Update Build Process
```json
{
  "scripts": {
    "build:css": "sass frontend/public/scss/main.scss frontend/public/css/compiled.css --watch"
  }
}
```

### Step 3: Create Main SCSS File
```scss
// main.scss
@use 'variables' as *;
@use 'mixins' as *;
@use 'functions' as *;

@use 'base';
@use 'components';
@use 'layout';
@use 'themes';
```

### Step 4: Migrate Existing CSS
1. Move variables to `_variables.scss`
2. Convert repeated patterns to mixins
3. Organize styles by component
4. Add theme variations

## Theme Switching Implementation

### CSS Custom Properties with SCSS
```scss
// Generate CSS custom properties
:root {
  @include theme-properties('gray');
}

[data-theme="blue"] {
  @include theme-properties('blue');
}
```

### JavaScript Theme Switcher
```javascript
function switchTheme(themeName) {
  document.documentElement.setAttribute('data-theme', themeName);
  localStorage.setItem('theme', themeName);
}
```

## Maintenance Benefits

### Before (CSS)
```css
/* Repeated code across files */
.button-primary {
  background: #6b7280;
  padding: 12px 24px;
  border-radius: 8px;
  /* ... */
}

.button-secondary {
  background: #f7fafc;
  padding: 12px 24px;
  border-radius: 8px;
  /* ... */
}
```

### After (SCSS)
```scss
.button-primary {
  @include button-variant($primary-color);
}

.button-secondary {
  @include button-variant($gray-50, $gray-700);
}
```

## Recommended Tools

1. **VS Code Extensions**:
   - Sass (.sass only)
   - SCSS IntelliSense

2. **Build Tools**:
   - Sass CLI
   - PostCSS (for autoprefixer)
   - PurgeCSS (for unused CSS removal)

3. **Linting**:
   - stylelint-scss
   - prettier for formatting

## Compatibility Notes

- All current CSS will remain functional
- SCSS compiles to standard CSS
- CSS custom properties still work with SCSS
- Progressive migration possible (file by file)

## Future Enhancements

1. **Design Tokens**: Convert to JSON for cross-platform use
2. **Component Library**: Create reusable component mixins
3. **Automated Testing**: CSS regression testing
4. **Documentation**: Automatic style guide generation