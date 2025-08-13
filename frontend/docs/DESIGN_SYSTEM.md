# FAF Design System Documentation

## Color Palette (Gray Theme)

### Primary Colors
- **Primary Gradient**: `linear-gradient(135deg, #6b7280 0%, #374151 100%)`
  - Start: `#6b7280` (gray-500)
  - End: `#374151` (gray-700)
- **Primary Color**: `#6b7280` (gray-500)
- **Primary Dark**: `#4b5563` (gray-600)

### Gray Scale
- **Gray 50**: `#f7fafc` - Lightest backgrounds
- **Gray 100**: `#edf2f7` - Light backgrounds
- **Gray 200**: `#e2e8f0` - Borders, dividers
- **Gray 300**: `#cbd5e0` - Disabled states
- **Gray 400**: `#a0aec0` - Placeholder text
- **Gray 500**: `#718096` - Body text
- **Gray 600**: `#4a5568` - Headings
- **Gray 700**: `#2d3748` - Dark text
- **Gray 800**: `#1a202c` - Darkest text
- **Gray 900**: `#171923` - Black alternative

### Functional Colors
- **Success**: `#48bb78` (green-400)
- **Success Dark**: `#38a169` (green-500)
- **Danger**: `#f56565` (red-400)
- **Danger Dark**: `#e53e3e` (red-500)
- **Warning**: `#ed8936` (orange-400)
- **Warning Dark**: `#dd6b20` (orange-500)

### Shadows & Effects
- **Focus Ring**: `0 0 0 3px rgba(107, 114, 128, 0.1)`
- **Button Hover Shadow**: `0 10px 25px rgba(107, 114, 128, 0.3)`
- **Card Hover Shadow**: `0 5px 15px rgba(107, 114, 128, 0.4)`

## Typography
- **Font Family**: `'Segoe UI', Tahoma, Geneva, Verdana, sans-serif`
- **Base Font Size**: `16px`
- **Line Height**: `1.5`

## Spacing Scale
- `--spacing-1`: `0.25rem` (4px)
- `--spacing-2`: `0.5rem` (8px)
- `--spacing-3`: `0.75rem` (12px)
- `--spacing-4`: `1rem` (16px)
- `--spacing-5`: `1.25rem` (20px)
- `--spacing-6`: `1.5rem` (24px)
- `--spacing-8`: `2rem` (32px)
- `--spacing-10`: `2.5rem` (40px)
- `--spacing-12`: `3rem` (48px)

## Border Radius
- `--border-radius-sm`: `0.25rem` (4px)
- `--border-radius-md`: `0.375rem` (6px)
- `--border-radius-lg`: `0.5rem` (8px)
- `--border-radius-xl`: `1rem` (16px)
- `--border-radius-full`: `9999px`

## Transitions
- `--transition-base`: `all 0.3s ease`
- `--transition-fast`: `all 0.15s ease`
- `--transition-slow`: `all 0.5s ease`

## Usage Guidelines

### Backgrounds
- Main background: `white`
- Secondary background: `--gray-50`
- Tertiary background: `--gray-100`

### Text Colors
- Primary text: `--gray-700`
- Secondary text: `--gray-600`
- Muted text: `--gray-500`
- Placeholder: `--gray-400`

### Interactive Elements
- Default state: `--primary-color`
- Hover state: `--primary-dark`
- Focus state: Add focus ring
- Disabled state: `--gray-300`

## Migration Notes

### From Purple to Gray (January 2025)
- Old primary: `#667eea` → New: `#6b7280`
- Old gradient: `#667eea to #764ba2` → New: `#6b7280 to #374151`
- Old hover: `#5a67d8` → New: `#4b5563`
- Old shadow rgba: `rgba(102, 126, 234, ...)` → New: `rgba(107, 114, 128, ...)`

### Future SCSS Migration
Consider using `_variables.scss` for easier theme management with:
- Mixins for gradients
- Functions for color variations
- Maps for color palettes
- @use for modular imports