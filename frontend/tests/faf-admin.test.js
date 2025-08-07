/**
 * Tests for faf-admin.js ES6 module
 * Basic module structure and export validation
 */

const fs = require('fs');
const path = require('path');

describe('🔧 FAF Admin Module Tests', () => {
  let moduleContent;
  
  beforeAll(() => {
    const modulePath = path.join(__dirname, '../admin/faf-admin.js');
    moduleContent = fs.readFileSync(modulePath, 'utf8');
  });

  describe('Module Structure', () => {
    test('should export all required namespaces', () => {
      expect(moduleContent).toContain('export class AdminAPI');
      expect(moduleContent).toContain('export const Utils');
      expect(moduleContent).toContain('export const UI');
      expect(moduleContent).toContain('export const Charts');
      expect(moduleContent).toContain('export const SAFE_HTML_ENTITIES');
    });

    test('should contain critical security constants', () => {
      expect(moduleContent).toContain('SAFE_HTML_ENTITIES');
      expect(moduleContent).toContain('TRUSTED_IMAGE_DOMAINS');
      expect(moduleContent).toContain('res.cloudinary.com');
    });

    test('should have proper AdminAPI methods', () => {
      expect(moduleContent).toContain('static async fetchCSRFToken()');
      expect(moduleContent).toContain('static async request(');
      expect(moduleContent).toContain('static async init()');
    });

    test('should have Utils methods', () => {
      expect(moduleContent).toContain('unescapeHTML(text)');
      expect(moduleContent).toContain('escapeHTML(text)');
      expect(moduleContent).toContain('formatDate(date)');
      expect(moduleContent).toContain('isTrustedImageUrl(url)');
    });

    test('should have UI methods', () => {
      expect(moduleContent).toContain('showAlert(message, type');
      expect(moduleContent).toContain('createLightbox(');
    });

    test('should have Charts methods', () => {
      expect(moduleContent).toContain('createPieChart(items, config');
      expect(moduleContent).toContain('createAnswersList(items, config');
    });
  });

  describe('Security Features', () => {
    test('should maintain XSS protection patterns', () => {
      expect(moduleContent).toContain('textContent');
      expect(moduleContent).toContain('createElement');
      // innerHTML ne doit apparaître que dans les commentaires, pas dans le code actif
      const codeWithoutComments = moduleContent.replace(/\/\/.*$/gm, '').replace(/\/\*[\s\S]*?\*\//g, '');
      expect(codeWithoutComments).not.toContain('innerHTML');
    });

    test('should have HTTPS-only image validation', () => {
      expect(moduleContent).toContain('urlObj.protocol !== \'https:\'');
    });

    test('should include all French accented characters in SAFE_HTML_ENTITIES', () => {
      const frenchChars = ['&eacute;', '&egrave;', '&ecirc;', '&agrave;', '&acirc;', '&ugrave;', '&ucirc;', '&icirc;', '&ocirc;', '&ccedil;'];
      frenchChars.forEach(char => {
        expect(moduleContent).toContain(char);
      });
    });

    test('should decode Cloudinary URLs with escaped slashes', () => {
      // Vérifier que &#x2F; est dans SAFE_HTML_ENTITIES pour décoder les URLs Cloudinary
      expect(moduleContent).toContain("'&#x2F;': '/'");
      
      // Simuler le décodage d'une URL Cloudinary échappée
      const SAFE_HTML_ENTITIES = {
        '&#x2F;': '/',
        '&#39;': "'",
        '&quot;': '"',
        '&amp;': '&',
        '&lt;': '<',
        '&gt;': '>'
      };
      
      function unescapeHTML(text) {
        if (!text || typeof text !== 'string') return text || '';
        let result = text;
        for (let entity in SAFE_HTML_ENTITIES) {
          if (SAFE_HTML_ENTITIES.hasOwnProperty(entity)) {
            const char = SAFE_HTML_ENTITIES[entity];
            const escapedEntity = entity.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
            result = result.replace(new RegExp(escapedEntity, 'g'), char);
          }
        }
        return result;
      }
      
      const input = 'https:&#x2F;&#x2F;res.cloudinary.com&#x2F;project&#x2F;image&#x2F;upload&#x2F;v123&#x2F;sample.jpg';
      const expected = 'https://res.cloudinary.com/project/image/upload/v123/sample.jpg';
      expect(unescapeHTML(input)).toBe(expected);
    });
  });

  describe('Backward Compatibility', () => {
    test('should provide global window exports for compatibility', () => {
      expect(moduleContent).toContain('window.AdminAPI = AdminAPI');
      expect(moduleContent).toContain('window.Utils = Utils');
      expect(moduleContent).toContain('window.UI = UI');
      expect(moduleContent).toContain('window.Charts = Charts');
      expect(moduleContent).toContain('window.unescapeHTML = Utils.unescapeHTML');
      expect(moduleContent).toContain('window.showAlert = UI.showAlert');
    });

    test('should auto-initialize on DOMContentLoaded', () => {
      expect(moduleContent).toContain('document.addEventListener(\'DOMContentLoaded\'');
      expect(moduleContent).toContain('AdminAPI.init()');
    });
  });
});