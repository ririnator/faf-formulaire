const { describe, test, expect } = require('@jest/globals');
const { isCloudinaryUrl, smartEscape, escapeQuestion } = require('../middleware/validation');

describe('smartEscape() Security Tests', () => {
  
  describe('Valid Cloudinary URLs', () => {
    test('should NOT escape valid Cloudinary URL', () => {
      const url = 'https://res.cloudinary.com/demo/image/upload/v1234/sample.jpg';
      expect(smartEscape(url)).toBe(url);
    });
    
    test('should NOT escape Cloudinary URL with complex path', () => {
      const url = 'https://res.cloudinary.com/doyupygie/image/upload/v1754587188/faf-images/image.png';
      expect(smartEscape(url)).toBe(url);
    });
    
    test('should NOT escape Cloudinary URL with special characters in filename', () => {
      const url = 'https://res.cloudinary.com/demo/image/upload/v123/image_2025-01-08.png';
      expect(smartEscape(url)).toBe(url);
    });
  });
  
  describe('Malicious Cloudinary URLs', () => {
    test('should escape Cloudinary URL with script tag', () => {
      const malicious = 'https://res.cloudinary.com/test/image/upload/<script>alert("XSS")</script>';
      const escaped = smartEscape(malicious);
      expect(escaped).toContain('&lt;script&gt;');
      expect(escaped).not.toContain('<script>');
    });
    
    test('should escape Cloudinary URL with single quote', () => {
      const malicious = "https://res.cloudinary.com/test/image/upload/file'onclick='alert(1)'.png";
      const escaped = smartEscape(malicious);
      expect(escaped).toMatch(/(&#39;|&#x27;)/); // Accept both decimal and hex
      expect(escaped).not.toBe(malicious);
      // Vérifier que isCloudinaryUrl rejette aussi cette URL
      expect(isCloudinaryUrl(malicious)).toBe(false);
    });
    
    test('should reject Cloudinary URL with single quote in filename', () => {
      const urlWithQuote = "https://res.cloudinary.com/demo/image/upload/capture_d'ecran.png";
      expect(isCloudinaryUrl(urlWithQuote)).toBe(false);
      const escaped = smartEscape(urlWithQuote);
      expect(escaped).toMatch(/(&#39;|&#x27;)/); // Accept both decimal and hex
      expect(escaped).not.toBe(urlWithQuote);
    });
    
    test('should escape Cloudinary URL with double quote', () => {
      const malicious = 'https://res.cloudinary.com/test/image/upload/file"onerror="alert(1)".png';
      const escaped = smartEscape(malicious);
      expect(escaped).toContain('&quot;');
      expect(escaped).not.toBe(malicious);
    });
    
    test('should escape Cloudinary URL with javascript: protocol', () => {
      const malicious = 'https://res.cloudinary.com/test/image/upload/javascript:alert(1)';
      const escaped = smartEscape(malicious);
      expect(escaped).not.toBe(malicious);
    });
  });
  
  describe('Non-Cloudinary URLs', () => {
    test('should escape non-Cloudinary image URL', () => {
      const url = 'https://example.com/image.jpg';
      const escaped = smartEscape(url);
      expect(escaped).toContain('https:&#x2F;&#x2F;');
      expect(escaped).not.toBe(url);
    });
    
    test('should escape HTTP Cloudinary URL (not HTTPS)', () => {
      const url = 'http://res.cloudinary.com/demo/image/upload/sample.jpg';
      const escaped = smartEscape(url);
      expect(escaped).toContain('http:&#x2F;&#x2F;');
      expect(escaped).not.toBe(url);
    });
    
    test('should escape fake Cloudinary domain', () => {
      const url = 'https://res-cloudinary.com/demo/image/upload/sample.jpg';
      const escaped = smartEscape(url);
      expect(escaped).toContain('&#x2F;');
      expect(escaped).not.toBe(url);
    });
  });
  
  describe('XSS Attack Vectors', () => {
    test('should escape script tag', () => {
      const xss = '<script>alert("XSS")</script>';
      const escaped = smartEscape(xss);
      expect(escaped).toBe('&lt;script&gt;alert&#x28;&quot;XSS&quot;&#x29;&lt;&#x2F;script&gt;');
    });
    
    test('should escape img tag with onerror', () => {
      const xss = '<img src=x onerror=alert("XSS")>';
      const escaped = smartEscape(xss);
      expect(escaped).toContain('&lt;img');
      expect(escaped).toContain('&quot;');
      expect(escaped).not.toContain('<img');
    });
    
    test('should escape onclick attribute', () => {
      const xss = '"><div onclick="alert(1)">click</div>';
      const escaped = smartEscape(xss);
      expect(escaped).toContain('&quot;');
      expect(escaped).toContain('&lt;div');
      expect(escaped).toContain('&gt;');
    });
    
    test('should escape javascript: URL', () => {
      const xss = 'javascript:alert(document.cookie)';
      const escaped = smartEscape(xss);
      // javascript: protocol should have parentheses escaped for security
      expect(escaped).toBe('javascript:alert&#x28;document.cookie&#x29;');
    });
    
    test('should escape data: URL with base64 script', () => {
      const xss = 'data:text/html,<script>alert(1)</script>';
      const escaped = smartEscape(xss);
      expect(escaped).toContain('&lt;script&gt;');
      expect(escaped).toContain('&#x2F;');
    });
  });
  
  describe('Normal Text', () => {
    test('should escape apostrophes in normal text', () => {
      const text = "C'est l'été";
      const escaped = smartEscape(text);
      expect(escaped).toBe("C&#x27;est l&#x27;été"); // Use hex format like the code
    });
    
    test('should escape quotes in normal text', () => {
      const text = 'He said "Hello"';
      const escaped = smartEscape(text);
      expect(escaped).toBe('He said &quot;Hello&quot;');
    });
    
    test('should escape HTML entities', () => {
      const text = '5 < 10 && 10 > 5';
      const escaped = smartEscape(text);
      expect(escaped).toBe('5 &lt; 10 &amp;&amp; 10 &gt; 5');
    });
    
    test('should escape slashes in paths', () => {
      const text = '/path/to/file';
      const escaped = smartEscape(text);
      expect(escaped).toBe('&#x2F;path&#x2F;to&#x2F;file');
    });
  });
  
  describe('Edge Cases', () => {
    test('should handle null input', () => {
      expect(smartEscape(null)).toBe(null);
    });
    
    test('should handle undefined input', () => {
      expect(smartEscape(undefined)).toBe(undefined);
    });
    
    test('should handle empty string', () => {
      expect(smartEscape('')).toBe('');
    });
    
    test('should handle number input', () => {
      expect(smartEscape(123)).toBe(123);
    });
    
    test('should handle very long Cloudinary URL', () => {
      const longPath = 'a'.repeat(1000);
      const url = `https://res.cloudinary.com/demo/image/upload/${longPath}.jpg`;
      expect(smartEscape(url)).toBe(url);
    });
  });
  
  describe('Security Boundary Testing', () => {
    test('should escape Cloudinary URL with mixed attack vectors', () => {
      const attack = 'https://res.cloudinary.com/test/image/upload/<img src=x onerror=alert(1)>';
      const escaped = smartEscape(attack);
      expect(escaped).toContain('&lt;img');
      expect(escaped).not.toContain('<img');
    });
    
    test('should escape truly invalid Cloudinary-like URL', () => {
      const url = 'https://res.cloudinary.com/demo/invalid/upload/sample.mp4';
      const escaped = smartEscape(url);
      expect(escaped).toContain('&#x2F;');
      expect(escaped).not.toBe(url);
    });
    
    test('should handle Cloudinary URL with query parameters', () => {
      const url = 'https://res.cloudinary.com/demo/image/upload/w_200,h_200/sample.jpg?v=123';
      expect(smartEscape(url)).toBe(url);
    });
    
    test('should handle Cloudinary URL with transformation parameters', () => {
      const url = 'https://res.cloudinary.com/demo/image/upload/c_scale,w_500/sample.jpg';
      expect(smartEscape(url)).toBe(url);
    });
  });
});

describe('isCloudinaryUrl() Validation Tests', () => {
  
  describe('Valid URLs', () => {
    test('should accept standard Cloudinary URL', () => {
      expect(isCloudinaryUrl('https://res.cloudinary.com/demo/image/upload/sample.jpg')).toBe(true);
    });
    
    test('should accept Cloudinary URL with version', () => {
      expect(isCloudinaryUrl('https://res.cloudinary.com/demo/image/upload/v1234567890/sample.jpg')).toBe(true);
    });
    
    test('should accept Cloudinary URL with transformations', () => {
      expect(isCloudinaryUrl('https://res.cloudinary.com/demo/image/upload/w_200,h_200,c_fill/sample.jpg')).toBe(true);
    });
  });
  
  describe('Invalid URLs', () => {
    test('should reject non-HTTPS URL', () => {
      expect(isCloudinaryUrl('http://res.cloudinary.com/demo/image/upload/sample.jpg')).toBe(false);
    });
    
    test('should reject non-Cloudinary domain', () => {
      expect(isCloudinaryUrl('https://example.com/image/upload/sample.jpg')).toBe(false);
    });
    
    test('should reject URL without /image/upload/', () => {
      expect(isCloudinaryUrl('https://res.cloudinary.com/demo/sample.jpg')).toBe(false);
    });
    
    test('should reject URL with script tag', () => {
      expect(isCloudinaryUrl('https://res.cloudinary.com/demo/image/upload/<script>alert(1)</script>')).toBe(false);
    });
    
    test('should reject URL with single quote', () => {
      expect(isCloudinaryUrl("https://res.cloudinary.com/demo/image/upload/file'.jpg")).toBe(false);
    });
    
    test('should reject URL with double quote', () => {
      expect(isCloudinaryUrl('https://res.cloudinary.com/demo/image/upload/file".jpg')).toBe(false);
    });
    
    test('should reject URL with javascript:', () => {
      expect(isCloudinaryUrl('https://res.cloudinary.com/demo/image/upload/javascript:alert(1)')).toBe(false);
    });
    
    test('should reject URL with onclick', () => {
      expect(isCloudinaryUrl('https://res.cloudinary.com/demo/image/upload/file.jpg?onclick=alert(1)')).toBe(false);
    });
    
    test('should accept URL with script keyword in filename', () => {
      expect(isCloudinaryUrl('https://res.cloudinary.com/demo/image/upload/myscript.jpg')).toBe(true);
    });
  });
  
  describe('Edge Cases', () => {
    test('should reject null', () => {
      expect(isCloudinaryUrl(null)).toBe(false);
    });
    
    test('should reject undefined', () => {
      expect(isCloudinaryUrl(undefined)).toBe(false);
    });
    
    test('should reject empty string', () => {
      expect(isCloudinaryUrl('')).toBe(false);
    });
    
    test('should reject number', () => {
      expect(isCloudinaryUrl(123)).toBe(false);
    });
    
    test('should reject object', () => {
      expect(isCloudinaryUrl({})).toBe(false);
    });
  });
});

describe('escapeQuestion() Tests', () => {
  
  describe('French Text Preservation', () => {
    test('should preserve apostrophes in French questions', () => {
      const question = "C'est quoi ta reaction pic préférée ?";
      expect(escapeQuestion(question)).toBe(question);
    });
    
    test('should preserve contractions', () => {
      const question = "Qu'est-ce que tu penses de l'été ?";
      expect(escapeQuestion(question)).toBe(question);
    });
    
    test('should preserve slashes in text', () => {
      const question = "Ton ratio travail/loisir ce mois ?";
      expect(escapeQuestion(question)).toBe(question);
    });
  });
  
  describe('Security Protection', () => {
    test('should escape HTML tags', () => {
      const malicious = 'Question avec <script>alert("XSS")</script>';
      const escaped = escapeQuestion(malicious);
      expect(escaped).toContain('&lt;script&gt;');
      expect(escaped).not.toContain('<script>');
    });
    
    test('should escape double quotes', () => {
      const question = 'Question avec "guillemets" dangereuses';
      const escaped = escapeQuestion(question);
      expect(escaped).toContain('&quot;');
      expect(escaped).not.toContain('"');
    });
    
    test('should escape ampersands', () => {
      const question = 'Question avec & commercial';
      const escaped = escapeQuestion(question);
      expect(escaped).toBe('Question avec &amp; commercial');
    });
    
    test('should NOT escape single quotes', () => {
      const question = "C'est important de garder les apostrophes";
      const escaped = escapeQuestion(question);
      expect(escaped).toBe(question);
      expect(escaped).not.toContain('&#39;');
    });
    
    test('should NOT escape slashes', () => {
      const question = "Ratio travail/loisir";
      const escaped = escapeQuestion(question);
      expect(escaped).toBe(question);
      expect(escaped).not.toContain('&#x2F;');
    });
  });
  
  describe('Edge Cases', () => {
    test('should handle null input', () => {
      expect(escapeQuestion(null)).toBe(null);
    });
    
    test('should handle undefined input', () => {
      expect(escapeQuestion(undefined)).toBe(undefined);
    });
    
    test('should handle empty string', () => {
      expect(escapeQuestion('')).toBe('');
    });
    
    test('should handle number input', () => {
      expect(escapeQuestion(123)).toBe(123);
    });
  });
  
  describe('Real-world French Questions', () => {
    test('should handle typical FAF questions', () => {
      const questions = [
        "C'est quoi la reaction pic que tu utilises le plus en ce moment ?",
        "Possibilité d'ajouter un peu plus de détails à la question précédente :",
        "Qu'est-ce qui t'a le plus marqué ce mois ?",
        "Balance ton ratio travail/loisir du mois",
        "Photo de toi ce mois (selfie/miroir/quelqu'un d'autre)"
      ];
      
      questions.forEach(question => {
        const escaped = escapeQuestion(question);
        expect(escaped).toBe(question); // Aucune modification
        expect(escaped).not.toContain('&#39;'); // Pas d'encodage d'apostrophe
        expect(escaped).not.toContain('&#x2F;'); // Pas d'encodage de slash
      });
    });
    
    test('should escape malicious French questions', () => {
      const malicious = 'Question avec <img src="x" onerror="alert(\'XSS\')">';
      const escaped = escapeQuestion(malicious);
      expect(escaped).toContain('&lt;img');
      expect(escaped).toContain('&quot;');
      expect(escaped).not.toContain('<img');
      // Mais les apostrophes dans alert restent
      expect(escaped).toContain("alert('XSS')");
    });
  });
});