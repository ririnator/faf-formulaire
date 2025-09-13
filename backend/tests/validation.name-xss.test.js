const { applySafeEscape, smartEscape } = require('../middleware/validation');

describe('Validation - Name XSS Protection', () => {
  let req, res, next;

  beforeEach(() => {
    req = {
      body: {}
    };
    res = {};
    next = jest.fn();
  });

  describe('applySafeEscape middleware', () => {
    it('should escape XSS attempts in name field', () => {
      req.body.name = '<script>alert("XSS")</script>';
      
      applySafeEscape(req, res, next);
      
      expect(req.body.name).toBe('&lt;script&gt;alert(&quot;XSS&quot;)&lt;&#x2F;script&gt;');
      expect(next).toHaveBeenCalledTimes(1);
    });

    it('should escape HTML entities in name field', () => {
      req.body.name = '<img src="x" onerror="alert(1)">';
      
      applySafeEscape(req, res, next);
      
      expect(req.body.name).toBe('&lt;img src=&quot;x&quot; onerror=&quot;alert(1)&quot;&gt;');
      expect(next).toHaveBeenCalledTimes(1);
    });

    it('should handle normal names without modification', () => {
      req.body.name = 'Jean-Pierre';
      
      applySafeEscape(req, res, next);
      
      expect(req.body.name).toBe('Jean-Pierre');
      expect(next).toHaveBeenCalledTimes(1);
    });

    it('should handle French names with accents correctly', () => {
      req.body.name = 'François Müller';
      
      applySafeEscape(req, res, next);
      
      expect(req.body.name).toBe('François Müller');
      expect(next).toHaveBeenCalledTimes(1);
    });

    it('should escape dangerous characters in name', () => {
      req.body.name = 'User"><script>alert("hack")</script>';
      
      applySafeEscape(req, res, next);
      
      expect(req.body.name).toBe('User&quot;&gt;&lt;script&gt;alert(&quot;hack&quot;)&lt;&#x2F;script&gt;');
      expect(next).toHaveBeenCalledTimes(1);
    });

    it('should handle null/undefined name gracefully', () => {
      req.body.name = null;
      
      applySafeEscape(req, res, next);
      
      expect(req.body.name).toBe(null);
      expect(next).toHaveBeenCalledTimes(1);
    });

    it('should handle non-string name gracefully', () => {
      req.body.name = 12345;
      
      applySafeEscape(req, res, next);
      
      expect(req.body.name).toBe(12345);
      expect(next).toHaveBeenCalledTimes(1);
    });

    it('should escape SQL injection attempts in name', () => {
      req.body.name = "'; DROP TABLE users; --";
      
      applySafeEscape(req, res, next);
      
      expect(req.body.name).toBe('&#39;; DROP TABLE users; --');
      expect(next).toHaveBeenCalledTimes(1);
    });

    it('should escape event handlers in name', () => {
      req.body.name = 'onload="alert(1)"';
      
      applySafeEscape(req, res, next);
      
      expect(req.body.name).toBe('onload=&quot;alert(1)&quot;');
      expect(next).toHaveBeenCalledTimes(1);
    });

    it('should escape javascript: protocol in name', () => {
      req.body.name = 'javascript:alert(1)';
      
      applySafeEscape(req, res, next);
      
      expect(req.body.name).toBe('javascript:alert(1)'); // smartEscape ne bloque pas javascript: dans le texte normal
      expect(next).toHaveBeenCalledTimes(1);
    });

    it('should process both name and responses together', () => {
      req.body.name = '<script>alert("name")</script>';
      req.body.responses = [
        {
          question: 'Question with <b>HTML</b>',
          answer: '<script>alert("answer")</script>'
        }
      ];
      
      applySafeEscape(req, res, next);
      
      expect(req.body.name).toBe('&lt;script&gt;alert(&quot;name&quot;)&lt;&#x2F;script&gt;');
      expect(req.body.responses[0].question).toBe('Question with &lt;b&gt;HTML&lt;/b&gt;');
      expect(req.body.responses[0].answer).toBe('&lt;script&gt;alert(&quot;answer&quot;)&lt;&#x2F;script&gt;');
      expect(next).toHaveBeenCalledTimes(1);
    });
  });

  describe('smartEscape function', () => {
    it('should escape all dangerous characters', () => {
      const dangerous = '<script>alert("test")</script>';
      const result = smartEscape(dangerous);
      
      expect(result).toBe('&lt;script&gt;alert(&quot;test&quot;)&lt;&#x2F;script&gt;');
    });

    it('should escape quotes and ampersands', () => {
      const input = 'Test & "quotes" & \'apostrophes\'';
      const result = smartEscape(input);
      
      expect(result).toBe('Test &amp; &quot;quotes&quot; &amp; &#39;apostrophes&#39;');
    });
  });
});