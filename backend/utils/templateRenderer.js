// Simple template renderer for nonce injection
const fs = require('fs');
const path = require('path');

class TemplateRenderer {
  static renderHTML(filePath, variables = {}) {
    try {
      const htmlContent = fs.readFileSync(filePath, 'utf8');
      
      // Replace template variables
      let rendered = htmlContent;
      for (const [key, value] of Object.entries(variables)) {
        const regex = new RegExp(`{{${key}}}`, 'g');
        rendered = rendered.replace(regex, value);
      }
      
      return rendered;
    } catch (error) {
      console.error('Template rendering error:', error.message);
      throw new Error('Template not found');
    }
  }

  static async renderWithNonce(filePath, res) {
    const nonce = res.locals.nonce || '';
    const variables = { nonce };
    
    try {
      const rendered = this.renderHTML(filePath, variables);
      return rendered;
    } catch (error) {
      throw error;
    }
  }
}

module.exports = TemplateRenderer;