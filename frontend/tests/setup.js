/**
 * Setup file for frontend tests
 * Configure jsdom environment for DOM testing
 */

// Polyfill TextEncoder/TextDecoder for JSDOM compatibility
const { TextEncoder, TextDecoder } = require('util');
global.TextEncoder = TextEncoder;
global.TextDecoder = TextDecoder;

// Mock console.error pour les tests plus propres
const originalError = console.error;
beforeAll(() => {
  console.error = (...args) => {
    if (
      typeof args[0] === 'string' &&
      args[0].includes('Warning: ReactDOM.render is deprecated')
    ) {
      return;
    }
    // Filter out intentional test errors for form submission and integration tests
    if (args[0] && args[0].message && (
      args[0].message.includes('Failed to fetch') ||
      args[0].message.includes('Upload failed: Network error') ||
      args[0].message.includes('Le nom doit contenir') ||
      args[0].message.includes('HTMLCanvasElement.prototype.getContext')
    )) {
      return;
    }
    originalError.call(console, ...args);
  };
});

afterAll(() => {
  console.error = originalError;
});

// Mock fetch pour les tests
global.fetch = jest.fn();

// Mock toLocaleString pour assurer la cohérence des tests
const originalToLocaleString = Date.prototype.toLocaleString;

beforeEach(() => {
  fetch.mockClear();
  
  // Reset toLocaleString mock
  Date.prototype.toLocaleString = originalToLocaleString;
});

// Helper pour mocker des dates spécifiques dans les tests
global.mockDate = (dateString) => {
  const mockDate = new Date(dateString);
  jest.spyOn(global, 'Date').mockImplementation(() => mockDate);
};

global.restoreDate = () => {
  global.Date.mockRestore();
};