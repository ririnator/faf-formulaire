/**
 * Setup file for frontend tests
 * Configure jsdom environment for DOM testing
 */

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