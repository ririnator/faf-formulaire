module.exports = {
  env: {
    node: true,
    es2021: true,
    jest: true
  },
  extends: [
    'eslint:recommended'
  ],
  parserOptions: {
    ecmaVersion: 2021,
    sourceType: 'module'
  },
  rules: {
    // Détecter les variables inutilisées
    'no-unused-vars': ['error', { 
      vars: 'all', 
      args: 'after-used',
      ignoreRestSiblings: false 
    }],
    
    // Détecter les imports inutilisés
    'no-unused-expressions': 'error',
    
    // Variables définies mais jamais lues
    'no-undef': 'error'
  },
  
  // Ignorer certains patterns
  ignorePatterns: [
    'node_modules/',
    'coverage/',
    '*.test.js'
  ]
};