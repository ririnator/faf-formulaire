#!/usr/bin/env node

/**
 * Script pour lancer les tests frontend avec une configuration appropriée
 * Usage: node run-frontend-tests.js [--watch] [--coverage]
 */

const { spawn } = require('child_process');
const path = require('path');

const args = process.argv.slice(2);
const isWatch = args.includes('--watch');
const isCoverage = args.includes('--coverage');

// Commande Jest avec configuration frontend
const jestArgs = [
  '--config', 'frontend/tests/jest.config.js',
  '--rootDir', '.'
];

if (isWatch) {
  jestArgs.push('--watch');
}

if (isCoverage) {
  jestArgs.push('--coverage');
}

// Ajouter verbose par défaut
jestArgs.push('--verbose');

console.log('🧪 Lancement des tests frontend...\n');
console.log(`Commande: npx jest ${jestArgs.join(' ')}\n`);

// Lancer Jest
const jest = spawn('npx', ['jest', ...jestArgs], {
  stdio: 'inherit',
  cwd: process.cwd()
});

jest.on('error', (error) => {
  console.error('❌ Erreur lors du lancement des tests:', error);
  process.exit(1);
});

jest.on('close', (code) => {
  if (code === 0) {
    console.log('\n✅ Tests frontend terminés avec succès !');
  } else {
    console.log('\n❌ Tests frontend échoués.');
    process.exit(code);
  }
});