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

// Filtrer les arguments non-flags pour les passer à Jest
const testFiles = args.filter(arg => !arg.startsWith('--'));

// Commande Jest avec configuration frontend
const jestArgs = [
  '--config', path.join(__dirname, 'frontend/tests/jest.config.js'),
  '--rootDir', __dirname
];

if (isWatch) {
  jestArgs.push('--watch');
}

if (isCoverage) {
  jestArgs.push('--coverage');
}

// Ajouter verbose par défaut
jestArgs.push('--verbose');

// Ajouter les fichiers de test spécifiques si fournis
if (testFiles.length > 0) {
  jestArgs.push(...testFiles.map(f => `frontend/tests/${f}`));
}

console.log('🧪 Lancement des tests frontend...\n');
console.log(`Commande: npx jest ${jestArgs.join(' ')}\n`);

// Lancer Jest depuis le répertoire racine
const jest = spawn('npx', ['jest', ...jestArgs], {
  stdio: 'inherit',
  cwd: __dirname
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