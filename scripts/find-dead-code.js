#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

/**
 * Script de détection de dead code pour le projet FAF
 * Trouve les fichiers qui exportent mais ne sont jamais importés
 */

const BACKEND_DIR = path.join(__dirname, '../backend');
const FRONTEND_DIR = path.join(__dirname, '../frontend');

// Fichiers à ignorer (points d'entrée, tests, config)
const IGNORE_PATTERNS = [
  'app.js',           // Point d'entrée
  '*.test.js',        // Tests
  'jest.config.js',   // Config
  'node_modules',     // Dépendances
  '.git'              // Git
];

function shouldIgnore(filePath) {
  return IGNORE_PATTERNS.some(pattern => 
    filePath.includes(pattern.replace('*', ''))
  );
}

function getAllJSFiles(dir) {
  const files = [];
  
  function scan(currentDir) {
    const items = fs.readdirSync(currentDir);
    
    for (const item of items) {
      const fullPath = path.join(currentDir, item);
      
      if (shouldIgnore(fullPath)) continue;
      
      const stat = fs.statSync(fullPath);
      
      if (stat.isDirectory()) {
        scan(fullPath);
      } else if (item.endsWith('.js')) {
        files.push(fullPath);
      }
    }
  }
  
  scan(dir);
  return files;
}

function hasExports(filePath) {
  try {
    const content = fs.readFileSync(filePath, 'utf8');
    return content.includes('module.exports') || 
           content.includes('exports.') ||
           content.includes('export ');
  } catch (err) {
    return false;
  }
}

function isImported(filePath, allFiles) {
  const fileName = path.basename(filePath, '.js');
  const relativePath = path.relative(BACKEND_DIR, filePath);
  
  // Rechercher les imports dans tous les fichiers
  for (const file of allFiles) {
    if (file === filePath) continue;
    
    try {
      const content = fs.readFileSync(file, 'utf8');
      
      // Vérifier différents patterns d'import
      const importPatterns = [
        `require('${relativePath}')`,
        `require("./${fileName}")`,
        `require("../${fileName}")`,
        `require('./${fileName}')`,
        `require('../${fileName}')`,
        `require('./services/${fileName}')`,
        `require('./middleware/${fileName}')`,
        `require('./config/${fileName}')`,
        `require('./utils/${fileName}')`,
        fileName  // Nom simple
      ];
      
      for (const pattern of importPatterns) {
        if (content.includes(pattern)) {
          return true;
        }
      }
    } catch (err) {
      continue;
    }
  }
  
  return false;
}

function findDeadCode() {
  console.log('🔍 Recherche de dead code dans le projet FAF...\n');
  
  const backendFiles = getAllJSFiles(BACKEND_DIR);
  const frontendFiles = getAllJSFiles(FRONTEND_DIR);
  const allFiles = [...backendFiles, ...frontendFiles];
  
  console.log(`📁 ${allFiles.length} fichiers JavaScript trouvés\n`);
  
  const deadFiles = [];
  
  for (const file of backendFiles) {
    if (hasExports(file) && !isImported(file, allFiles)) {
      deadFiles.push(file);
    }
  }
  
  if (deadFiles.length === 0) {
    console.log('✅ Aucun dead code détecté !');
  } else {
    console.log(`❌ ${deadFiles.length} fichier(s) de dead code détecté(s):\n`);
    
    deadFiles.forEach(file => {
      const relativePath = path.relative(process.cwd(), file);
      console.log(`  🗑️  ${relativePath}`);
    });
    
    console.log('\n💡 Ces fichiers exportent du code mais ne sont jamais importés.');
    console.log('   Vérifiez s\'ils peuvent être supprimés en toute sécurité.');
  }
}

// Exécution
findDeadCode();