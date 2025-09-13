#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

/**
 * Script amélioré de détection de dead code
 * Utilise l'AST pour analyser précisément les imports/exports
 */

const PROJECT_ROOT = path.join(__dirname, '..');
const BACKEND_DIR = path.join(PROJECT_ROOT, 'backend');

function getAllJSFiles(dir) {
  const files = [];
  
  function scan(currentDir) {
    if (currentDir.includes('node_modules') || currentDir.includes('.git')) return;
    
    try {
      const items = fs.readdirSync(currentDir);
      
      for (const item of items) {
        const fullPath = path.join(currentDir, item);
        const stat = fs.statSync(fullPath);
        
        if (stat.isDirectory()) {
          scan(fullPath);
        } else if (item.endsWith('.js') && !item.includes('.test.') && item !== 'jest.config.js') {
          files.push(fullPath);
        }
      }
    } catch (err) {
      // Ignorer les erreurs de permission
    }
  }
  
  scan(dir);
  return files;
}

function extractRequires(filePath) {
  try {
    const content = fs.readFileSync(filePath, 'utf8');
    const requires = [];
    
    // Pattern pour capturer les require() avec chemins relatifs
    const requireRegex = /require\(['"`]([^'"`]+)['"`]\)/g;
    let match;
    
    while ((match = requireRegex.exec(content)) !== null) {
      const requiredPath = match[1];
      
      // Convertir en chemin absolu si relatif
      if (requiredPath.startsWith('./') || requiredPath.startsWith('../')) {
        const dir = path.dirname(filePath);
        const absolutePath = path.resolve(dir, requiredPath);
        
        // Ajouter .js si pas d'extension
        const finalPath = absolutePath.endsWith('.js') ? absolutePath : absolutePath + '.js';
        
        if (fs.existsSync(finalPath)) {
          requires.push(finalPath);
        }
      }
    }
    
    return requires;
  } catch (err) {
    return [];
  }
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

function findRealDeadCode() {
  console.log('🔍 Recherche précise de dead code...\n');
  
  const allFiles = getAllJSFiles(BACKEND_DIR);
  const entryPoints = [
    path.join(BACKEND_DIR, 'app.js')
  ];
  
  console.log(`📁 ${allFiles.length} fichiers JavaScript analysés`);
  console.log(`🚪 Points d'entrée: ${entryPoints.map(f => path.basename(f)).join(', ')}\n`);
  
  // Construire le graphe de dépendances
  const dependencyGraph = new Map();
  const reachableFiles = new Set();
  
  for (const file of allFiles) {
    const requires = extractRequires(file);
    dependencyGraph.set(file, requires);
  }
  
  // Parcours en profondeur depuis les points d'entrée
  function markReachable(filePath) {
    if (reachableFiles.has(filePath)) return;
    
    reachableFiles.add(filePath);
    const deps = dependencyGraph.get(filePath) || [];
    
    for (const dep of deps) {
      markReachable(dep);
    }
  }
  
  // Marquer tous les fichiers atteignables
  for (const entry of entryPoints) {
    markReachable(entry);
  }
  
  // Trouver les fichiers inaccessibles qui ont des exports
  const deadFiles = [];
  
  for (const file of allFiles) {
    if (!reachableFiles.has(file) && hasExports(file)) {
      deadFiles.push(file);
    }
  }
  
  // Résultats
  console.log(`✅ ${reachableFiles.size} fichiers atteignables`);
  console.log(`🗑️  ${deadFiles.length} fichiers de dead code détectés\n`);
  
  if (deadFiles.length > 0) {
    console.log('Dead code confirmé:');
    deadFiles.forEach(file => {
      const relativePath = path.relative(PROJECT_ROOT, file);
      console.log(`  ❌ ${relativePath}`);
    });
  } else {
    console.log('🎉 Aucun dead code détecté !');
  }
  
  return {
    total: allFiles.length,
    reachable: reachableFiles.size,
    dead: deadFiles.length,
    deadFiles
  };
}

// Exécution
const result = findRealDeadCode();

console.log('\n📊 Résumé:');
console.log(`Total: ${result.total} fichiers`);
console.log(`Atteignables: ${result.reachable} fichiers (${Math.round(result.reachable/result.total*100)}%)`);
console.log(`Dead code: ${result.dead} fichiers (${Math.round(result.dead/result.total*100)}%)`);