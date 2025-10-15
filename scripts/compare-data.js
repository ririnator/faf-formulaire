#!/usr/bin/env node

const { MongoClient } = require('mongodb');
const fs = require('fs');
const path = require('path');
require('dotenv').config();

const uri = process.env.MONGODB_URI;
const client = new MongoClient(uri);

async function compareData() {
  try {
    console.log('🔍 Comparaison Backup vs MongoDB actuel\n');

    // 1. Charger le backup
    const backupFile = path.join(__dirname, '../backups/mongodb-backup-1760513256245.json');
    const backupData = JSON.parse(fs.readFileSync(backupFile, 'utf8'));
    const backupResponses = backupData.responses || [];

    console.log('📦 Backup:');
    console.log('   Total:', backupResponses.length, 'réponses\n');

    // 2. Récupérer MongoDB
    await client.connect();
    const db = client.db();
    const mongoResponses = await db.collection('responses').find().toArray();

    console.log('📊 MongoDB actuel:');
    console.log('   Total:', mongoResponses.length, 'réponses\n');

    // 3. Afficher les données MongoDB actuelles
    console.log('📋 Détails MongoDB:\n');
    for (const resp of mongoResponses) {
      console.log(`   - ${resp.name} (${resp.month})`);
      console.log(`     Token: ${resp.token || 'null'}`);
      console.log(`     isAdmin: ${resp.isAdmin}`);
      console.log(`     Réponses: ${resp.responses?.length || 0}`);
      console.log(`     Date: ${resp.createdAt}`);
      console.log('');
    }

    // 4. Comparer avec le backup
    console.log('📋 Échantillon du backup (5 premières):\n');
    for (let i = 0; i < Math.min(5, backupResponses.length); i++) {
      const resp = backupResponses[i];
      console.log(`   ${i+1}. ${resp.name} (${resp.month})`);
      console.log(`      Token: ${resp.token || 'null'}`);
      console.log(`      isAdmin: ${resp.isAdmin}`);
      console.log(`      Réponses: ${resp.responses?.length || 0}`);
      console.log('');
    }

    // 5. Vérifier si les données du backup existent dans MongoDB
    console.log('🔍 Analyse des différences:\n');

    const mongoKeys = new Set(mongoResponses.map(r => `${r.name}-${r.month}-${r.isAdmin}`));
    const backupKeys = new Set(backupResponses.map(r => `${r.name}-${r.month}-${r.isAdmin}`));

    const inBackupOnly = backupResponses.filter(r =>
      !mongoKeys.has(`${r.name}-${r.month}-${r.isAdmin}`)
    );

    console.log('   Réponses dans le BACKUP mais PAS dans MongoDB:', inBackupOnly.length);

    if (inBackupOnly.length > 0 && inBackupOnly.length <= 10) {
      console.log('\n   Liste:');
      for (const resp of inBackupOnly) {
        console.log(`   - ${resp.name} (${resp.month})`);
      }
    }

    await client.close();
  } catch (err) {
    console.log('❌ Erreur:', err.message);
    await client.close();
    process.exit(1);
  }
}

compareData();
