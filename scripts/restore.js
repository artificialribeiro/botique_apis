#!/usr/bin/env node
/**
 * BOUTIQUE DINIZ API - Script de Restauração
 * Desenvolvido por Estúdio Atlas
 * 
 * Uso: node scripts/restore.js <arquivo_backup.zip>
 */

require('dotenv').config();
const unzipper = require('unzipper');
const archiver = require('archiver');
const fs = require('fs');
const path = require('path');

const args = process.argv.slice(2);

console.log('╔════════════════════════════════════════════════════════════╗');
console.log('║        BOUTIQUE DINIZ API - Restauração de Backup          ║');
console.log('║                Desenvolvido por Estúdio Atlas              ║');
console.log('╚════════════════════════════════════════════════════════════╝');
console.log('');

if (args.length === 0) {
  console.log('❌ Uso: node scripts/restore.js <arquivo_backup.zip>');
  console.log('');
  console.log('Backups disponíveis:');
  
  const backupDir = path.resolve(process.cwd(), './data/backups');
  if (fs.existsSync(backupDir)) {
    const files = fs.readdirSync(backupDir)
      .filter(f => f.endsWith('.zip'))
      .sort()
      .reverse();
    
    if (files.length === 0) {
      console.log('  Nenhum backup encontrado.');
    } else {
      files.forEach(f => {
        const stats = fs.statSync(path.join(backupDir, f));
        const sizeMB = (stats.size / (1024 * 1024)).toFixed(2);
        console.log(`  • ${f} (${sizeMB} MB)`);
      });
    }
  }
  
  process.exit(1);
}

const backupFile = args[0];
let backupPath;

// Verificar se é caminho absoluto ou relativo
if (path.isAbsolute(backupFile)) {
  backupPath = backupFile;
} else if (backupFile.includes('/')) {
  backupPath = path.resolve(process.cwd(), backupFile);
} else {
  // Procurar na pasta de backups
  backupPath = path.resolve(process.cwd(), './data/backups', backupFile);
}

if (!fs.existsSync(backupPath)) {
  console.log(`❌ Arquivo não encontrado: ${backupPath}`);
  process.exit(1);
}

console.log(`📦 Restaurando: ${path.basename(backupPath)}`);
console.log('');

async function restore() {
  try {
    const dataDir = path.resolve(process.cwd(), './data');
    const backupDir = path.resolve(process.cwd(), './data/backups');
    
    // Criar backup de segurança antes de restaurar
    console.log('🔒 Criando backup de segurança do estado atual...');
    
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    const preRestoreBackup = `pre_restore_${timestamp}.zip`;
    const preRestorePath = path.join(backupDir, preRestoreBackup);
    
    const preBackupOutput = fs.createWriteStream(preRestorePath);
    const preBackupArchive = archiver('zip', { zlib: { level: 9 } });
    
    await new Promise((resolve, reject) => {
      preBackupOutput.on('close', resolve);
      preBackupOutput.on('error', reject);
      preBackupArchive.pipe(preBackupOutput);
      
      if (fs.existsSync(path.join(dataDir, 'core.db'))) {
        preBackupArchive.file(path.join(dataDir, 'core.db'), { name: 'data/core.db' });
      }
      if (fs.existsSync(path.join(dataDir, 'auth.db'))) {
        preBackupArchive.file(path.join(dataDir, 'auth.db'), { name: 'data/auth.db' });
      }
      if (fs.existsSync(path.join(dataDir, 'audit.db'))) {
        preBackupArchive.file(path.join(dataDir, 'audit.db'), { name: 'data/audit.db' });
      }
      
      preBackupArchive.finalize();
    });
    
    console.log(`  ✅ Backup de segurança: ${preRestoreBackup}`);
    console.log('');
    
    // Extrair backup
    console.log('📂 Extraindo backup...');
    
    const extractPath = path.resolve(process.cwd());
    
    await new Promise((resolve, reject) => {
      fs.createReadStream(backupPath)
        .pipe(unzipper.Extract({ path: extractPath }))
        .on('close', resolve)
        .on('error', reject);
    });
    
    console.log('');
    console.log('╔════════════════════════════════════════════════════════════╗');
    console.log('║            ✅ BACKUP RESTAURADO COM SUCESSO!               ║');
    console.log('╠════════════════════════════════════════════════════════════╣');
    console.log(`║  Backup de segurança: ${preRestoreBackup.padEnd(32)}║`);
    console.log('║                                                            ║');
    console.log('║  ⚠️  REINICIE O SERVIDOR PARA APLICAR AS ALTERAÇÕES!       ║');
    console.log('║                                                            ║');
    console.log('║  Comando: pm2 restart boutique-diniz-api                   ║');
    console.log('╚════════════════════════════════════════════════════════════╝');
  } catch (error) {
    console.error('❌ Erro ao restaurar backup:', error.message);
    process.exit(1);
  }
}

restore();
