#!/usr/bin/env node
/**
 * BOUTIQUE DINIZ API - Script de Backup Manual
 * Desenvolvido por Estúdio Atlas
 * 
 * Uso: node scripts/backup.js
 */

require('dotenv').config();
const archiver = require('archiver');
const fs = require('fs');
const path = require('path');

const dataDir = path.resolve(process.cwd(), './data');
const backupDir = path.resolve(process.cwd(), './data/backups');

console.log('╔════════════════════════════════════════════════════════════╗');
console.log('║          BOUTIQUE DINIZ API - Backup Manual                ║');
console.log('║                Desenvolvido por Estúdio Atlas              ║');
console.log('╚════════════════════════════════════════════════════════════╝');
console.log('');

// Garantir que o diretório de backup existe
if (!fs.existsSync(backupDir)) {
  fs.mkdirSync(backupDir, { recursive: true });
}

const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
const backupFileName = `manual_backup_${timestamp}.zip`;
const backupPath = path.join(backupDir, backupFileName);

console.log(`📦 Criando backup: ${backupFileName}`);
console.log('');

const output = fs.createWriteStream(backupPath);
const archive = archiver('zip', { zlib: { level: 9 } });

output.on('close', () => {
  const sizeBytes = archive.pointer();
  const sizeMB = (sizeBytes / (1024 * 1024)).toFixed(2);
  
  console.log('');
  console.log('╔════════════════════════════════════════════════════════════╗');
  console.log('║              ✅ BACKUP CRIADO COM SUCESSO!                 ║');
  console.log('╠════════════════════════════════════════════════════════════╣');
  console.log(`║  Arquivo: ${backupFileName.padEnd(43)}║`);
  console.log(`║  Tamanho: ${(sizeMB + ' MB').padEnd(43)}║`);
  console.log(`║  Local: data/backups/                                      ║`);
  console.log('╚════════════════════════════════════════════════════════════╝');
});

archive.on('error', (err) => {
  console.error('❌ Erro ao criar backup:', err.message);
  process.exit(1);
});

archive.on('entry', (entry) => {
  console.log(`  📄 ${entry.name}`);
});

archive.pipe(output);

// Adicionar bancos de dados
console.log('📁 Adicionando bancos de dados...');
if (fs.existsSync(path.join(dataDir, 'core.db'))) {
  archive.file(path.join(dataDir, 'core.db'), { name: 'data/core.db' });
}
if (fs.existsSync(path.join(dataDir, 'auth.db'))) {
  archive.file(path.join(dataDir, 'auth.db'), { name: 'data/auth.db' });
}
if (fs.existsSync(path.join(dataDir, 'audit.db'))) {
  archive.file(path.join(dataDir, 'audit.db'), { name: 'data/audit.db' });
}

// Adicionar uploads
console.log('📁 Adicionando uploads...');
const uploadsDir = path.join(dataDir, 'uploads');
if (fs.existsSync(uploadsDir)) {
  archive.directory(uploadsDir, 'data/uploads');
}

// Adicionar .env
console.log('📁 Adicionando configurações...');
const envPath = path.resolve(process.cwd(), '.env');
if (fs.existsSync(envPath)) {
  archive.file(envPath, { name: '.env' });
}

archive.finalize();
