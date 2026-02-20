#!/usr/bin/env node

/**
 * BOUTIQUE DINIZ API - Script de Migração: Adicionar Tabela de Carrossel
 * Desenvolvido por Estúdio Atlas
 * 
 * Este script adiciona a tabela de carrossel a bancos de dados existentes
 * que não possuem essa tabela ainda.
 */

require('dotenv').config();
const Database = require('better-sqlite3');
const path = require('path');

const dataDir = path.resolve(process.cwd(), './data');
const corePath = path.resolve(dataDir, 'core.db');

console.log('\n╔════════════════════════════════════════════════════════════╗');
console.log('║     BOUTIQUE DINIZ API - Adicionar Tabela de Carrossel    ║');
console.log('╚════════════════════════════════════════════════════════════╝\n');

try {
  const coreDb = new Database(corePath);
  
  // Verificar se tabela já existe
  const tableExists = coreDb.prepare(`
    SELECT name FROM sqlite_master 
    WHERE type='table' AND name='carrossel'
  `).get();
  
  if (tableExists) {
    console.log('✅ Tabela de carrossel já existe!');
    coreDb.close();
    process.exit(0);
  }
  
  console.log('📦 Criando tabela de carrossel...');
  
  coreDb.exec(`
    CREATE TABLE IF NOT EXISTS carrossel (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      titulo TEXT,
      descricao TEXT,
      imagem_caminho TEXT NOT NULL,
      produto_id INTEGER,
      link TEXT,
      ordem INTEGER NOT NULL DEFAULT 0,
      ativo INTEGER NOT NULL DEFAULT 1,
      criado_em TEXT NOT NULL DEFAULT (datetime('now')),
      atualizado_em TEXT,
      FOREIGN KEY (produto_id) REFERENCES produto(id) ON DELETE SET NULL
    );
    CREATE INDEX IF NOT EXISTS idx_carrossel_ordem ON carrossel(ordem);
    CREATE INDEX IF NOT EXISTS idx_carrossel_ativo ON carrossel(ativo);
    CREATE INDEX IF NOT EXISTS idx_carrossel_produto ON carrossel(produto_id);
  `);
  
  console.log('✅ Tabela de carrossel criada com sucesso!');
  
  coreDb.close();
  
  console.log('\n╔════════════════════════════════════════════════════════════╗');
  console.log('║                  Migração Concluída!                      ║');
  console.log('╚════════════════════════════════════════════════════════════╝\n');
  
  process.exit(0);
  
} catch (error) {
  console.error('❌ Erro ao adicionar tabela de carrossel:', error.message);
  process.exit(1);
}
