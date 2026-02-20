/**
 * BOUTIQUE DINIZ API - Configuração do Banco de Dados
 * Desenvolvido por Estúdio Atlas
 * 
 * Utiliza SQLite com múltiplos arquivos para segurança:
 * - core.db: Operações do dia a dia
 * - auth.db: Segurança e autenticação
 * - audit.db: Auditoria e logs
 */

const Database = require('./sqlite-compat');
const config = require('./index');
const logger = require('../utils/logger');
const path = require('path');
const fs = require('fs');

// Garantir que o diretório data existe
const dataDir = path.dirname(config.database.corePath);
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

// Conexões com os bancos
let coreDb = null;
let authDb = null;
let auditDb = null;

/**
 * Inicializa conexão com banco de dados
 */
function initDatabase(dbPath, name) {
  try {
    const db = new Database(dbPath, {
      verbose: config.env === 'development' ? console.log : null
    });
    
    // Configurações de performance e segurança
    db.pragma('journal_mode = WAL');
    db.pragma('foreign_keys = ON');
    db.pragma('synchronous = NORMAL');
    db.pragma('cache_size = -64000'); // 64MB cache
    db.pragma('temp_store = MEMORY');
    
    logger.info(`Banco de dados ${name} conectado: ${dbPath}`);
    return db;
  } catch (error) {
    logger.error(`Erro ao conectar banco ${name}: ${error.message}`);
    throw error;
  }
}

/**
 * Obtém conexão com core.db
 */
function getCore() {
  if (!coreDb) {
    coreDb = initDatabase(config.database.corePath, 'core');
  }
  return coreDb;
}

/**
 * Obtém conexão com auth.db
 */
function getAuth() {
  if (!authDb) {
    authDb = initDatabase(config.database.authPath, 'auth');
  }
  return authDb;
}

/**
 * Obtém conexão com audit.db
 */
function getAudit() {
  if (!auditDb) {
    auditDb = initDatabase(config.database.auditPath, 'audit');
  }
  return auditDb;
}

/**
 * Fecha todas as conexões
 */
function closeAll() {
  if (coreDb) {
    coreDb.close();
    coreDb = null;
    logger.info('Banco core.db fechado');
  }
  if (authDb) {
    authDb.close();
    authDb = null;
    logger.info('Banco auth.db fechado');
  }
  if (auditDb) {
    auditDb.close();
    auditDb = null;
    logger.info('Banco audit.db fechado');
  }
}

/**
 * Executa transação no banco especificado
 */
function transaction(db, fn) {
  return db.transaction(fn)();
}

module.exports = {
  getCore,
  getAuth,
  getAudit,
  closeAll,
  transaction
};
