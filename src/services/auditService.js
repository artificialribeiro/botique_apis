/**
 * BOUTIQUE DINIZ API - Serviço de Auditoria
 * Desenvolvido por Estúdio Atlas
 */

const db = require('../config/database');
const logger = require('../utils/logger');

/**
 * Registra evento de auditoria
 */
function log(entidade, entidadeId, acao, options = {}) {
  try {
    const auditDb = db.getAudit();
    
    const stmt = auditDb.prepare(`
      INSERT INTO audit_log (
        entidade, entidade_id, acao, antes_json, depois_json,
        usuario_id, usuario_tipo, ip, user_agent
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    
    stmt.run(
      entidade,
      entidadeId,
      acao,
      options.antes ? JSON.stringify(options.antes) : null,
      options.depois ? JSON.stringify(options.depois) : null,
      options.usuarioId || null,
      options.usuarioTipo || null,
      options.ip || null,
      options.userAgent || null
    );
    
    logger.debug(`Audit log: ${acao} em ${entidade}:${entidadeId}`);
  } catch (error) {
    logger.error('Erro ao registrar auditoria:', error);
  }
}

/**
 * Registra criação
 */
function logCreate(entidade, entidadeId, dados, options = {}) {
  log(entidade, entidadeId, 'create', {
    ...options,
    depois: dados
  });
}

/**
 * Registra atualização
 */
function logUpdate(entidade, entidadeId, antes, depois, options = {}) {
  log(entidade, entidadeId, 'update', {
    ...options,
    antes,
    depois
  });
}

/**
 * Registra exclusão
 */
function logDelete(entidade, entidadeId, dados, options = {}) {
  log(entidade, entidadeId, 'delete', {
    ...options,
    antes: dados
  });
}

/**
 * Registra mudança de status
 */
function logStatusChange(entidade, entidadeId, statusAnterior, statusNovo, options = {}) {
  log(entidade, entidadeId, 'status_change', {
    ...options,
    antes: { status: statusAnterior },
    depois: { status: statusNovo }
  });
}

/**
 * Registra login
 */
function logLogin(usuarioId, usuarioTipo, options = {}) {
  log('sessao', usuarioId, 'login', {
    ...options,
    usuarioId,
    usuarioTipo
  });
}

/**
 * Registra logout
 */
function logLogout(usuarioId, usuarioTipo, options = {}) {
  log('sessao', usuarioId, 'logout', {
    ...options,
    usuarioId,
    usuarioTipo
  });
}

/**
 * Busca logs de auditoria
 */
function getLogs(filters = {}, page = 1, pageSize = 20) {
  const auditDb = db.getAudit();
  
  let sql = 'SELECT * FROM audit_log WHERE 1=1';
  const params = [];
  
  if (filters.entidade) {
    sql += ' AND entidade = ?';
    params.push(filters.entidade);
  }
  
  if (filters.entidadeId) {
    sql += ' AND entidade_id = ?';
    params.push(filters.entidadeId);
  }
  
  if (filters.acao) {
    sql += ' AND acao = ?';
    params.push(filters.acao);
  }
  
  if (filters.usuarioId) {
    sql += ' AND usuario_id = ?';
    params.push(filters.usuarioId);
  }
  
  if (filters.dataInicio) {
    sql += ' AND criado_em >= ?';
    params.push(filters.dataInicio);
  }
  
  if (filters.dataFim) {
    sql += ' AND criado_em <= ?';
    params.push(filters.dataFim);
  }
  
  // Contar total
  const countSql = sql.replace('SELECT *', 'SELECT COUNT(*) as total');
  const { total } = auditDb.prepare(countSql).get(...params);
  
  // Aplicar paginação
  sql += ' ORDER BY criado_em DESC LIMIT ? OFFSET ?';
  params.push(pageSize, (page - 1) * pageSize);
  
  const logs = auditDb.prepare(sql).all(...params);
  
  // Parse JSON fields
  logs.forEach(log => {
    if (log.antes_json) log.antes = JSON.parse(log.antes_json);
    if (log.depois_json) log.depois = JSON.parse(log.depois_json);
    delete log.antes_json;
    delete log.depois_json;
  });
  
  return { logs, total };
}

module.exports = {
  log,
  logCreate,
  logUpdate,
  logDelete,
  logStatusChange,
  logLogin,
  logLogout,
  getLogs
};
