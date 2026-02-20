/**
 * BOUTIQUE DINIZ API - Controller de Filiais/Unidades
 * Desenvolvido por Estúdio Atlas
 *
 * Este controlador expõe endpoints CRUD para gerenciar as filiais (unidades)
 * da loja. Cada filial possui um nome único, um tipo (loja, site,
 * estoque ou administrativo) e um status de ativo. Os métodos utilizam
 * o banco core através do util de banco de dados e respeitam o padrão de
 * respostas definido em src/utils/response.js. As alterações são
 * auditadas usando auditService.
 */

const db = require('../config/database');
const { success, successPaginated, created, notFound } = require('../utils/response');
const { getPaginationParams } = require('../utils/pagination');
const auditService = require('../services/auditService');
const { extractAuditInfo } = require('../middlewares/auth');
const logger = require('../utils/logger');

/**
 * POST /api/filiais
 * Cria nova filial
 */
function criar(req, res) {
  try {
    const { nome, tipo, ativo } = req.body;
    if (!nome || !tipo) {
      // Erro de validação simples
      return res.status(400).json({
        success: false,
        message: 'Erro de validação',
        error: {
          code: 'VALIDATION_ERROR',
          details: [
            { field: !nome ? 'nome' : 'tipo', issue: 'Campo obrigatório' }
          ]
        }
      });
    }
    const coreDb = db.getCore();
    const stmt = coreDb.prepare(`INSERT INTO filial (nome, tipo, ativo) VALUES (?, ?, ?)`);
    const result = stmt.run(nome, tipo, ativo !== undefined ? (ativo ? 1 : 0) : 1);
    const filial = coreDb.prepare(`SELECT * FROM filial WHERE id = ?`).get(result.lastInsertRowid);
    // Log de auditoria
    auditService.logCreate('filial', filial.id, filial, extractAuditInfo(req));
    logger.info('Filial criada', { filialId: filial.id });
    return created(res, filial, 'Filial criada com sucesso');
  } catch (error) {
    logger.error('Erro ao criar filial:', error);
    throw error;
  }
}

/**
 * GET /api/filiais
 * Lista filiais com paginação
 */
function listar(req, res) {
  try {
    const { page, pageSize, offset } = getPaginationParams(req.query);
    const { q, ativo, tipo } = req.query;
    const coreDb = db.getCore();
    let sql = `SELECT * FROM filial WHERE 1=1`;
    const params = [];
    if (q) {
      sql += ` AND nome LIKE ?`;
      params.push(`%${q}%`);
    }
    if (ativo !== undefined) {
      sql += ` AND ativo = ?`;
      params.push(parseInt(ativo));
    }
    if (tipo) {
      sql += ` AND tipo = ?`;
      params.push(tipo);
    }
    // Contar total
    const countSql = sql.replace(/SELECT \*/,'SELECT COUNT(*) as total');
    const { total } = coreDb.prepare(countSql).get(...params);
    // Paginar
    sql += ` ORDER BY criado_em DESC LIMIT ? OFFSET ?`;
    params.push(pageSize, offset);
    const filiais = coreDb.prepare(sql).all(...params);
    return successPaginated(res, filiais, page, pageSize, total);
  } catch (error) {
    logger.error('Erro ao listar filiais:', error);
    throw error;
  }
}

/**
 * GET /api/filiais/:id
 * Busca filial por ID
 */
function buscar(req, res) {
  try {
    const { id } = req.params;
    const coreDb = db.getCore();
    const filial = coreDb.prepare(`SELECT * FROM filial WHERE id = ?`).get(id);
    if (!filial) {
      return notFound(res, 'Filial não encontrada');
    }
    return success(res, filial);
  } catch (error) {
    logger.error('Erro ao buscar filial:', error);
    throw error;
  }
}

/**
 * PUT /api/filiais/:id
 * Atualiza uma filial
 */
function atualizar(req, res) {
  try {
    const { id } = req.params;
    const { nome, tipo, ativo } = req.body;
    const coreDb = db.getCore();
    const filialAntes = coreDb.prepare(`SELECT * FROM filial WHERE id = ?`).get(id);
    if (!filialAntes) {
      return notFound(res, 'Filial não encontrada');
    }
    const updates = [];
    const params = [];
    if (nome !== undefined) { updates.push('nome = ?'); params.push(nome); }
    if (tipo !== undefined) { updates.push('tipo = ?'); params.push(tipo); }
    if (ativo !== undefined) { updates.push('ativo = ?'); params.push(ativo ? 1 : 0); }
    if (updates.length > 0) {
      updates.push('criado_em = criado_em'); // placeholder to satisfy comma join but keep original criado_em
      params.push(id);
      coreDb.prepare(`UPDATE filial SET ${updates.join(', ')} WHERE id = ?`).run(...params);
    }
    const filialDepois = coreDb.prepare(`SELECT * FROM filial WHERE id = ?`).get(id);
    auditService.logUpdate('filial', id, filialAntes, filialDepois, extractAuditInfo(req));
    logger.info('Filial atualizada', { filialId: id });
    return success(res, filialDepois, 'Filial atualizada com sucesso');
  } catch (error) {
    logger.error('Erro ao atualizar filial:', error);
    throw error;
  }
}

/**
 * DELETE /api/filiais/:id
 * Remove (desativa) uma filial
 */
function remover(req, res) {
  try {
    const { id } = req.params;
    const coreDb = db.getCore();
    const filialAntes = coreDb.prepare(`SELECT * FROM filial WHERE id = ?`).get(id);
    if (!filialAntes) {
      return notFound(res, 'Filial não encontrada');
    }
    coreDb.prepare(`UPDATE filial SET ativo = 0 WHERE id = ?`).run(id);
    const filialDepois = coreDb.prepare(`SELECT * FROM filial WHERE id = ?`).get(id);
    auditService.logUpdate('filial', id, filialAntes, filialDepois, extractAuditInfo(req));
    logger.info('Filial removida', { filialId: id });
    return success(res, filialDepois, 'Filial removida com sucesso');
  } catch (error) {
    logger.error('Erro ao remover filial:', error);
    throw error;
  }
}

module.exports = {
  criar,
  listar,
  buscar,
  atualizar,
  remover
};