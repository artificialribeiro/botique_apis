/**
 * BOUTIQUE DINIZ API - Controller de Variantes de Produto
 * Desenvolvido por Estúdio Atlas
 */

const db = require('../config/database');
const { success, created, notFound, conflict } = require('../utils/response');
const auditService = require('../services/auditService');
const { extractAuditInfo } = require('../middlewares/auth');
const logger = require('../utils/logger');

/**
 * POST /api/produtos/:id/variantes
 * Cria variante do produto
 */
function criar(req, res) {
  try {
    const { id: produtoId } = req.params;
    const { tamanho, cor, estoque, estoque_minimo } = req.body;
    
    const coreDb = db.getCore();
    
    // Verificar se produto existe
    const produto = coreDb.prepare('SELECT id FROM produto WHERE id = ?').get(produtoId);
    if (!produto) {
      return notFound(res, 'Produto não encontrado');
    }
    
    // Verificar se variante já existe
    const existente = coreDb.prepare(`
      SELECT id FROM produto_variante WHERE produto_id = ? AND tamanho = ? AND cor = ?
    `).get(produtoId, tamanho, cor);
    
    if (existente) {
      return conflict(res, 'Variante já existe para este tamanho e cor');
    }
    
    const result = coreDb.prepare(`
      INSERT INTO produto_variante (produto_id, tamanho, cor, estoque, estoque_minimo)
      VALUES (?, ?, ?, ?, ?)
    `).run(produtoId, tamanho, cor, estoque || 0, estoque_minimo || 0);
    
    const variante = coreDb.prepare('SELECT * FROM produto_variante WHERE id = ?').get(result.lastInsertRowid);
    
    auditService.logCreate('produto_variante', variante.id, variante, extractAuditInfo(req));
    
    logger.info('Variante criada', { varianteId: variante.id, produtoId });
    
    return created(res, variante, 'Variante criada com sucesso');
  } catch (error) {
    logger.error('Erro ao criar variante:', error);
    throw error;
  }
}

/**
 * GET /api/produtos/:id/variantes
 * Lista variantes do produto
 */
function listar(req, res) {
  try {
    const { id: produtoId } = req.params;
    const coreDb = db.getCore();
    
    const produto = coreDb.prepare('SELECT id FROM produto WHERE id = ?').get(produtoId);
    if (!produto) {
      return notFound(res, 'Produto não encontrado');
    }
    
    const variantes = coreDb.prepare(`
      SELECT * FROM produto_variante WHERE produto_id = ? ORDER BY tamanho, cor
    `).all(produtoId);
    
    return success(res, variantes);
  } catch (error) {
    logger.error('Erro ao listar variantes:', error);
    throw error;
  }
}

/**
 * PUT /api/variantes/:id
 * Atualiza variante
 */
function atualizar(req, res) {
  try {
    const { id } = req.params;
    const { tamanho, cor, estoque, estoque_minimo, ativo } = req.body;
    
    const coreDb = db.getCore();
    
    const varianteAntes = coreDb.prepare('SELECT * FROM produto_variante WHERE id = ?').get(id);
    if (!varianteAntes) {
      return notFound(res, 'Variante não encontrada');
    }
    
    const updates = [];
    const params = [];
    
    if (tamanho !== undefined) { updates.push('tamanho = ?'); params.push(tamanho); }
    if (cor !== undefined) { updates.push('cor = ?'); params.push(cor); }
    if (estoque !== undefined) { updates.push('estoque = ?'); params.push(estoque); }
    if (estoque_minimo !== undefined) { updates.push('estoque_minimo = ?'); params.push(estoque_minimo); }
    if (ativo !== undefined) { updates.push('ativo = ?'); params.push(ativo ? 1 : 0); }
    
    if (updates.length > 0) {
      updates.push('atualizado_em = datetime(\'now\')');
      params.push(id);
      coreDb.prepare(`UPDATE produto_variante SET ${updates.join(', ')} WHERE id = ?`).run(...params);
    }
    
    const varianteDepois = coreDb.prepare('SELECT * FROM produto_variante WHERE id = ?').get(id);
    
    auditService.logUpdate('produto_variante', id, varianteAntes, varianteDepois, extractAuditInfo(req));
    
    logger.info('Variante atualizada', { varianteId: id });
    
    return success(res, varianteDepois, 'Variante atualizada com sucesso');
  } catch (error) {
    logger.error('Erro ao atualizar variante:', error);
    throw error;
  }
}

/**
 * DELETE /api/variantes/:id
 * Remove variante
 */
function remover(req, res) {
  try {
    const { id } = req.params;
    const coreDb = db.getCore();
    
    const variante = coreDb.prepare('SELECT * FROM produto_variante WHERE id = ?').get(id);
    if (!variante) {
      return notFound(res, 'Variante não encontrada');
    }
    
    // Soft delete
    coreDb.prepare('UPDATE produto_variante SET ativo = 0, atualizado_em = datetime(\'now\') WHERE id = ?').run(id);
    
    auditService.logDelete('produto_variante', id, variante, extractAuditInfo(req));
    
    logger.info('Variante removida', { varianteId: id });
    
    return success(res, null, 'Variante removida com sucesso');
  } catch (error) {
    logger.error('Erro ao remover variante:', error);
    throw error;
  }
}

module.exports = {
  criar,
  listar,
  atualizar,
  remover
};
