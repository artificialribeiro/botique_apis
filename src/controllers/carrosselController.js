/**
 * BOUTIQUE DINIZ API - Controller de Carrossel de Produtos
 * Desenvolvido por Estúdio Atlas
 * 
 * Gerencia o carrossel de produtos exibido na página inicial
 */

const db = require('../config/database');
const { success, successPaginated, created, notFound, validationError } = require('../utils/response');
const { getPaginationParams } = require('../utils/pagination');
const auditService = require('../services/auditService');
const { extractAuditInfo } = require('../middlewares/auth');
const { getRelativePath, removeFile } = require('../middlewares/upload');
const logger = require('../utils/logger');
const path = require('path');
const config = require('../config');

/**
 * POST /api/carrossel
 * Cria novo item de carrossel
 */
function criar(req, res) {
  try {
    const { titulo, descricao, produto_id, link, ordem, ativo } = req.body;
    const coreDb = db.getCore();
    
    if (!req.file) {
      return validationError(res, [{ field: 'imagem', issue: 'Imagem é obrigatória' }]);
    }
    
    // Validar se produto existe (se informado)
    if (produto_id) {
      const produto = coreDb.prepare('SELECT id FROM produto WHERE id = ?').get(produto_id);
      if (!produto) {
        return validationError(res, [{ field: 'produto_id', issue: 'Produto não encontrado' }]);
      }
    }
    
    const caminho = getRelativePath(req.file.path);
    
    // Obter próxima ordem se não informada
    let novaOrdem = ordem || 0;
    if (!ordem) {
      const ultimoItem = coreDb.prepare('SELECT MAX(ordem) as max_ordem FROM carrossel').get();
      novaOrdem = (ultimoItem.max_ordem || 0) + 1;
    }
    
    const result = coreDb.prepare(`
      INSERT INTO carrossel (titulo, descricao, imagem_caminho, produto_id, link, ordem, ativo)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(
      titulo || null,
      descricao || null,
      caminho,
      produto_id || null,
      link || null,
      novaOrdem,
      ativo !== undefined ? (ativo ? 1 : 0) : 1
    );
    
    const item = coreDb.prepare('SELECT * FROM carrossel WHERE id = ?').get(result.lastInsertRowid);
    
    auditService.logCreate('carrossel', item.id, item, extractAuditInfo(req));
    
    logger.info('Item de carrossel criado', { carrosselId: item.id });
    
    return created(res, item, 'Item de carrossel criado com sucesso');
  } catch (error) {
    logger.error('Erro ao criar item de carrossel:', error);
    throw error;
  }
}

/**
 * GET /api/carrossel
 * Lista itens de carrossel com paginação
 */
function listar(req, res) {
  try {
    const { page, pageSize, offset } = getPaginationParams(req.query);
    const { ativo } = req.query;
    const coreDb = db.getCore();
    
    let sql = 'SELECT * FROM carrossel WHERE 1=1';
    const params = [];
    
    if (ativo !== undefined) {
      sql += ' AND ativo = ?';
      params.push(parseInt(ativo));
    }
    
    // Contar total
    const countSql = sql.replace('SELECT *', 'SELECT COUNT(*) as total');
    const { total } = coreDb.prepare(countSql).get(...params);
    
    // Buscar com paginação
    sql += ' ORDER BY ordem ASC, criado_em DESC LIMIT ? OFFSET ?';
    params.push(pageSize, offset);
    
    const itens = coreDb.prepare(sql).all(...params);
    
    return successPaginated(res, itens, page, pageSize, total);
  } catch (error) {
    logger.error('Erro ao listar carrossel:', error);
    throw error;
  }
}

/**
 * GET /api/carrossel/:id
 * Busca item de carrossel por ID
 */
function buscar(req, res) {
  try {
    const { id } = req.params;
    const coreDb = db.getCore();
    
    const item = coreDb.prepare('SELECT * FROM carrossel WHERE id = ?').get(id);
    
    if (!item) {
      return notFound(res, 'Item de carrossel não encontrado');
    }
    
    // Se houver produto associado, carregar seus dados
    if (item.produto_id) {
      const produto = coreDb.prepare('SELECT id, nome, descricao, preco FROM produto WHERE id = ?').get(item.produto_id);
      item.produto = produto || null;
    }
    
    return success(res, item);
  } catch (error) {
    logger.error('Erro ao buscar item de carrossel:', error);
    throw error;
  }
}

/**
 * PUT /api/carrossel/:id
 * Atualiza item de carrossel
 */
function atualizar(req, res) {
  try {
    const { id } = req.params;
    const { titulo, descricao, produto_id, link, ordem, ativo } = req.body;
    const coreDb = db.getCore();
    
    const itemAntes = coreDb.prepare('SELECT * FROM carrossel WHERE id = ?').get(id);
    if (!itemAntes) {
      return notFound(res, 'Item de carrossel não encontrado');
    }
    
    // Validar se produto existe (se informado)
    if (produto_id) {
      const produto = coreDb.prepare('SELECT id FROM produto WHERE id = ?').get(produto_id);
      if (!produto) {
        return validationError(res, [{ field: 'produto_id', issue: 'Produto não encontrado' }]);
      }
    }
    
    const updates = [];
    const params = [];
    
    if (titulo !== undefined) { updates.push('titulo = ?'); params.push(titulo); }
    if (descricao !== undefined) { updates.push('descricao = ?'); params.push(descricao); }
    if (produto_id !== undefined) { updates.push('produto_id = ?'); params.push(produto_id || null); }
    if (link !== undefined) { updates.push('link = ?'); params.push(link); }
    if (ordem !== undefined) { updates.push('ordem = ?'); params.push(ordem); }
    if (ativo !== undefined) { updates.push('ativo = ?'); params.push(ativo ? 1 : 0); }
    
    if (req.file) {
      // Remover imagem antiga
      const oldPath = path.join(config.upload.path, itemAntes.imagem_caminho.replace('/uploads', ''));
      removeFile(oldPath);
      
      updates.push('imagem_caminho = ?');
      params.push(getRelativePath(req.file.path));
    }
    
    if (updates.length > 0) {
      updates.push('atualizado_em = datetime(\'now\')');
      params.push(id);
      coreDb.prepare(`UPDATE carrossel SET ${updates.join(', ')} WHERE id = ?`).run(...params);
    }
    
    const itemDepois = coreDb.prepare('SELECT * FROM carrossel WHERE id = ?').get(id);
    
    auditService.logUpdate('carrossel', id, itemAntes, itemDepois, extractAuditInfo(req));
    
    logger.info('Item de carrossel atualizado', { carrosselId: id });
    
    return success(res, itemDepois, 'Item de carrossel atualizado com sucesso');
  } catch (error) {
    logger.error('Erro ao atualizar item de carrossel:', error);
    throw error;
  }
}

/**
 * DELETE /api/carrossel/:id
 * Remove item de carrossel
 */
function remover(req, res) {
  try {
    const { id } = req.params;
    const coreDb = db.getCore();
    
    const item = coreDb.prepare('SELECT * FROM carrossel WHERE id = ?').get(id);
    if (!item) {
      return notFound(res, 'Item de carrossel não encontrado');
    }
    
    // Remover imagem
    const filePath = path.join(config.upload.path, item.imagem_caminho.replace('/uploads', ''));
    removeFile(filePath);
    
    // Remover do banco
    coreDb.prepare('DELETE FROM carrossel WHERE id = ?').run(id);
    
    auditService.logDelete('carrossel', id, item, extractAuditInfo(req));
    
    logger.info('Item de carrossel removido', { carrosselId: id });
    
    return success(res, null, 'Item de carrossel removido com sucesso');
  } catch (error) {
    logger.error('Erro ao remover item de carrossel:', error);
    throw error;
  }
}

/**
 * PATCH /api/carrossel/:id/ordem
 * Reordena itens do carrossel
 */
function reordenar(req, res) {
  try {
    const { itens } = req.body; // Array de { id, ordem }
    
    if (!Array.isArray(itens) || itens.length === 0) {
      return validationError(res, [{ field: 'itens', issue: 'Array de itens com ordem é obrigatório' }]);
    }
    
    const coreDb = db.getCore();
    
    // Atualizar ordem de cada item em uma transação
    const transaction = coreDb.transaction(() => {
      for (const item of itens) {
        coreDb.prepare('UPDATE carrossel SET ordem = ? WHERE id = ?').run(item.ordem, item.id);
      }
    });
    
    transaction();
    
    logger.info('Carrossel reordenado', { quantidade: itens.length });
    
    return success(res, { quantidade: itens.length }, 'Carrossel reordenado com sucesso');
  } catch (error) {
    logger.error('Erro ao reordenar carrossel:', error);
    throw error;
  }
}

/**
 * GET /api/carrossel/ativo/listar
 * Lista apenas itens ativos do carrossel (para frontend)
 */
function listarAtivos(req, res) {
  try {
    const coreDb = db.getCore();
    
    const itens = coreDb.prepare(`
      SELECT * FROM carrossel WHERE ativo = 1 ORDER BY ordem ASC
    `).all();
    
    return success(res, itens);
  } catch (error) {
    logger.error('Erro ao listar carrossel ativo:', error);
    throw error;
  }
}

module.exports = {
  criar,
  listar,
  buscar,
  atualizar,
  remover,
  reordenar,
  listarAtivos
};
