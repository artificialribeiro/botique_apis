/**
 * BOUTIQUE DINIZ API - Controller de Endereços
 * Desenvolvido por Estúdio Atlas
 */

const db = require('../config/database');
const { success, created, notFound } = require('../utils/response');
const auditService = require('../services/auditService');
const { extractAuditInfo } = require('../middlewares/auth');
const logger = require('../utils/logger');

/**
 * POST /api/clientes/:id/enderecos
 * Cria endereço para cliente
 */
function criar(req, res) {
  try {
    const { id: clienteId } = req.params;
    const { tipo, rua, numero, complemento, bairro, cidade, estado, cep, referencia, principal } = req.body;
    
    const coreDb = db.getCore();
    
    // Verificar se cliente existe
    const cliente = coreDb.prepare('SELECT id FROM cliente WHERE id = ?').get(clienteId);
    if (!cliente) {
      return notFound(res, 'Cliente não encontrado');
    }
    
    // Se for principal, remover flag dos outros
    if (principal) {
      coreDb.prepare('UPDATE cliente_endereco SET principal = 0 WHERE cliente_id = ?').run(clienteId);
    }
    
    const result = coreDb.prepare(`
      INSERT INTO cliente_endereco (cliente_id, tipo, rua, numero, complemento, bairro, cidade, estado, cep, referencia, principal)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(clienteId, tipo, rua, numero || null, complemento || null, bairro || null, cidade, estado, cep || null, referencia || null, principal ? 1 : 0);
    
    const endereco = coreDb.prepare('SELECT * FROM cliente_endereco WHERE id = ?').get(result.lastInsertRowid);
    
    auditService.logCreate('cliente_endereco', endereco.id, endereco, extractAuditInfo(req));
    
    logger.info('Endereço criado', { enderecoId: endereco.id, clienteId });
    
    return created(res, endereco, 'Endereço criado com sucesso');
  } catch (error) {
    logger.error('Erro ao criar endereço:', error);
    throw error;
  }
}

/**
 * GET /api/clientes/:id/enderecos
 * Lista endereços do cliente
 */
function listar(req, res) {
  try {
    const { id: clienteId } = req.params;
    const coreDb = db.getCore();
    
    // Verificar se cliente existe
    const cliente = coreDb.prepare('SELECT id FROM cliente WHERE id = ?').get(clienteId);
    if (!cliente) {
      return notFound(res, 'Cliente não encontrado');
    }
    
    const enderecos = coreDb.prepare(`
      SELECT * FROM cliente_endereco WHERE cliente_id = ? ORDER BY principal DESC, criado_em DESC
    `).all(clienteId);
    
    return success(res, enderecos);
  } catch (error) {
    logger.error('Erro ao listar endereços:', error);
    throw error;
  }
}

/**
 * PUT /api/enderecos/:id
 * Atualiza endereço
 */
function atualizar(req, res) {
  try {
    const { id } = req.params;
    const { tipo, rua, numero, complemento, bairro, cidade, estado, cep, referencia, principal } = req.body;
    
    const coreDb = db.getCore();
    
    const enderecoAntes = coreDb.prepare('SELECT * FROM cliente_endereco WHERE id = ?').get(id);
    if (!enderecoAntes) {
      return notFound(res, 'Endereço não encontrado');
    }
    
    // Se for principal, remover flag dos outros
    if (principal) {
      coreDb.prepare('UPDATE cliente_endereco SET principal = 0 WHERE cliente_id = ?').run(enderecoAntes.cliente_id);
    }
    
    const updates = [];
    const params = [];
    
    if (tipo !== undefined) { updates.push('tipo = ?'); params.push(tipo); }
    if (rua !== undefined) { updates.push('rua = ?'); params.push(rua); }
    if (numero !== undefined) { updates.push('numero = ?'); params.push(numero); }
    if (complemento !== undefined) { updates.push('complemento = ?'); params.push(complemento); }
    if (bairro !== undefined) { updates.push('bairro = ?'); params.push(bairro); }
    if (cidade !== undefined) { updates.push('cidade = ?'); params.push(cidade); }
    if (estado !== undefined) { updates.push('estado = ?'); params.push(estado); }
    if (cep !== undefined) { updates.push('cep = ?'); params.push(cep); }
    if (referencia !== undefined) { updates.push('referencia = ?'); params.push(referencia); }
    if (principal !== undefined) { updates.push('principal = ?'); params.push(principal ? 1 : 0); }
    
    if (updates.length > 0) {
      params.push(id);
      coreDb.prepare(`UPDATE cliente_endereco SET ${updates.join(', ')} WHERE id = ?`).run(...params);
    }
    
    const enderecoDepois = coreDb.prepare('SELECT * FROM cliente_endereco WHERE id = ?').get(id);
    
    auditService.logUpdate('cliente_endereco', id, enderecoAntes, enderecoDepois, extractAuditInfo(req));
    
    logger.info('Endereço atualizado', { enderecoId: id });
    
    return success(res, enderecoDepois, 'Endereço atualizado com sucesso');
  } catch (error) {
    logger.error('Erro ao atualizar endereço:', error);
    throw error;
  }
}

/**
 * DELETE /api/enderecos/:id
 * Remove endereço
 */
function remover(req, res) {
  try {
    const { id } = req.params;
    const coreDb = db.getCore();
    
    const endereco = coreDb.prepare('SELECT * FROM cliente_endereco WHERE id = ?').get(id);
    if (!endereco) {
      return notFound(res, 'Endereço não encontrado');
    }
    
    coreDb.prepare('DELETE FROM cliente_endereco WHERE id = ?').run(id);
    
    auditService.logDelete('cliente_endereco', id, endereco, extractAuditInfo(req));
    
    logger.info('Endereço removido', { enderecoId: id });
    
    return success(res, null, 'Endereço removido com sucesso');
  } catch (error) {
    logger.error('Erro ao remover endereço:', error);
    throw error;
  }
}

module.exports = {
  criar,
  listar,
  atualizar,
  remover
};
