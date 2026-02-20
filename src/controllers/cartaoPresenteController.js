/**
 * BOUTIQUE DINIZ API - Controller de Cartões Presente
 * Desenvolvido por Estúdio Atlas
 *
 * Este controlador implementa operações para criar, listar, buscar,
 * resgatar e remover cartões presente. Um cartão presente possui um
 * número único (16 dígitos), código de segurança (4 dígitos), valor
 * original, saldo atual, validade e status. Para resgatar parte do
 * saldo, o cliente precisa fornecer o número e o código de segurança.
 */

const db = require('../config/database');
const { success, successPaginated, created, notFound, conflict } = require('../utils/response');
const { getPaginationParams } = require('../utils/pagination');
const auditService = require('../services/auditService');
const { extractAuditInfo } = require('../middlewares/auth');
const logger = require('../utils/logger');
const crypto = require('crypto');

/**
 * Gera uma string numérica de tamanho definido usando bytes aleatórios.
 * É utilizada para gerar o número do cartão e o código de segurança.
 * @param {number} length
 * @returns {string}
 */
function gerarNumerosAleatorios(length) {
  const bytes = crypto.randomBytes(length);
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    out += (bytes[i] % 10).toString();
  }
  return out.padEnd(length, Math.floor(Math.random() * 10).toString());
}

/**
 * Cria um novo cartão presente.
 *
 * POST /api/cartoes
 */
function criar(req, res) {
  try {
    const { valor, validade, comprador_id } = req.body;
    if (!valor || !validade) {
      return res.status(400).json({
        success: false,
        message: 'Erro de validação',
        error: {
          code: 'VALIDATION_ERROR',
          details: [
            { field: !valor ? 'valor' : 'validade', issue: 'Campo obrigatório' }
          ]
        }
      });
    }
    const coreDb = db.getCore();
    // Gera números e códigos únicos
    function inserirCartao() {
      const numero = gerarNumerosAleatorios(16);
      const codigo = gerarNumerosAleatorios(4);
      // Verificar se já existe
      const existente = coreDb.prepare(`SELECT id FROM cartao_presente WHERE numero = ?`).get(numero);
      if (existente) {
        return inserirCartao();
      }
      const stmt = coreDb.prepare(`INSERT INTO cartao_presente (numero, codigo_seguranca, valor_original, saldo, validade, status, comprador_id) VALUES (?, ?, ?, ?, ?, 'ativo', ?)`);
      const info = stmt.run(numero, codigo, valor, valor, validade, comprador_id || null);
      const cartao = coreDb.prepare(`SELECT * FROM cartao_presente WHERE id = ?`).get(info.lastInsertRowid);
      auditService.logCreate('cartao_presente', cartao.id, cartao, extractAuditInfo(req));
      logger.info('Cartão presente criado', { cartaoId: cartao.id });
      return res.status(201).json({
        success: true,
        message: 'Cartão presente criado com sucesso',
        data: cartao
      });
    }
    return inserirCartao();
  } catch (error) {
    logger.error('Erro ao criar cartão presente:', error);
    throw error;
  }
}

/**
 * Lista cartões presente com paginação. Pode filtrar por comprador_id ou status.
 * GET /api/cartoes
 */
function listar(req, res) {
  try {
    const { page, pageSize, offset } = getPaginationParams(req.query);
    const { comprador_id, status } = req.query;
    const coreDb = db.getCore();
    let sql = `SELECT * FROM cartao_presente WHERE 1=1`;
    const params = [];
    if (comprador_id) {
      sql += ` AND comprador_id = ?`;
      params.push(comprador_id);
    }
    if (status) {
      sql += ` AND status = ?`;
      params.push(status);
    }
    // Contar total
    const countSql = sql.replace(/SELECT \*/, 'SELECT COUNT(*) as total');
    const { total } = coreDb.prepare(countSql).get(...params);
    sql += ` ORDER BY criado_em DESC LIMIT ? OFFSET ?`;
    params.push(pageSize, offset);
    const cartoes = coreDb.prepare(sql).all(...params);
    return successPaginated(res, cartoes, page, pageSize, total);
  } catch (error) {
    logger.error('Erro ao listar cartões presente:', error);
    throw error;
  }
}

/**
 * Busca cartão presente pelo número.
 * GET /api/cartoes/numero/:numero
 */
function buscarPorNumero(req, res) {
  try {
    const { numero } = req.params;
    const coreDb = db.getCore();
    const cartao = coreDb.prepare(`SELECT * FROM cartao_presente WHERE numero = ?`).get(numero);
    if (!cartao) {
      return notFound(res, 'Cartão presente não encontrado');
    }
    return success(res, cartao);
  } catch (error) {
    logger.error('Erro ao buscar cartão presente por número:', error);
    throw error;
  }
}

/**
 * Remove um cartão presente pelo ID.
 * DELETE /api/cartoes/:id
 */
function remover(req, res) {
  try {
    const { id } = req.params;
    const coreDb = db.getCore();
    const cartao = coreDb.prepare(`SELECT * FROM cartao_presente WHERE id = ?`).get(id);
    if (!cartao) {
      return notFound(res, 'Cartão presente não encontrado');
    }
    coreDb.prepare(`DELETE FROM cartao_presente WHERE id = ?`).run(id);
    auditService.logDelete('cartao_presente', id, cartao, extractAuditInfo(req));
    logger.info('Cartão presente removido', { cartaoId: id });
    return success(res, cartao, 'Cartão presente removido com sucesso');
  } catch (error) {
    logger.error('Erro ao remover cartão presente:', error);
    throw error;
  }
}

/**
 * Resgata saldo de um cartão presente.
 * POST /api/cartoes/resgatar
 */
function resgatar(req, res) {
  try {
    const { numero, codigo_seguranca, valor } = req.body;
    if (!numero || !codigo_seguranca || !valor) {
      return res.status(400).json({
        success: false,
        message: 'Erro de validação',
        error: {
          code: 'VALIDATION_ERROR',
          details: [
            { field: !numero ? 'numero' : !codigo_seguranca ? 'codigo_seguranca' : 'valor', issue: 'Campo obrigatório' }
          ]
        }
      });
    }
    const coreDb = db.getCore();
    const cartao = coreDb.prepare(`SELECT * FROM cartao_presente WHERE numero = ?`).get(numero);
    if (!cartao) {
      return notFound(res, 'Cartão presente não encontrado');
    }
    if (cartao.codigo_seguranca !== codigo_seguranca) {
      return conflict(res, 'Código de segurança inválido');
    }
    if (cartao.status !== 'ativo') {
      return conflict(res, `Cartão não está ativo (status atual: ${cartao.status})`);
    }
    const hoje = new Date();
    const validade = new Date(cartao.validade);
    if (hoje > validade) {
      // Atualiza status para expirado
      coreDb.prepare(`UPDATE cartao_presente SET status = 'expirado' WHERE id = ?`).run(cartao.id);
      auditService.logUpdate('cartao_presente', cartao.id, cartao, { ...cartao, status: 'expirado' }, extractAuditInfo(req));
      return conflict(res, 'Cartão presente expirado');
    }
    const valorResgate = parseFloat(valor);
    if (valorResgate <= 0) {
      return conflict(res, 'Valor de resgate deve ser maior que zero');
    }
    if (valorResgate > cartao.saldo) {
      return conflict(res, 'Valor de resgate maior que saldo disponível');
    }
    const saldoNovo = cartao.saldo - valorResgate;
    const novoStatus = saldoNovo === 0 ? 'utilizado' : 'ativo';
    // Atualiza registro
    coreDb.prepare(`UPDATE cartao_presente SET saldo = ?, status = ? WHERE id = ?`).run(saldoNovo, novoStatus, cartao.id);
    const cartaoAtualizado = { ...cartao, saldo: saldoNovo, status: novoStatus };
    auditService.logUpdate('cartao_presente', cartao.id, cartao, cartaoAtualizado, extractAuditInfo(req));
    logger.info('Cartão presente resgatado', { cartaoId: cartao.id, valor: valorResgate });
    return success(res, cartaoAtualizado, 'Resgate realizado com sucesso');
  } catch (error) {
    logger.error('Erro ao resgatar cartão presente:', error);
    throw error;
  }
}

module.exports = {
  criar,
  listar,
  buscarPorNumero,
  remover,
  resgatar
};