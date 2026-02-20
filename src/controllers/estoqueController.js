/**
 * BOUTIQUE DINIZ API - Controller de Estoque
 * Desenvolvido por Estúdio Atlas
 */

const db = require('../config/database');
const { success, successPaginated, created, notFound, validationError } = require('../utils/response');
const { getPaginationParams } = require('../utils/pagination');
const auditService = require('../services/auditService');
const { extractAuditInfo } = require('../middlewares/auth');
const logger = require('../utils/logger');

/**
 * POST /api/estoque/movimentos
 * Registra movimento de estoque
 */
function criarMovimento(req, res) {
  try {
    // Aceita parametro produto_variante_id (legado) ou variante_id para compatibilidade com banco de dados
    let { produto_variante_id, variante_id, tipo, quantidade, motivo, referencia_tipo, referencia_id, usuario_id } = req.body;
    // Priorizar variante_id se fornecido; caso contrário, usar produto_variante_id
    variante_id = variante_id || produto_variante_id;
    
    const coreDb = db.getCore();
    
    // Verificar se variante existe
    const variante = coreDb.prepare('SELECT * FROM produto_variante WHERE id = ?').get(variante_id);
    if (!variante) {
      return notFound(res, 'Variante de produto não encontrada');
    }
    
    // Calcular novo estoque
    let novoEstoque = variante.estoque;
    if (tipo === 'entrada') {
      novoEstoque += quantidade;
    } else if (tipo === 'saida') {
      novoEstoque -= quantidade;
      if (novoEstoque < 0) {
        return validationError(res, [{ field: 'quantidade', issue: 'Estoque insuficiente' }]);
      }
    } else if (tipo === 'ajuste') {
      novoEstoque = quantidade; // Ajuste define o valor absoluto
    }
    
    // Registrar movimento
    const result = coreDb.prepare(`
      INSERT INTO estoque_movimento (variante_id, tipo, quantidade, motivo, referencia_tipo, referencia_id, usuario_id)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(variante_id, tipo, quantidade, motivo || null, referencia_tipo || null, referencia_id || null, usuario_id || null);
    
    // Atualizar estoque da variante
    coreDb.prepare('UPDATE produto_variante SET estoque = ?, atualizado_em = datetime(\'now\') WHERE id = ?').run(novoEstoque, variante_id);
    
    const movimento = coreDb.prepare('SELECT * FROM estoque_movimento WHERE id = ?').get(result.lastInsertRowid);
    movimento.estoque_anterior = variante.estoque;
    movimento.estoque_atual = novoEstoque;
    
    auditService.logCreate('estoque_movimento', movimento.id, movimento, extractAuditInfo(req));
    
    logger.info('Movimento de estoque registrado', { movimentoId: movimento.id, tipo, quantidade });
    
    return created(res, movimento, 'Movimento registrado com sucesso');
  } catch (error) {
    logger.error('Erro ao registrar movimento:', error);
    throw error;
  }
}

/**
 * GET /api/estoque/movimentos
 * Lista movimentos de estoque
 */
function listarMovimentos(req, res) {
  try {
    const { page, pageSize, offset } = getPaginationParams(req.query);
    const { produto_variante_id, tipo, data_inicio, data_fim, usuario_id } = req.query;
    
    const coreDb = db.getCore();
    
    let sql = `
      SELECT em.*, pv.tamanho, pv.cor, p.nome as produto_nome
      FROM estoque_movimento em
      JOIN produto_variante pv ON em.variante_id = pv.id
      JOIN produto p ON pv.produto_id = p.id
      WHERE 1=1
    `;
    const params = [];
    
    if (produto_variante_id) {
      sql += ' AND em.variante_id = ?';
      params.push(produto_variante_id);
    }
    
    if (tipo) {
      sql += ' AND em.tipo = ?';
      params.push(tipo);
    }
    
    if (data_inicio) {
      sql += ' AND em.criado_em >= ?';
      params.push(data_inicio);
    }
    
    if (data_fim) {
      sql += ' AND em.criado_em <= ?';
      params.push(data_fim);
    }
    
    if (usuario_id) {
      sql += ' AND em.usuario_id = ?';
      params.push(usuario_id);
    }
    
    // Contar total
    const countSql = sql.replace(/SELECT em\.\*, pv\.tamanho, pv\.cor, p\.nome as produto_nome/, 'SELECT COUNT(*) as total');
    const { total } = coreDb.prepare(countSql).get(...params);
    
    // Buscar com paginação
    sql += ' ORDER BY em.criado_em DESC LIMIT ? OFFSET ?';
    params.push(pageSize, offset);
    
    const movimentos = coreDb.prepare(sql).all(...params);
    
    return successPaginated(res, movimentos, page, pageSize, total);
  } catch (error) {
    logger.error('Erro ao listar movimentos:', error);
    throw error;
  }
}

/**
 * GET /api/estoque/alertas
 * Lista produtos com estoque baixo
 */
function listarAlertas(req, res) {
  try {
    const coreDb = db.getCore();
    
    const alertas = coreDb.prepare(`
      SELECT pv.*, p.nome as produto_nome, p.sku
      FROM produto_variante pv
      JOIN produto p ON pv.produto_id = p.id
      WHERE pv.estoque <= pv.estoque_minimo AND pv.ativo = 1 AND p.ativo = 1
      ORDER BY (pv.estoque_minimo - pv.estoque) DESC
    `).all();
    
    return success(res, alertas, `${alertas.length} produto(s) com estoque baixo`);
  } catch (error) {
    logger.error('Erro ao listar alertas:', error);
    throw error;
  }
}

/**
 * GET /api/estoque/resumo
 * Resumo geral do estoque
 */
function resumo(req, res) {
  try {
    const coreDb = db.getCore();
    
    const totalProdutos = coreDb.prepare('SELECT COUNT(*) as total FROM produto WHERE ativo = 1').get().total;
    const totalVariantes = coreDb.prepare('SELECT COUNT(*) as total FROM produto_variante WHERE ativo = 1').get().total;
    const totalItens = coreDb.prepare('SELECT SUM(estoque) as total FROM produto_variante WHERE ativo = 1').get().total || 0;
    const alertas = coreDb.prepare(`
      SELECT COUNT(*) as total FROM produto_variante pv
      JOIN produto p ON pv.produto_id = p.id
      WHERE pv.estoque <= pv.estoque_minimo AND pv.ativo = 1 AND p.ativo = 1
    `).get().total;
    
    const movimentosHoje = coreDb.prepare(`
      SELECT 
        SUM(CASE WHEN tipo = 'entrada' THEN quantidade ELSE 0 END) as entradas,
        SUM(CASE WHEN tipo = 'saida' THEN quantidade ELSE 0 END) as saidas
      FROM estoque_movimento
      WHERE date(criado_em) = date('now')
    `).get();
    
    return success(res, {
      total_produtos: totalProdutos,
      total_variantes: totalVariantes,
      total_itens_estoque: totalItens,
      alertas_estoque_baixo: alertas,
      movimentos_hoje: {
        entradas: movimentosHoje.entradas || 0,
        saidas: movimentosHoje.saidas || 0
      }
    });
  } catch (error) {
    logger.error('Erro ao gerar resumo:', error);
    throw error;
  }
}

module.exports = {
  criarMovimento,
  listarMovimentos,
  listarAlertas,
  resumo
};
