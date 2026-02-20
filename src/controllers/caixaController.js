/**
 * BOUTIQUE DINIZ API - Controller de Caixa
 * Desenvolvido por Estúdio Atlas
 *
 * Fluxo do caixa da loja:
 *   1. Operadora abre o caixa  → POST /api/caixa/abrir        → status: 'aberto'
 *   2. Lançamentos do dia      → POST /api/caixa/lancamentos  → vinculados à sessão
 *   3. Operadora fecha o caixa → POST /api/caixa/:id/fechar   → status: 'pendente_aprovacao'
 *   4. Financeiro corrige/aprova → via financeiroController   → status: 'aprovado' | 'rejeitado'
 */

const db = require('../config/database');
const {
  success, successPaginated, created, notFound, conflict, validationError
} = require('../utils/response');
const { getPaginationParams } = require('../utils/pagination');
const auditService = require('../services/auditService');
const { extractAuditInfo } = require('../middlewares/auth');
const logger = require('../utils/logger');

// ============================================
// SESSÕES DE CAIXA
// ============================================

/**
 * POST /api/caixa/abrir
 * Abre uma sessão de caixa formal com registro de quem abriu e valor inicial
 */
function abrirCaixa(req, res) {
  try {
    const { filial_id, usuario_id, valor_abertura, observacoes } = req.body;

    if (!filial_id || !usuario_id) {
      return validationError(res, [
        { field: 'filial_id', issue: 'Filial é obrigatória' },
        { field: 'usuario_id', issue: 'Usuário é obrigatório' }
      ]);
    }

    const coreDb = db.getCore();

    // REGRA ATUALIZADA: Só bloqueia se já existir um caixa com status 'aberto' hoje.
    // Caixas com status 'pendente_aprovacao' NÃO bloqueiam a abertura de um novo caixa.
    const caixaAberto = coreDb.prepare(`
      SELECT id FROM caixa_sessao
      WHERE filial_id = ?
        AND status = 'aberto'
        AND date(aberto_em) = date('now')
    `).get(filial_id);

    if (caixaAberto) {
      return conflict(res, 'Já existe um caixa aberto para esta filial hoje. Feche-o antes de abrir outro.');
    }

    const result = coreDb.prepare(`
      INSERT INTO caixa_sessao (filial_id, usuario_abertura_id, valor_abertura, observacoes_abertura, status)
      VALUES (?, ?, ?, ?, 'aberto')
    `).run(filial_id, usuario_id, valor_abertura || 0, observacoes || null);

    const sessao = coreDb.prepare('SELECT * FROM caixa_sessao WHERE id = ?').get(result.lastInsertRowid);

    auditService.logCreate('caixa_sessao', sessao.id, sessao, extractAuditInfo(req));
    logger.info('Caixa aberto', { sessaoId: sessao.id, filialId: filial_id, usuarioId: usuario_id });

    return created(res, sessao, 'Caixa aberto com sucesso');
  } catch (error) {
    logger.error('Erro ao abrir caixa:', error);
    throw error;
  }
}

/**
 * POST /api/caixa/:sessaoId/fechar
 * Operadora fecha o caixa — gera resumo automático e envia para aprovação do financeiro
 */
function fecharCaixa(req, res) {
  try {
    const { sessaoId } = req.params;
    const { usuario_id, valor_fechamento_declarado, observacoes } = req.body;

    const coreDb = db.getCore();

    const sessao = coreDb.prepare('SELECT * FROM caixa_sessao WHERE id = ?').get(sessaoId);
    if (!sessao) return notFound(res, 'Sessão de caixa não encontrada');

    if (sessao.status !== 'aberto') {
      return conflict(res, 'Caixa não pode ser fechado — status atual: ' + sessao.status);
    }

    const totais = coreDb.prepare(`
      SELECT
        COALESCE(SUM(CASE WHEN tipo = 'entrada' THEN valor ELSE 0 END), 0) AS total_entradas,
        COALESCE(SUM(CASE WHEN tipo = 'saida'   THEN valor ELSE 0 END), 0) AS total_saidas,
        COUNT(*) AS total_lancamentos
      FROM caixa_lancamento
      WHERE sessao_id = ?
    `).get(sessaoId);

    const saldoCalculado = (sessao.valor_abertura || 0) + totais.total_entradas - totais.total_saidas;
    const diferenca = valor_fechamento_declarado != null
      ? parseFloat((valor_fechamento_declarado - saldoCalculado).toFixed(2))
      : null;

    coreDb.prepare(`
      UPDATE caixa_sessao SET
        usuario_fechamento_id      = ?,
        fechado_em                 = datetime('now'),
        valor_fechamento_declarado = ?,
        total_entradas             = ?,
        total_saidas               = ?,
        saldo_calculado            = ?,
        diferenca                  = ?,
        observacoes_fechamento     = ?,
        status                     = 'pendente_aprovacao'
      WHERE id = ?
    `).run(
      usuario_id,
      valor_fechamento_declarado != null ? valor_fechamento_declarado : null,
      totais.total_entradas,
      totais.total_saidas,
      saldoCalculado,
      diferenca,
      observacoes || null,
      sessaoId
    );

    const sessaoAtualizada = coreDb.prepare('SELECT * FROM caixa_sessao WHERE id = ?').get(sessaoId);

    auditService.logStatusChange('caixa_sessao', sessaoId, 'aberto', 'pendente_aprovacao', extractAuditInfo(req));
    logger.info('Caixa fechado, aguardando aprovação', { sessaoId, saldoCalculado, diferenca });

    return success(res, sessaoAtualizada, 'Caixa fechado. Aguardando aprovação do financeiro');
  } catch (error) {
    logger.error('Erro ao fechar caixa:', error);
    throw error;
  }
}

/**
 * GET /api/caixa/sessoes
 * Lista sessões de caixa com filtros
 */
function listarSessoes(req, res) {
  try {
    const { page, pageSize, offset } = getPaginationParams(req.query);
    const { filial_id, status, data_inicio, data_fim } = req.query;

    const coreDb = db.getCore();

    let sql = `
      SELECT cs.*, f.nome AS filial_nome
      FROM caixa_sessao cs
      JOIN filial f ON cs.filial_id = f.id
      WHERE 1=1
    `;
    const params = [];

    if (filial_id)   { sql += ' AND cs.filial_id = ?';              params.push(filial_id); }
    if (status)      { sql += ' AND cs.status = ?';                 params.push(status); }
    if (data_inicio) { sql += ' AND date(cs.aberto_em) >= ?';       params.push(data_inicio); }
    if (data_fim)    { sql += ' AND date(cs.aberto_em) <= ?';       params.push(data_fim); }

    let sessaoWherePart = sql.substring(sql.indexOf('WHERE'));
    const countSql = `SELECT COUNT(*) as total FROM caixa_sessao cs
      JOIN filial f ON cs.filial_id = f.id
      ${sessaoWherePart}`;
    const countResult = coreDb.prepare(countSql).get(...params);
    const total = countResult ? countResult.total : 0;

    sql += ' ORDER BY cs.aberto_em DESC LIMIT ? OFFSET ?';
    params.push(pageSize, offset);

    const sessoes = coreDb.prepare(sql).all(...params);

    return successPaginated(res, sessoes, page, pageSize, total);
  } catch (error) {
    logger.error('Erro ao listar sessões:', error);
    throw error;
  }
}

/**
 * GET /api/caixa/sessoes/:id
 * Detalhe completo de uma sessão com todos os seus lançamentos
 */
function buscarSessao(req, res) {
  try {
    const { id } = req.params;
    const coreDb = db.getCore();

    const sessao = coreDb.prepare(`
      SELECT cs.*, f.nome AS filial_nome
      FROM caixa_sessao cs
      JOIN filial f ON cs.filial_id = f.id
      WHERE cs.id = ?
    `).get(id);

    if (!sessao) return notFound(res, 'Sessão de caixa não encontrada');

    // Buscar lançamentos completos da sessão
    const lancamentos = coreDb.prepare(`
      SELECT cl.*, c.nome_completo AS cliente_nome,
             p.nome AS produto_nome, pv.tamanho, pv.cor
      FROM caixa_lancamento cl
      LEFT JOIN cliente c ON cl.cliente_id = c.id
      LEFT JOIN produto_variante pv ON cl.produto_variante_id = pv.id
      LEFT JOIN produto p ON pv.produto_id = p.id
      WHERE cl.sessao_id = ?
      ORDER BY cl.criado_em ASC
    `).all(id);

    // Calcular totais em tempo real caso não estejam preenchidos
    const totalEntradas = lancamentos
      .filter(l => l.tipo === 'entrada')
      .reduce((sum, l) => sum + (l.valor || 0), 0);
    const totalSaidas = lancamentos
      .filter(l => l.tipo === 'saida')
      .reduce((sum, l) => sum + (l.valor || 0), 0);
    const saldoCalculado = (sessao.valor_abertura || 0) + totalEntradas - totalSaidas;

    return success(res, {
      ...sessao,
      total_entradas_calculado: parseFloat(totalEntradas.toFixed(2)),
      total_saidas_calculado: parseFloat(totalSaidas.toFixed(2)),
      saldo_calculado_tempo_real: parseFloat(saldoCalculado.toFixed(2)),
      total_lancamentos: lancamentos.length,
      lancamentos
    });
  } catch (error) {
    logger.error('Erro ao buscar sessão:', error);
    throw error;
  }
}

// ============================================
// LANÇAMENTOS
// ============================================

/**
 * POST /api/caixa/lancamentos
 * Cria lançamento vinculado automaticamente à sessão aberta da filial
 */
function criar(req, res) {
  try {
    const {
      filial_id, sessao_id, pedido_id, produto_variante_id, tipo, descricao,
      valor, forma_pagamento, parcelas, cliente_id, usuario_vendedor_id, origem
    } = req.body;

    const coreDb = db.getCore();

    let sessaoAtiva = null;
    if (sessao_id) {
      sessaoAtiva = coreDb.prepare(
        "SELECT id FROM caixa_sessao WHERE id = ? AND status = 'aberto'"
      ).get(sessao_id);
    } else if (filial_id) {
      sessaoAtiva = coreDb.prepare(
        "SELECT id FROM caixa_sessao WHERE filial_id = ? AND status = 'aberto' AND date(aberto_em) = date('now')"
      ).get(filial_id);
    }

    const sessaoIdFinal = sessaoAtiva ? sessaoAtiva.id : null;

    const result = coreDb.prepare(`
      INSERT INTO caixa_lancamento (
        sessao_id, filial_id, pedido_id, produto_variante_id, tipo, descricao, valor,
        forma_pagamento, parcelas, cliente_id, usuario_vendedor_id, origem
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      sessaoIdFinal,
      filial_id,
      pedido_id || null,
      produto_variante_id || null,
      tipo,
      descricao,
      valor,
      forma_pagamento || null,
      parcelas || null,
      cliente_id || null,
      usuario_vendedor_id,
      origem
    );

    const lancamento = coreDb.prepare('SELECT * FROM caixa_lancamento WHERE id = ?').get(result.lastInsertRowid);

    auditService.logCreate('caixa_lancamento', lancamento.id, lancamento, extractAuditInfo(req));
    logger.info('Lançamento criado', { lancamentoId: lancamento.id, tipo, valor, sessaoId: sessaoIdFinal });

    return created(res, lancamento, 'Lançamento criado com sucesso');
  } catch (error) {
    logger.error('Erro ao criar lançamento:', error);
    throw error;
  }
}

/**
 * GET /api/caixa/lancamentos
 */
function listar(req, res) {
  try {
    const { page, pageSize, offset } = getPaginationParams(req.query);
    const { filial_id, sessao_id, tipo, data_inicio, data_fim, usuario_id, origem } = req.query;

    const coreDb = db.getCore();

    let sql = `
      SELECT cl.*, f.nome AS filial_nome, c.nome_completo AS cliente_nome
      FROM caixa_lancamento cl
      JOIN filial f ON cl.filial_id = f.id
      LEFT JOIN cliente c ON cl.cliente_id = c.id
      WHERE 1=1
    `;
    const params = [];

    if (filial_id)   { sql += ' AND cl.filial_id = ?';             params.push(filial_id); }
    if (sessao_id)   { sql += ' AND cl.sessao_id = ?';             params.push(sessao_id); }
    if (tipo)        { sql += ' AND cl.tipo = ?';                  params.push(tipo); }
    if (data_inicio) { sql += ' AND cl.criado_em >= ?';            params.push(data_inicio); }
    if (data_fim)    { sql += ' AND cl.criado_em <= ?';            params.push(data_fim); }
    if (usuario_id)  { sql += ' AND cl.usuario_vendedor_id = ?';   params.push(usuario_id); }
    if (origem)      { sql += ' AND cl.origem = ?';                params.push(origem); }

    // Contar total — query independente para evitar falha de regex
    let caixaWherePart = sql.substring(sql.indexOf('WHERE'));
    const countSql = `SELECT COUNT(*) as total FROM caixa_lancamento cl
      JOIN filial f ON cl.filial_id = f.id
      LEFT JOIN cliente c ON cl.cliente_id = c.id
      ${caixaWherePart}`;
    const countResult = coreDb.prepare(countSql).get(...params);
    const total = countResult ? countResult.total : 0;

    sql += ' ORDER BY cl.criado_em DESC LIMIT ? OFFSET ?';
    params.push(pageSize, offset);

    const lancamentos = coreDb.prepare(sql).all(...params);

    return successPaginated(res, lancamentos, page, pageSize, total);
  } catch (error) {
    logger.error('Erro ao listar lançamentos:', error);
    throw error;
  }
}

/**
 * PUT /api/caixa/lancamentos/:id
 * Edição permitida enquanto a sessão não estiver 'aprovado'
 */
function atualizar(req, res) {
  try {
    const { id } = req.params;
    const { descricao, valor, forma_pagamento, parcelas, tipo } = req.body;

    const coreDb = db.getCore();

    const lancamentoAntes = coreDb.prepare('SELECT * FROM caixa_lancamento WHERE id = ?').get(id);
    if (!lancamentoAntes) return notFound(res, 'Lançamento não encontrado');

    if (lancamentoAntes.sessao_id) {
      const sessao = coreDb.prepare('SELECT status FROM caixa_sessao WHERE id = ?').get(lancamentoAntes.sessao_id);
      if (sessao && sessao.status === 'aprovado') {
        return conflict(res, 'Não é possível editar lançamentos de uma sessão já aprovada');
      }
    }

    const updates = [];
    const params = [];

    if (descricao     !== undefined) { updates.push('descricao = ?');       params.push(descricao); }
    if (valor         !== undefined) { updates.push('valor = ?');           params.push(valor); }
    if (forma_pagamento !== undefined) { updates.push('forma_pagamento = ?'); params.push(forma_pagamento); }
    if (parcelas      !== undefined) { updates.push('parcelas = ?');        params.push(parcelas); }
    if (tipo          !== undefined) { updates.push('tipo = ?');            params.push(tipo); }

    if (updates.length > 0) {
      params.push(id);
      coreDb.prepare('UPDATE caixa_lancamento SET ' + updates.join(', ') + ' WHERE id = ?').run(...params);
    }

    const lancamentoDepois = coreDb.prepare('SELECT * FROM caixa_lancamento WHERE id = ?').get(id);

    auditService.logUpdate('caixa_lancamento', id, lancamentoAntes, lancamentoDepois, extractAuditInfo(req));
    logger.info('Lançamento atualizado', { lancamentoId: id });

    return success(res, lancamentoDepois, 'Lançamento atualizado com sucesso');
  } catch (error) {
    logger.error('Erro ao atualizar lançamento:', error);
    throw error;
  }
}

/**
 * DELETE /api/caixa/lancamentos/:id
 */
function remover(req, res) {
  try {
    const { id } = req.params;
    const coreDb = db.getCore();

    const lancamento = coreDb.prepare('SELECT * FROM caixa_lancamento WHERE id = ?').get(id);
    if (!lancamento) return notFound(res, 'Lançamento não encontrado');

    if (lancamento.sessao_id) {
      const sessao = coreDb.prepare('SELECT status FROM caixa_sessao WHERE id = ?').get(lancamento.sessao_id);
      if (sessao && sessao.status === 'aprovado') {
        return conflict(res, 'Não é possível remover lançamentos de uma sessão já aprovada');
      }
    }

    coreDb.prepare('DELETE FROM caixa_lancamento WHERE id = ?').run(id);

    auditService.logDelete('caixa_lancamento', id, lancamento, extractAuditInfo(req));
    logger.info('Lançamento removido', { lancamentoId: id });

    return success(res, null, 'Lançamento removido com sucesso');
  } catch (error) {
    logger.error('Erro ao remover lançamento:', error);
    throw error;
  }
}

/**
 * GET /api/caixa/resumo
 */
function resumo(req, res) {
  try {
    const { filial_id, data_inicio, data_fim } = req.query;
    const coreDb = db.getCore();

    let sql = 'SELECT * FROM caixa_lancamento WHERE 1=1';
    const params = [];

    if (filial_id)   { sql += ' AND filial_id = ?';  params.push(filial_id); }
    if (data_inicio) { sql += ' AND criado_em >= ?'; params.push(data_inicio); }
    if (data_fim)    { sql += ' AND criado_em <= ?'; params.push(data_fim); }

    const lancamentos = coreDb.prepare(sql).all(...params);

    let entradas = 0;
    let saidas = 0;
    const porFormaPagamento = {};
    const porOrigem = {};

    lancamentos.forEach(l => {
      if (l.tipo === 'entrada') {
        entradas += l.valor;
        porOrigem[l.origem] = (porOrigem[l.origem] || 0) + l.valor;
      } else {
        saidas += l.valor;
      }
      if (l.forma_pagamento) {
        porFormaPagamento[l.forma_pagamento] = (porFormaPagamento[l.forma_pagamento] || 0) + l.valor;
      }
    });

    return success(res, {
      periodo: { inicio: data_inicio || 'Todos', fim: data_fim || 'Todos' },
      filial_id: filial_id || 'Todas',
      total_lancamentos: lancamentos.length,
      entradas: parseFloat(entradas.toFixed(2)),
      saidas: parseFloat(saidas.toFixed(2)),
      saldo: parseFloat((entradas - saidas).toFixed(2)),
      por_forma_pagamento: porFormaPagamento,
      por_origem: porOrigem
    });
  } catch (error) {
    logger.error('Erro ao gerar resumo:', error);
    throw error;
  }
}

module.exports = {
  abrirCaixa,
  fecharCaixa,
  listarSessoes,
  buscarSessao,
  criar,
  listar,
  atualizar,
  remover,
  resumo
};
