/**
 * BOUTIQUE DINIZ API - Controller Financeiro
 * Desenvolvido por Estúdio Atlas
 *
 * Responsabilidades:
 *   1. Aprovação/rejeição de fechamentos de caixa das lojas
 *      → O financeiro revisa, corrige lançamentos e homologa cada sessão
 *   2. Contas a Pagar (fornecedores, despesas, etc.)
 *   3. Contas a Receber (além das vendas: reembolsos, acordos, etc.)
 *   4. Fechamento Financeiro Consolidado por período (multi-filiais)
 *      → Agrega caixas aprovados + contas a pagar/receber
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
// APROVAÇÃO DE CAIXAS
// ============================================

/**
 * GET /api/financeiro/caixas-pendentes
 * Lista todas as sessões de caixa aguardando aprovação do financeiro
 */
function listarCaixasPendentes(req, res) {
  try {
    const { page, pageSize, offset } = getPaginationParams(req.query);
    const { filial_id, data_inicio, data_fim } = req.query;

    const coreDb = db.getCore();

    let sql = `
      SELECT cs.*, f.nome AS filial_nome
      FROM caixa_sessao cs
      JOIN filial f ON cs.filial_id = f.id
      WHERE cs.status = 'pendente_aprovacao'
    `;
    const params = [];

    if (filial_id)   { sql += ' AND cs.filial_id = ?';        params.push(filial_id); }
    if (data_inicio) { sql += ' AND date(cs.fechado_em) >= ?'; params.push(data_inicio); }
    if (data_fim)    { sql += ' AND date(cs.fechado_em) <= ?'; params.push(data_fim); }

    let finCaixaWhere = sql.substring(sql.indexOf('WHERE'));
    const countSql = `SELECT COUNT(*) as total FROM caixa_sessao cs
      JOIN filial f ON cs.filial_id = f.id
      ${finCaixaWhere}`;
    const countResult = coreDb.prepare(countSql).get(...params);
    const total = countResult ? countResult.total : 0;

    sql += ' ORDER BY cs.fechado_em ASC LIMIT ? OFFSET ?';
    params.push(pageSize, offset);

    const sessoes = coreDb.prepare(sql).all(...params);

    return successPaginated(res, sessoes, page, pageSize, total,
      total + ' caixa(s) aguardando aprovação');
  } catch (error) {
    logger.error('Erro ao listar caixas pendentes:', error);
    throw error;
  }
}

/**
 * GET /api/financeiro/caixas/:sessaoId
 * Detalhe completo de uma sessão de caixa para revisão do financeiro
 * Inclui todos os lançamentos e eventuais correções já feitas
 */
function revisarCaixa(req, res) {
  try {
    const { sessaoId } = req.params;
    const coreDb = db.getCore();

    const sessao = coreDb.prepare(`
      SELECT cs.*, f.nome AS filial_nome
      FROM caixa_sessao cs
      JOIN filial f ON cs.filial_id = f.id
      WHERE cs.id = ?
    `).get(sessaoId);

    if (!sessao) return notFound(res, 'Sessão de caixa não encontrada');

    const lancamentos = coreDb.prepare(`
      SELECT cl.*, c.nome_completo AS cliente_nome
      FROM caixa_lancamento cl
      LEFT JOIN cliente c ON cl.cliente_id = c.id
      WHERE cl.sessao_id = ?
      ORDER BY cl.criado_em ASC
    `).all(sessaoId);

    // Recalcular totais em tempo real (pode ter sido editado pelo financeiro)
    let totalEntradas = 0;
    let totalSaidas = 0;
    const porFormaPagamento = {};

    lancamentos.forEach(l => {
      if (l.tipo === 'entrada') totalEntradas += l.valor;
      else totalSaidas += l.valor;
      if (l.forma_pagamento) {
        porFormaPagamento[l.forma_pagamento] = (porFormaPagamento[l.forma_pagamento] || 0) + l.valor;
      }
    });

    const saldoRecalculado = (sessao.valor_abertura || 0) + totalEntradas - totalSaidas;

    return success(res, {
      sessao,
      lancamentos,
      recalculo: {
        total_entradas:    parseFloat(totalEntradas.toFixed(2)),
        total_saidas:      parseFloat(totalSaidas.toFixed(2)),
        saldo_recalculado: parseFloat(saldoRecalculado.toFixed(2)),
        diferenca_vs_declarado: sessao.valor_fechamento_declarado != null
          ? parseFloat((sessao.valor_fechamento_declarado - saldoRecalculado).toFixed(2))
          : null,
        por_forma_pagamento: porFormaPagamento
      }
    });
  } catch (error) {
    logger.error('Erro ao revisar caixa:', error);
    throw error;
  }
}

/**
 * POST /api/financeiro/caixas/:sessaoId/aprovar
 * Financeiro aprova o fechamento — atualiza os totais com os valores revisados
 */
function aprovarCaixa(req, res) {
  try {
    const { sessaoId } = req.params;
    const { usuario_financeiro_id, observacoes } = req.body;

    const coreDb = db.getCore();

    const sessao = coreDb.prepare('SELECT * FROM caixa_sessao WHERE id = ?').get(sessaoId);
    if (!sessao) return notFound(res, 'Sessão de caixa não encontrada');

    if (sessao.status !== 'pendente_aprovacao') {
      return conflict(res, 'Sessão não está pendente de aprovação — status atual: ' + sessao.status);
    }

    // Recalcular totais finais com lançamentos atuais (financeiro pode ter editado)
    const totais = coreDb.prepare(`
      SELECT
        COALESCE(SUM(CASE WHEN tipo = 'entrada' THEN valor ELSE 0 END), 0) AS total_entradas,
        COALESCE(SUM(CASE WHEN tipo = 'saida'   THEN valor ELSE 0 END), 0) AS total_saidas
      FROM caixa_lancamento WHERE sessao_id = ?
    `).get(sessaoId);

    const saldoFinal = (sessao.valor_abertura || 0) + totais.total_entradas - totais.total_saidas;

    coreDb.prepare(`
      UPDATE caixa_sessao SET
        status                  = 'aprovado',
        usuario_aprovacao_id    = ?,
        aprovado_em             = datetime('now'),
        observacoes_aprovacao   = ?,
        total_entradas          = ?,
        total_saidas            = ?,
        saldo_calculado         = ?
      WHERE id = ?
    `).run(
      usuario_financeiro_id || null,
      observacoes || null,
      totais.total_entradas,
      totais.total_saidas,
      saldoFinal,
      sessaoId
    );

    const sessaoAprovada = coreDb.prepare('SELECT * FROM caixa_sessao WHERE id = ?').get(sessaoId);

    auditService.logStatusChange('caixa_sessao', sessaoId, 'pendente_aprovacao', 'aprovado', extractAuditInfo(req));
    logger.info('Caixa aprovado pelo financeiro', { sessaoId, saldoFinal, usuarioFinanceiro: usuario_financeiro_id });

    return success(res, sessaoAprovada, 'Fechamento de caixa aprovado com sucesso');
  } catch (error) {
    logger.error('Erro ao aprovar caixa:', error);
    throw error;
  }
}

/**
 * POST /api/financeiro/caixas/:sessaoId/rejeitar
 * Financeiro rejeita o fechamento — devolve o caixa para status 'aberto' para correção
 */
function rejeitarCaixa(req, res) {
  try {
    const { sessaoId } = req.params;
    const { usuario_financeiro_id, motivo } = req.body;

    if (!motivo) {
      return validationError(res, [{ field: 'motivo', issue: 'O motivo da rejeição é obrigatório' }]);
    }

    const coreDb = db.getCore();

    const sessao = coreDb.prepare('SELECT * FROM caixa_sessao WHERE id = ?').get(sessaoId);
    if (!sessao) return notFound(res, 'Sessão de caixa não encontrada');

    if (sessao.status !== 'pendente_aprovacao') {
      return conflict(res, 'Sessão não está pendente de aprovação');
    }

    // Devolve para 'aberto' para que a operadora corrija e feche novamente
    coreDb.prepare(`
      UPDATE caixa_sessao SET
        status                = 'aberto',
        fechado_em            = NULL,
        usuario_fechamento_id = NULL,
        observacoes_fechamento = ?,
        total_entradas        = NULL,
        total_saidas          = NULL,
        saldo_calculado       = NULL,
        diferenca             = NULL
      WHERE id = ?
    `).run('REJEITADO PELO FINANCEIRO: ' + motivo, sessaoId);

    const sessaoAtualizada = coreDb.prepare('SELECT * FROM caixa_sessao WHERE id = ?').get(sessaoId);

    auditService.logStatusChange('caixa_sessao', sessaoId, 'pendente_aprovacao', 'aberto', extractAuditInfo(req));
    logger.warn('Caixa rejeitado pelo financeiro', { sessaoId, motivo, usuarioFinanceiro: usuario_financeiro_id });

    return success(res, sessaoAtualizada, 'Fechamento rejeitado. Caixa reaberto para correção pela operadora');
  } catch (error) {
    logger.error('Erro ao rejeitar caixa:', error);
    throw error;
  }
}

// ============================================
// CONTAS A PAGAR
// ============================================

/**
 * POST /api/financeiro/contas-pagar
 * Registra uma conta a pagar (fornecedor, despesa operacional, etc.)
 */
function criarContaPagar(req, res) {
  try {
    const {
      filial_id, fornecedor_id, descricao, valor, data_vencimento,
      forma_pagamento, numero_documento, observacoes, usuario_id
    } = req.body;

    if (!descricao || !valor || !data_vencimento) {
      return validationError(res, [
        { field: 'descricao',       issue: 'Descrição é obrigatória' },
        { field: 'valor',           issue: 'Valor é obrigatório' },
        { field: 'data_vencimento', issue: 'Data de vencimento é obrigatória' }
      ]);
    }

    const coreDb = db.getCore();

    const result = coreDb.prepare(`
      INSERT INTO financeiro_conta_pagar (
        filial_id, fornecedor_id, descricao, valor, data_vencimento,
        forma_pagamento, numero_documento, observacoes, criado_por_usuario_id
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      filial_id || null,
      fornecedor_id || null,
      descricao,
      valor,
      data_vencimento,
      forma_pagamento || null,
      numero_documento || null,
      observacoes || null,
      usuario_id || null
    );

    const conta = coreDb.prepare('SELECT * FROM financeiro_conta_pagar WHERE id = ?').get(result.lastInsertRowid);

    auditService.logCreate('financeiro_conta_pagar', conta.id, conta, extractAuditInfo(req));
    logger.info('Conta a pagar criada', { contaId: conta.id, valor, descricao });

    return created(res, conta, 'Conta a pagar registrada com sucesso');
  } catch (error) {
    logger.error('Erro ao criar conta a pagar:', error);
    throw error;
  }
}

/**
 * GET /api/financeiro/contas-pagar
 * Lista contas a pagar com filtros
 */
function listarContasPagar(req, res) {
  try {
    const { page, pageSize, offset } = getPaginationParams(req.query);
    const { filial_id, status, fornecedor_id, vencimento_inicio, vencimento_fim } = req.query;

    const coreDb = db.getCore();

    let sql = `
      SELECT cp.*,
             f.nome  AS filial_nome,
             fo.nome_fantasia AS fornecedor_nome
      FROM financeiro_conta_pagar cp
      LEFT JOIN filial f     ON cp.filial_id     = f.id
      LEFT JOIN fornecedor fo ON cp.fornecedor_id = fo.id
      WHERE 1=1
    `;
    const params = [];

    if (filial_id)        { sql += ' AND cp.filial_id = ?';                    params.push(filial_id); }
    if (status)           { sql += ' AND cp.status = ?';                       params.push(status); }
    if (fornecedor_id)    { sql += ' AND cp.fornecedor_id = ?';                params.push(fornecedor_id); }
    if (vencimento_inicio){ sql += ' AND cp.data_vencimento >= ?';             params.push(vencimento_inicio); }
    if (vencimento_fim)   { sql += ' AND cp.data_vencimento <= ?';             params.push(vencimento_fim); }

    let cpWhere = sql.substring(sql.indexOf('WHERE'));
    const countSql = `SELECT COUNT(*) as total FROM financeiro_conta_pagar cp
      LEFT JOIN filial f ON cp.filial_id = f.id
      LEFT JOIN fornecedor fo ON cp.fornecedor_id = fo.id
      ${cpWhere}`;
    const countResult = coreDb.prepare(countSql).get(...params);
    const total = countResult ? countResult.total : 0;

    sql += ' ORDER BY cp.data_vencimento ASC LIMIT ? OFFSET ?';
    params.push(pageSize, offset);

    const contas = coreDb.prepare(sql).all(...params);

    return successPaginated(res, contas, page, pageSize, total);
  } catch (error) {
    logger.error('Erro ao listar contas a pagar:', error);
    throw error;
  }
}

/**
 * PUT /api/financeiro/contas-pagar/:id
 * Atualiza dados da conta a pagar (enquanto não estiver paga)
 */
function atualizarContaPagar(req, res) {
  try {
    const { id } = req.params;
    const { descricao, valor, data_vencimento, forma_pagamento, numero_documento, observacoes } = req.body;

    const coreDb = db.getCore();

    const contaAntes = coreDb.prepare('SELECT * FROM financeiro_conta_pagar WHERE id = ?').get(id);
    if (!contaAntes) return notFound(res, 'Conta a pagar não encontrada');

    if (contaAntes.status === 'pago') {
      return conflict(res, 'Não é possível editar uma conta já paga');
    }

    const updates = [];
    const params = [];

    if (descricao         !== undefined) { updates.push('descricao = ?');         params.push(descricao); }
    if (valor             !== undefined) { updates.push('valor = ?');             params.push(valor); }
    if (data_vencimento   !== undefined) { updates.push('data_vencimento = ?');   params.push(data_vencimento); }
    if (forma_pagamento   !== undefined) { updates.push('forma_pagamento = ?');   params.push(forma_pagamento); }
    if (numero_documento  !== undefined) { updates.push('numero_documento = ?');  params.push(numero_documento); }
    if (observacoes       !== undefined) { updates.push('observacoes = ?');       params.push(observacoes); }

    if (updates.length > 0) {
      params.push(id);
      coreDb.prepare('UPDATE financeiro_conta_pagar SET ' + updates.join(', ') + ' WHERE id = ?').run(...params);
    }

    const contaDepois = coreDb.prepare('SELECT * FROM financeiro_conta_pagar WHERE id = ?').get(id);

    auditService.logUpdate('financeiro_conta_pagar', id, contaAntes, contaDepois, extractAuditInfo(req));

    return success(res, contaDepois, 'Conta a pagar atualizada com sucesso');
  } catch (error) {
    logger.error('Erro ao atualizar conta a pagar:', error);
    throw error;
  }
}

/**
 * PATCH /api/financeiro/contas-pagar/:id/baixar
 * Registra o pagamento (baixa) de uma conta a pagar
 */
function baixarContaPagar(req, res) {
  try {
    const { id } = req.params;
    const { data_pagamento, valor_pago, forma_pagamento, usuario_id, observacoes } = req.body;

    const coreDb = db.getCore();

    const conta = coreDb.prepare('SELECT * FROM financeiro_conta_pagar WHERE id = ?').get(id);
    if (!conta) return notFound(res, 'Conta a pagar não encontrada');

    if (conta.status === 'pago') {
      return conflict(res, 'Conta já foi baixada');
    }

    coreDb.prepare(`
      UPDATE financeiro_conta_pagar SET
        status         = 'pago',
        data_pagamento = ?,
        valor_pago     = ?,
        forma_pagamento = COALESCE(?, forma_pagamento),
        pago_por_usuario_id = ?,
        observacoes    = COALESCE(?, observacoes)
      WHERE id = ?
    `).run(
      data_pagamento || new Date().toISOString().split('T')[0],
      valor_pago || conta.valor,
      forma_pagamento || null,
      usuario_id || null,
      observacoes || null,
      id
    );

    const contaBaixada = coreDb.prepare('SELECT * FROM financeiro_conta_pagar WHERE id = ?').get(id);

    auditService.logStatusChange('financeiro_conta_pagar', id, 'pendente', 'pago', extractAuditInfo(req));
    logger.info('Conta a pagar baixada', { contaId: id, valorPago: valor_pago || conta.valor });

    return success(res, contaBaixada, 'Pagamento registrado com sucesso');
  } catch (error) {
    logger.error('Erro ao baixar conta a pagar:', error);
    throw error;
  }
}

// ============================================
// CONTAS A RECEBER
// ============================================

/**
 * POST /api/financeiro/contas-receber
 * Registra uma conta a receber (além das vendas normais)
 */
function criarContaReceber(req, res) {
  try {
    const {
      filial_id, cliente_id, descricao, valor, data_vencimento,
      forma_pagamento, numero_documento, observacoes, usuario_id
    } = req.body;

    if (!descricao || !valor || !data_vencimento) {
      return validationError(res, [
        { field: 'descricao',       issue: 'Descrição é obrigatória' },
        { field: 'valor',           issue: 'Valor é obrigatório' },
        { field: 'data_vencimento', issue: 'Data de vencimento é obrigatória' }
      ]);
    }

    const coreDb = db.getCore();

    const result = coreDb.prepare(`
      INSERT INTO financeiro_conta_receber (
        filial_id, cliente_id, descricao, valor, data_vencimento,
        forma_pagamento, numero_documento, observacoes, criado_por_usuario_id
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      filial_id || null,
      cliente_id || null,
      descricao,
      valor,
      data_vencimento,
      forma_pagamento || null,
      numero_documento || null,
      observacoes || null,
      usuario_id || null
    );

    const conta = coreDb.prepare('SELECT * FROM financeiro_conta_receber WHERE id = ?').get(result.lastInsertRowid);

    auditService.logCreate('financeiro_conta_receber', conta.id, conta, extractAuditInfo(req));
    logger.info('Conta a receber criada', { contaId: conta.id, valor, descricao });

    return created(res, conta, 'Conta a receber registrada com sucesso');
  } catch (error) {
    logger.error('Erro ao criar conta a receber:', error);
    throw error;
  }
}

/**
 * GET /api/financeiro/contas-receber
 */
function listarContasReceber(req, res) {
  try {
    const { page, pageSize, offset } = getPaginationParams(req.query);
    const { filial_id, status, cliente_id, vencimento_inicio, vencimento_fim } = req.query;

    const coreDb = db.getCore();

    let sql = `
      SELECT cr.*,
             f.nome  AS filial_nome,
             c.nome_completo AS cliente_nome
      FROM financeiro_conta_receber cr
      LEFT JOIN filial f   ON cr.filial_id  = f.id
      LEFT JOIN cliente c  ON cr.cliente_id = c.id
      WHERE 1=1
    `;
    const params = [];

    if (filial_id)         { sql += ' AND cr.filial_id = ?';         params.push(filial_id); }
    if (status)            { sql += ' AND cr.status = ?';            params.push(status); }
    if (cliente_id)        { sql += ' AND cr.cliente_id = ?';        params.push(cliente_id); }
    if (vencimento_inicio) { sql += ' AND cr.data_vencimento >= ?';  params.push(vencimento_inicio); }
    if (vencimento_fim)    { sql += ' AND cr.data_vencimento <= ?';  params.push(vencimento_fim); }

    let crWhere = sql.substring(sql.indexOf('WHERE'));
    const countSql2 = `SELECT COUNT(*) as total FROM financeiro_conta_receber cr
      LEFT JOIN filial f ON cr.filial_id = f.id
      LEFT JOIN cliente c ON cr.cliente_id = c.id
      ${crWhere}`;
    const countResult2 = coreDb.prepare(countSql2).get(...params);
    const total = countResult2 ? countResult2.total : 0;

    sql += ' ORDER BY cr.data_vencimento ASC LIMIT ? OFFSET ?';
    params.push(pageSize, offset);

    const contas = coreDb.prepare(sql).all(...params);

    return successPaginated(res, contas, page, pageSize, total);
  } catch (error) {
    logger.error('Erro ao listar contas a receber:', error);
    throw error;
  }
}

/**
 * PATCH /api/financeiro/contas-receber/:id/baixar
 * Registra o recebimento (baixa) de uma conta a receber
 */
function baixarContaReceber(req, res) {
  try {
    const { id } = req.params;
    const { data_recebimento, valor_recebido, forma_pagamento, usuario_id, observacoes } = req.body;

    const coreDb = db.getCore();

    const conta = coreDb.prepare('SELECT * FROM financeiro_conta_receber WHERE id = ?').get(id);
    if (!conta) return notFound(res, 'Conta a receber não encontrada');

    if (conta.status === 'recebido') {
      return conflict(res, 'Conta já foi baixada');
    }

    coreDb.prepare(`
      UPDATE financeiro_conta_receber SET
        status            = 'recebido',
        data_recebimento  = ?,
        valor_recebido    = ?,
        forma_pagamento   = COALESCE(?, forma_pagamento),
        recebido_por_usuario_id = ?,
        observacoes       = COALESCE(?, observacoes)
      WHERE id = ?
    `).run(
      data_recebimento || new Date().toISOString().split('T')[0],
      valor_recebido || conta.valor,
      forma_pagamento || null,
      usuario_id || null,
      observacoes || null,
      id
    );

    const contaBaixada = coreDb.prepare('SELECT * FROM financeiro_conta_receber WHERE id = ?').get(id);

    auditService.logStatusChange('financeiro_conta_receber', id, 'pendente', 'recebido', extractAuditInfo(req));
    logger.info('Conta a receber baixada', { contaId: id, valorRecebido: valor_recebido || conta.valor });

    return success(res, contaBaixada, 'Recebimento registrado com sucesso');
  } catch (error) {
    logger.error('Erro ao baixar conta a receber:', error);
    throw error;
  }
}

// ============================================
// FECHAMENTO FINANCEIRO CONSOLIDADO
// ============================================

/**
 * POST /api/financeiro/fechamento
 * Gera o fechamento financeiro consolidado de um período
 * Agrega caixas aprovados de todas (ou de filiais específicas) + contas a pagar/receber
 */
function gerarFechamento(req, res) {
  try {
    const { data_inicio, data_fim, filiais_ids, usuario_id, observacoes } = req.body;

    if (!data_inicio || !data_fim) {
      return validationError(res, [
        { field: 'data_inicio', issue: 'Data de início é obrigatória' },
        { field: 'data_fim',    issue: 'Data de fim é obrigatória' }
      ]);
    }

    const coreDb = db.getCore();

    // Verificar se já existe fechamento para este período/filiais
    const fechamentoExistente = coreDb.prepare(`
      SELECT id FROM financeiro_fechamento
      WHERE data_inicio = ? AND data_fim = ?
        AND status NOT IN ('cancelado')
    `).get(data_inicio, data_fim);

    if (fechamentoExistente) {
      return conflict(res, 'Já existe um fechamento para este período. Cancele-o antes de gerar um novo');
    }

    // Montar filtro de filiais
    let filialFilter = '';
    let filialParams = [];
    if (filiais_ids && filiais_ids.length > 0) {
      filialFilter = ' AND filial_id IN (' + filiais_ids.map(() => '?').join(',') + ')';
      filialParams = filiais_ids;
    }

    // --- 1. Receitas de caixas aprovados no período ---
    const caixas = coreDb.prepare(`
      SELECT cs.id AS sessao_id, cs.filial_id, f.nome AS filial_nome,
             cs.total_entradas, cs.total_saidas, cs.saldo_calculado,
             cs.aberto_em, cs.fechado_em
      FROM caixa_sessao cs
      JOIN filial f ON cs.filial_id = f.id
      WHERE cs.status = 'aprovado'
        AND date(cs.fechado_em) BETWEEN ? AND ?
        ${filialFilter}
      ORDER BY cs.filial_id, cs.fechado_em
    `).all(data_inicio, data_fim, ...filialParams);

    const totalCaixasEntradas = caixas.reduce((s, c) => s + (c.total_entradas || 0), 0);
    const totalCaixasSaidas   = caixas.reduce((s, c) => s + (c.total_saidas   || 0), 0);
    const totalCaixasSaldo    = caixas.reduce((s, c) => s + (c.saldo_calculado || 0), 0);

    // --- 2. Contas a pagar pagas no período ---
    const contasPagas = coreDb.prepare(`
      SELECT cp.*, f.nome AS filial_nome, fo.nome_fantasia AS fornecedor_nome
      FROM financeiro_conta_pagar cp
      LEFT JOIN filial f     ON cp.filial_id     = f.id
      LEFT JOIN fornecedor fo ON cp.fornecedor_id = fo.id
      WHERE cp.status = 'pago'
        AND date(cp.data_pagamento) BETWEEN ? AND ?
        ${filialFilter.replace(/filial_id/g, 'cp.filial_id')}
    `).all(data_inicio, data_fim, ...filialParams);

    const totalPago = contasPagas.reduce((s, c) => s + (c.valor_pago || c.valor || 0), 0);

    // --- 3. Contas a receber recebidas no período ---
    const contasRecebidas = coreDb.prepare(`
      SELECT cr.*, f.nome AS filial_nome, cl.nome_completo AS cliente_nome
      FROM financeiro_conta_receber cr
      LEFT JOIN filial f   ON cr.filial_id  = f.id
      LEFT JOIN cliente cl ON cr.cliente_id = cl.id
      WHERE cr.status = 'recebido'
        AND date(cr.data_recebimento) BETWEEN ? AND ?
        ${filialFilter.replace(/filial_id/g, 'cr.filial_id')}
    `).all(data_inicio, data_fim, ...filialParams);

    const totalRecebido = contasRecebidas.reduce((s, c) => s + (c.valor_recebido || c.valor || 0), 0);

    // --- 4. Contas a pagar e receber em aberto no período ---
    const contasPagarAberto = coreDb.prepare(`
      SELECT COALESCE(SUM(valor), 0) AS total
      FROM financeiro_conta_pagar
      WHERE status = 'pendente'
        AND data_vencimento BETWEEN ? AND ?
        ${filialFilter}
    `).get(data_inicio, data_fim, ...filialParams).total;

    const contasReceberAberto = coreDb.prepare(`
      SELECT COALESCE(SUM(valor), 0) AS total
      FROM financeiro_conta_receber
      WHERE status = 'pendente'
        AND data_vencimento BETWEEN ? AND ?
        ${filialFilter}
    `).get(data_inicio, data_fim, ...filialParams).total;

    // --- 5. Consolidado ---
    const totalReceitas = totalCaixasEntradas + totalRecebido;
    const totalDespesas = totalCaixasSaidas + totalPago;
    const resultado     = totalReceitas - totalDespesas;

    // Gravar fechamento
    const resumoJson = JSON.stringify({
      caixas: { quantidade: caixas.length, entradas: totalCaixasEntradas, saidas: totalCaixasSaidas, saldo: totalCaixasSaldo },
      contas_pagar:   { quantidade: contasPagas.length,    total_pago: totalPago },
      contas_receber: { quantidade: contasRecebidas.length, total_recebido: totalRecebido },
      em_aberto: { contas_pagar: contasPagarAberto, contas_receber: contasReceberAberto }
    });

    const result = coreDb.prepare(`
      INSERT INTO financeiro_fechamento (
        data_inicio, data_fim, filiais_json,
        total_receitas, total_despesas, resultado,
        resumo_json, observacoes, criado_por_usuario_id
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      data_inicio,
      data_fim,
      filiais_ids ? JSON.stringify(filiais_ids) : null,
      parseFloat(totalReceitas.toFixed(2)),
      parseFloat(totalDespesas.toFixed(2)),
      parseFloat(resultado.toFixed(2)),
      resumoJson,
      observacoes || null,
      usuario_id || null
    );

    const fechamento = coreDb.prepare('SELECT * FROM financeiro_fechamento WHERE id = ?').get(result.lastInsertRowid);
    const resumo = JSON.parse(fechamento.resumo_json);

    auditService.logCreate('financeiro_fechamento', fechamento.id, fechamento, extractAuditInfo(req));
    logger.info('Fechamento financeiro gerado', { fechamentoId: fechamento.id, periodo: data_inicio + ' a ' + data_fim, resultado });

    return created(res, {
      fechamento,
      detalhes: {
        caixas,
        contas_pagas: contasPagas,
        contas_recebidas: contasRecebidas,
        resumo: {
          ...resumo,
          total_receitas: parseFloat(totalReceitas.toFixed(2)),
          total_despesas: parseFloat(totalDespesas.toFixed(2)),
          resultado:      parseFloat(resultado.toFixed(2))
        }
      }
    }, 'Fechamento financeiro gerado com sucesso');
  } catch (error) {
    logger.error('Erro ao gerar fechamento:', error);
    throw error;
  }
}

/**
 * GET /api/financeiro/fechamentos
 * Lista fechamentos financeiros
 */
function listarFechamentos(req, res) {
  try {
    const { page, pageSize, offset } = getPaginationParams(req.query);
    const coreDb = db.getCore();

    const fechCountResult = coreDb.prepare('SELECT COUNT(*) as total FROM financeiro_fechamento').get();
    const total = fechCountResult ? fechCountResult.total : 0;

    const fechamentos = coreDb.prepare(`
      SELECT * FROM financeiro_fechamento
      ORDER BY criado_em DESC LIMIT ? OFFSET ?
    `).all(pageSize, offset);

    fechamentos.forEach(f => {
      if (f.resumo_json) {
        try { f.resumo = JSON.parse(f.resumo_json); } catch(e) {}
        delete f.resumo_json;
      }
      if (f.filiais_json) {
        try { f.filiais = JSON.parse(f.filiais_json); } catch(e) {}
        delete f.filiais_json;
      }
    });

    return successPaginated(res, fechamentos, page, pageSize, total);
  } catch (error) {
    logger.error('Erro ao listar fechamentos:', error);
    throw error;
  }
}

/**
 * GET /api/financeiro/fechamentos/:id
 * Detalhe de um fechamento financeiro
 */
function buscarFechamento(req, res) {
  try {
    const { id } = req.params;
    const coreDb = db.getCore();

    const fechamento = coreDb.prepare('SELECT * FROM financeiro_fechamento WHERE id = ?').get(id);
    if (!fechamento) return notFound(res, 'Fechamento não encontrado');

    if (fechamento.resumo_json)  { fechamento.resumo  = JSON.parse(fechamento.resumo_json);  delete fechamento.resumo_json; }
    if (fechamento.filiais_json) { fechamento.filiais = JSON.parse(fechamento.filiais_json); delete fechamento.filiais_json; }

    return success(res, fechamento);
  } catch (error) {
    logger.error('Erro ao buscar fechamento:', error);
    throw error;
  }
}

/**
 * GET /api/financeiro/dashboard
 * Painel consolidado multi-filial: caixas abertos, pendentes, vencimentos próximos
 */
function dashboard(req, res) {
  try {
    const coreDb = db.getCore();
    const hoje   = new Date().toISOString().split('T')[0];
    const em7    = new Date(Date.now() + 7 * 86400000).toISOString().split('T')[0];

    const caixasAbertos        = coreDb.prepare("SELECT COUNT(*) as t FROM caixa_sessao WHERE status = 'aberto'").get().t;
    const caixasPendentes      = coreDb.prepare("SELECT COUNT(*) as t FROM caixa_sessao WHERE status = 'pendente_aprovacao'").get().t;
    const contasPagarVencendo  = coreDb.prepare("SELECT COUNT(*) as t, COALESCE(SUM(valor),0) as total FROM financeiro_conta_pagar WHERE status='pendente' AND data_vencimento BETWEEN ? AND ?").get(hoje, em7);
    const contasPagarVencidas  = coreDb.prepare("SELECT COUNT(*) as t, COALESCE(SUM(valor),0) as total FROM financeiro_conta_pagar WHERE status='pendente' AND data_vencimento < ?").get(hoje);
    const contasReceberPendentes = coreDb.prepare("SELECT COUNT(*) as t, COALESCE(SUM(valor),0) as total FROM financeiro_conta_receber WHERE status='pendente'").get();

    const caixasPorFilial = coreDb.prepare(`
      SELECT f.nome, cs.status, COUNT(*) as quantidade
      FROM caixa_sessao cs
      JOIN filial f ON cs.filial_id = f.id
      WHERE date(cs.aberto_em) = date('now')
      GROUP BY f.nome, cs.status
    `).all();

    return success(res, {
      hoje,
      caixas: {
        abertos:           caixasAbertos,
        pendentes_aprovacao: caixasPendentes,
        por_filial_hoje:   caixasPorFilial
      },
      contas_pagar: {
        vencendo_7_dias:  { quantidade: contasPagarVencendo.t,  total: parseFloat(contasPagarVencendo.total.toFixed(2)) },
        vencidas:         { quantidade: contasPagarVencidas.t,  total: parseFloat(contasPagarVencidas.total.toFixed(2)) }
      },
      contas_receber: {
        pendentes:        { quantidade: contasReceberPendentes.t, total: parseFloat(contasReceberPendentes.total.toFixed(2)) }
      }
    });
  } catch (error) {
    logger.error('Erro ao gerar dashboard financeiro:', error);
    throw error;
  }
}

module.exports = {
  // Aprovação de caixas
  listarCaixasPendentes,
  revisarCaixa,
  aprovarCaixa,
  rejeitarCaixa,
  // Contas a pagar
  criarContaPagar,
  listarContasPagar,
  atualizarContaPagar,
  baixarContaPagar,
  // Contas a receber
  criarContaReceber,
  listarContasReceber,
  baixarContaReceber,
  // Fechamento consolidado
  gerarFechamento,
  listarFechamentos,
  buscarFechamento,
  // Dashboard
  dashboard
};
