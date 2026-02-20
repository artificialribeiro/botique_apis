/**
 * BOUTIQUE DINIZ API - Controller de Pedidos
 * Desenvolvido por Estúdio Atlas
 */

const db = require('../config/database');
const { success, successPaginated, created, notFound, validationError } = require('../utils/response');
const { getPaginationParams } = require('../utils/pagination');
const auditService = require('../services/auditService');
const notificacaoService = require('../services/notificacaoService');
const { extractAuditInfo } = require('../middlewares/auth');
const logger = require('../utils/logger');

/**
 * POST /api/pedidos
 * Cria pedido a partir do carrinho
 */
function criar(req, res) {
  try {
    const { 
      cliente_id, filial_origem_id, endereco_entrega_id, 
      pagamento_tipo, pagamento_parcelas, cupom_codigo, frete 
    } = req.body;
    
    const coreDb = db.getCore();
    
    // Verificar cliente
    const cliente = coreDb.prepare('SELECT id FROM cliente WHERE id = ? AND ativo = 1').get(cliente_id);
    if (!cliente) {
      return notFound(res, 'Cliente não encontrado');
    }
    
    // Verificar endereço
    const endereco = coreDb.prepare('SELECT id FROM cliente_endereco WHERE id = ? AND cliente_id = ?').get(endereco_entrega_id, cliente_id);
    if (!endereco) {
      return notFound(res, 'Endereço não encontrado');
    }
    
    // Buscar itens do carrinho
    const itensCarrinho = coreDb.prepare(`
      SELECT ci.*, pv.produto_id, pv.estoque, p.preco, p.desconto_valor, p.desconto_percent
      FROM carrinho_item ci
      JOIN produto_variante pv ON ci.produto_variante_id = pv.id
      JOIN produto p ON pv.produto_id = p.id
      WHERE ci.cliente_id = ? AND pv.ativo = 1 AND p.ativo = 1
    `).all(cliente_id);
    
    if (itensCarrinho.length === 0) {
      return validationError(res, [{ field: 'carrinho', issue: 'Carrinho vazio' }]);
    }
    
    // Verificar estoque e calcular totais
    let subtotal = 0;
    let descontoTotal = 0;
    
    for (const item of itensCarrinho) {
      if (item.estoque < item.quantidade) {
        return validationError(res, [{ 
          field: 'estoque', 
          issue: `Estoque insuficiente para o produto (variante ${item.produto_variante_id})` 
        }]);
      }
      
      let descontoUnit = 0;
      if (item.desconto_valor) {
        descontoUnit = item.desconto_valor;
      } else if (item.desconto_percent) {
        descontoUnit = item.preco * (item.desconto_percent / 100);
      }
      
      subtotal += item.preco * item.quantidade;
      descontoTotal += descontoUnit * item.quantidade;
    }
    
    // Verificar cupom
    let cupomId = null;
    let descontoCupom = 0;
    
    if (cupom_codigo) {
      const cupom = coreDb.prepare(`
        SELECT * FROM cupom 
        WHERE codigo = ? AND ativo = 1 
        AND (data_inicio IS NULL OR date(data_inicio) <= date('now'))
        AND (data_fim IS NULL OR date(data_fim) >= date('now'))
        AND quantidade_usada < quantidade_total
      `).get(cupom_codigo);
      
      if (cupom) {
        cupomId = cupom.id;
        if (cupom.percentual) {
          descontoCupom = (subtotal - descontoTotal) * (cupom.percentual / 100);
        } else if (cupom.valor_fixo) {
          descontoCupom = cupom.valor_fixo;
        }
      }
    }
    
    const total = subtotal - descontoTotal - descontoCupom + (frete || 0);
    
    // Criar pedido em transação
    const transaction = coreDb.transaction(() => {
      // Inserir pedido
      const pedidoResult = coreDb.prepare(`
        INSERT INTO pedido (
          cliente_id, filial_origem_id, status_pedido, status_pagamento,
          pagamento_id_externo, pagamento_status_detalhado,
          pagamento_tipo, pagamento_parcelas, subtotal, desconto_total, frete, total,
          cupom_id, endereco_entrega_id
        ) VALUES (?, ?, 'novo', 'aguardando', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        cliente_id, filial_origem_id, 
        req.body.pagamento_id_externo || null,
        req.body.pagamento_status_detalhado || null,
        pagamento_tipo || null, pagamento_parcelas || null,
        subtotal, descontoTotal + descontoCupom, frete || 0, total, cupomId, endereco_entrega_id
      );
      
      const pedidoId = pedidoResult.lastInsertRowid;
      
      // Inserir itens do pedido e baixar estoque
      for (const item of itensCarrinho) {
        let descontoUnit = 0;
        if (item.desconto_valor) {
          descontoUnit = item.desconto_valor;
        } else if (item.desconto_percent) {
          descontoUnit = item.preco * (item.desconto_percent / 100);
        }
        
        const totalItem = (item.preco - descontoUnit) * item.quantidade;
        
        coreDb.prepare(`
          INSERT INTO pedido_item (pedido_id, produto_id, produto_variante_id, quantidade, preco_unit, desconto_unit, total_item)
          VALUES (?, ?, ?, ?, ?, ?, ?)
        `).run(pedidoId, item.produto_id, item.produto_variante_id, item.quantidade, item.preco, descontoUnit, totalItem);
        
        // Baixar estoque
        coreDb.prepare('UPDATE produto_variante SET estoque = estoque - ? WHERE id = ?').run(item.quantidade, item.produto_variante_id);
        
        // Registrar movimento de estoque
        coreDb.prepare(`
          INSERT INTO estoque_movimento (produto_variante_id, tipo, quantidade, motivo, referencia_tipo, referencia_id)
          VALUES (?, 'saida', ?, 'Venda - Pedido', 'pedido', ?)
        `).run(item.produto_variante_id, item.quantidade, pedidoId);
      }
      
      // Registrar uso do cupom
      if (cupomId) {
        coreDb.prepare(`
          INSERT INTO cupom_uso (cupom_id, pedido_id, cliente_id, valor_desconto)
          VALUES (?, ?, ?, ?)
        `).run(cupomId, pedidoId, cliente_id, descontoCupom);
        
        coreDb.prepare('UPDATE cupom SET quantidade_usada = quantidade_usada + 1 WHERE id = ?').run(cupomId);
      }
      
      // Limpar carrinho
      coreDb.prepare('DELETE FROM carrinho_item WHERE cliente_id = ?').run(cliente_id);
      
      return pedidoId;
    });
    
    const pedidoId = transaction();
    const pedido = coreDb.prepare('SELECT * FROM pedido WHERE id = ?').get(pedidoId);
    
    // Buscar itens do pedido
    pedido.itens = coreDb.prepare(`
      SELECT pi.*, p.nome as produto_nome, pv.tamanho, pv.cor
      FROM pedido_item pi
      JOIN produto p ON pi.produto_id = p.id
      JOIN produto_variante pv ON pi.produto_variante_id = pv.id
      WHERE pi.pedido_id = ?
    `).all(pedidoId);
    
    auditService.logCreate('pedido', pedidoId, pedido, extractAuditInfo(req));
    
    logger.info('Pedido criado', { pedidoId, clienteId: cliente_id, total });
    
    return created(res, pedido, 'Pedido criado com sucesso');
  } catch (error) {
    logger.error('Erro ao criar pedido:', error);
    throw error;
  }
}

/**
 * GET /api/pedidos
 * Lista pedidos com paginação
 */
function listar(req, res) {
  try {
    const { page, pageSize, offset } = getPaginationParams(req.query);
    const { cliente_id, status_pedido, status_pagamento, filial_id, data_inicio, data_fim } = req.query;
    
    const coreDb = db.getCore();
    
    let sql = `
      SELECT p.*, c.nome_completo as cliente_nome, f.nome as filial_nome
      FROM pedido p
      JOIN cliente c ON p.cliente_id = c.id
      JOIN filial f ON p.filial_origem_id = f.id
      WHERE 1=1
    `;
    const params = [];
    
    if (cliente_id) {
      sql += ' AND p.cliente_id = ?';
      params.push(cliente_id);
    }
    
    if (status_pedido) {
      sql += ' AND p.status_pedido = ?';
      params.push(status_pedido);
    }
    
    if (status_pagamento) {
      sql += ' AND p.status_pagamento = ?';
      params.push(status_pagamento);
    }
    
    if (filial_id) {
      sql += ' AND p.filial_origem_id = ?';
      params.push(filial_id);
    }
    
    if (data_inicio) {
      sql += ' AND p.criado_em >= ?';
      params.push(data_inicio);
    }
    
    if (data_fim) {
      sql += ' AND p.criado_em <= ?';
      params.push(data_fim);
    }
    
    // Contar total — query independente para evitar falha de regex
    let pedidoWherePart = sql.substring(sql.indexOf('WHERE'));
    const countSql = `SELECT COUNT(*) as total FROM pedido p
      JOIN cliente c ON p.cliente_id = c.id
      LEFT JOIN filial f ON p.filial_origem_id = f.id
      ${pedidoWherePart}`;
    const countResult = coreDb.prepare(countSql).get(...params);
    const total = countResult ? countResult.total : 0;
    
    // Buscar com paginação
    sql += ' ORDER BY p.criado_em DESC LIMIT ? OFFSET ?';
    params.push(pageSize, offset);
    
    const pedidos = coreDb.prepare(sql).all(...params);
    
    return successPaginated(res, pedidos, page, pageSize, total);
  } catch (error) {
    logger.error('Erro ao listar pedidos:', error);
    throw error;
  }
}

/**
 * GET /api/pedidos/:id
 * Busca pedido por ID
 */
function buscar(req, res) {
  try {
    const { id } = req.params;
    const coreDb = db.getCore();
    
    const pedido = coreDb.prepare(`
      SELECT p.*, c.nome_completo as cliente_nome, c.email as cliente_email, c.celular as cliente_celular,
             f.nome as filial_nome
      FROM pedido p
      JOIN cliente c ON p.cliente_id = c.id
      JOIN filial f ON p.filial_origem_id = f.id
      WHERE p.id = ?
    `).get(id);
    
    if (!pedido) {
      return notFound(res, 'Pedido não encontrado');
    }
    
    // Buscar itens
    pedido.itens = coreDb.prepare(`
      SELECT pi.*, p.nome as produto_nome, p.sku, pv.tamanho, pv.cor
      FROM pedido_item pi
      JOIN produto p ON pi.produto_id = p.id
      JOIN produto_variante pv ON pi.produto_variante_id = pv.id
      WHERE pi.pedido_id = ?
    `).all(id);
    
    // Buscar endereço
    pedido.endereco = coreDb.prepare('SELECT * FROM cliente_endereco WHERE id = ?').get(pedido.endereco_entrega_id);
    
    return success(res, pedido);
  } catch (error) {
    logger.error('Erro ao buscar pedido:', error);
    throw error;
  }
}

/**
 * PATCH /api/pedidos/:id/status-pedido
 * Atualiza status do pedido
 */
function atualizarStatusPedido(req, res) {
  try {
    const { id } = req.params;
    const { status_pedido, separado_por_usuario_id } = req.body;
    
    const coreDb = db.getCore();
    
    const pedido = coreDb.prepare('SELECT * FROM pedido WHERE id = ?').get(id);
    if (!pedido) {
      return notFound(res, 'Pedido não encontrado');
    }
    
    const statusAnterior = pedido.status_pedido;
    
    let sql = 'UPDATE pedido SET status_pedido = ?, atualizado_em = datetime(\'now\')';
    const params = [status_pedido];
    
    if (separado_por_usuario_id) {
      sql += ', separado_por_usuario_id = ?';
      params.push(separado_por_usuario_id);
    }
    
    sql += ' WHERE id = ?';
    params.push(id);
    
    coreDb.prepare(sql).run(...params);
    
    // Buscar dados do cliente e pedido para notificação
    const pedidoAtualizado = coreDb.prepare(`
      SELECT p.*, c.nome_completo, c.email, c.cpf
      FROM pedido p
      JOIN cliente c ON p.cliente_id = c.id
      WHERE p.id = ?
    `).get(id);
    
    // Enviar notificação de atualização de pedido
    if (pedidoAtualizado && pedidoAtualizado.email) {
      notificacaoService.notificarAtualizacaoPedido(pedidoAtualizado, pedidoAtualizado, statusAnterior, status_pedido).catch(err => {
        logger.error('Erro ao enviar notificação de atualização de pedido', err);
      });
    }
    
    auditService.logStatusChange('pedido', id, statusAnterior, status_pedido, extractAuditInfo(req));
    
    logger.info('Status do pedido atualizado', { pedidoId: id, de: statusAnterior, para: status_pedido });
    
    return success(res, { id, status_pedido }, 'Status atualizado com sucesso');
  } catch (error) {
    logger.error('Erro ao atualizar status:', error);
    throw error;
  }
}

/**
 * PATCH /api/pedidos/:id/status-pagamento
 * Atualiza status de pagamento
 */
function atualizarStatusPagamento(req, res) {
  try {
    const { id } = req.params;
    const { status_pagamento, pagamento_id_externo, pagamento_status_detalhado } = req.body;
    
    const coreDb = db.getCore();
    
    const pedido = coreDb.prepare('SELECT * FROM pedido WHERE id = ?').get(id);
    if (!pedido) {
      return notFound(res, 'Pedido não encontrado');
    }
    
    const statusAnterior = pedido.status_pagamento;
    
    let sql = 'UPDATE pedido SET status_pagamento = ?, atualizado_em = datetime(\'now\')';
    const params = [status_pagamento];
    
    if (pagamento_id_externo) {
      sql += ', pagamento_id_externo = ?';
      params.push(pagamento_id_externo);
    }
    
    if (pagamento_status_detalhado) {
      sql += ', pagamento_status_detalhado = ?';
      params.push(pagamento_status_detalhado);
    }
    
    sql += ' WHERE id = ?';
    params.push(id);
      coreDb.prepare(sql).run(...params);
    
    // Buscar dados do cliente e pedido para notificação
    const pedidoAtualizado = coreDb.prepare(`
      SELECT p.*, c.nome_completo, c.email, c.cpf
      FROM pedido p
      JOIN cliente c ON p.cliente_id = c.id
      WHERE p.id = ?
    `).get(id);
    
    // Enviar notificação de atualização de pedido
    if (pedidoAtualizado && pedidoAtualizado.email) {
      notificacaoService.notificarAtualizacaoPedido(pedidoAtualizado, pedidoAtualizado, 'pagamento_' + statusAnterior, 'pagamento_' + status_pagamento).catch(err => {
        logger.error('Erro ao enviar notificação de atualização de pedido', err);
      });
    }
    
    auditService.logStatusChange('pedido', id, statusAnterior, status_pagamento, extractAuditInfo(req));
    
    logger.info('Status de pagamento atualizado', { pedidoId: id, de: statusAnterior, para: status_pagamento });
    
    return success(res, { id, status_pagamento }, 'Status de pagamento atualizado com sucesso');
  } catch (error) {
    logger.error('Erro ao atualizar pagamento:', error);
    throw error;
  }
}

/**
 * PATCH /api/pedidos/:id/rastreio
 * Atualiza informações de rastreio
 */
function atualizarRastreio(req, res) {
  try {
    const { id } = req.params;
    const { codigo_rastreio, link_acompanhamento, data_prevista_entrega } = req.body;
    
    const coreDb = db.getCore();
    
    const pedido = coreDb.prepare('SELECT id FROM pedido WHERE id = ?').get(id);
    if (!pedido) {
      return notFound(res, 'Pedido não encontrado');
    }
    
    const updates = [];
    const params = [];
    
    if (codigo_rastreio !== undefined) { updates.push('codigo_rastreio = ?'); params.push(codigo_rastreio); }
    if (link_acompanhamento !== undefined) { updates.push('link_acompanhamento = ?'); params.push(link_acompanhamento); }
    if (data_prevista_entrega !== undefined) { updates.push('data_prevista_entrega = ?'); params.push(data_prevista_entrega); }
    
    if (updates.length > 0) {
      updates.push('atualizado_em = datetime(\'now\')');
      params.push(id);
      coreDb.prepare(`UPDATE pedido SET ${updates.join(', ')} WHERE id = ?`).run(...params);
    }
    
    const pedidoAtualizado = coreDb.prepare('SELECT id, codigo_rastreio, link_acompanhamento, data_prevista_entrega FROM pedido WHERE id = ?').get(id);
    
    logger.info('Rastreio atualizado', { pedidoId: id });
    
    return success(res, pedidoAtualizado, 'Informações de rastreio atualizadas');
  } catch (error) {
    logger.error('Erro ao atualizar rastreio:', error);
    throw error;
  }
}

module.exports = {
  criar,
  listar,
  buscar,
  atualizarStatusPedido,
  atualizarStatusPagamento,
  atualizarRastreio
};
