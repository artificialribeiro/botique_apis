/**
 * BOUTIQUE DINIZ API - Controller de Carrinho
 * Desenvolvido por Estúdio Atlas
 */

const db = require('../config/database');
const { success, created, notFound, validationError } = require('../utils/response');
const logger = require('../utils/logger');

/**
 * POST /api/carrinho
 * Adiciona item ao carrinho
 */
function adicionar(req, res) {
  try {
    const { cliente_id, produto_variante_id, quantidade } = req.body;
    
    const coreDb = db.getCore();
    
    // Verificar se cliente existe
    const cliente = coreDb.prepare('SELECT id FROM cliente WHERE id = ? AND ativo = 1').get(cliente_id);
    if (!cliente) {
      return notFound(res, 'Cliente não encontrado');
    }
    
    // Verificar se variante existe e tem estoque
    const variante = coreDb.prepare(`
      SELECT pv.*, p.nome as produto_nome, p.preco
      FROM produto_variante pv
      JOIN produto p ON pv.produto_id = p.id
      WHERE pv.id = ? AND pv.ativo = 1 AND p.ativo = 1
    `).get(produto_variante_id);
    
    if (!variante) {
      return notFound(res, 'Produto não encontrado ou indisponível');
    }
    
    if (variante.estoque < quantidade) {
      return validationError(res, [{ field: 'quantidade', issue: `Estoque insuficiente. Disponível: ${variante.estoque}` }]);
    }
    
    // Verificar se já existe no carrinho
    const itemExistente = coreDb.prepare(`
      SELECT * FROM carrinho_item WHERE cliente_id = ? AND produto_variante_id = ?
    `).get(cliente_id, produto_variante_id);
    
    let item;
    if (itemExistente) {
      // Atualizar quantidade
      const novaQuantidade = itemExistente.quantidade + quantidade;
      if (variante.estoque < novaQuantidade) {
        return validationError(res, [{ field: 'quantidade', issue: `Estoque insuficiente. Disponível: ${variante.estoque}` }]);
      }
      
      coreDb.prepare(`
        UPDATE carrinho_item SET quantidade = ?, atualizado_em = datetime('now')
        WHERE id = ?
      `).run(novaQuantidade, itemExistente.id);
      
      item = coreDb.prepare('SELECT * FROM carrinho_item WHERE id = ?').get(itemExistente.id);
    } else {
      // Criar novo item
      const result = coreDb.prepare(`
        INSERT INTO carrinho_item (cliente_id, produto_variante_id, quantidade)
        VALUES (?, ?, ?)
      `).run(cliente_id, produto_variante_id, quantidade);
      
      item = coreDb.prepare('SELECT * FROM carrinho_item WHERE id = ?').get(result.lastInsertRowid);
    }
    
    logger.info('Item adicionado ao carrinho', { clienteId: cliente_id, itemId: item.id });
    
    return created(res, item, 'Item adicionado ao carrinho');
  } catch (error) {
    logger.error('Erro ao adicionar ao carrinho:', error);
    throw error;
  }
}

/**
 * GET /api/carrinho/:cliente_id
 * Lista carrinho do cliente
 */
function listar(req, res) {
  try {
    const { cliente_id } = req.params;
    const coreDb = db.getCore();
    
    const cliente = coreDb.prepare('SELECT id FROM cliente WHERE id = ?').get(cliente_id);
    if (!cliente) {
      return notFound(res, 'Cliente não encontrado');
    }
    
    const itens = coreDb.prepare(`
      SELECT 
        ci.*,
        pv.tamanho, pv.cor, pv.estoque,
        p.id as produto_id, p.nome as produto_nome, p.preco, p.desconto_valor, p.desconto_percent,
        pi.caminho as imagem
      FROM carrinho_item ci
      JOIN produto_variante pv ON ci.produto_variante_id = pv.id
      JOIN produto p ON pv.produto_id = p.id
      LEFT JOIN produto_imagem pi ON p.id = pi.produto_id AND pi.ordem = 1
      WHERE ci.cliente_id = ?
      ORDER BY ci.criado_em DESC
    `).all(cliente_id);
    
    // Calcular totais
    let subtotal = 0;
    let desconto_total = 0;
    
    itens.forEach(item => {
      let precoItem = item.preco;
      let descontoItem = 0;
      
      if (item.desconto_valor) {
        descontoItem = item.desconto_valor;
      } else if (item.desconto_percent) {
        descontoItem = precoItem * (item.desconto_percent / 100);
      }
      
      item.preco_final = precoItem - descontoItem;
      item.total_item = item.preco_final * item.quantidade;
      
      subtotal += item.preco * item.quantidade;
      desconto_total += descontoItem * item.quantidade;
    });
    
    return success(res, {
      itens,
      resumo: {
        quantidade_itens: itens.length,
        subtotal: parseFloat(subtotal.toFixed(2)),
        desconto_total: parseFloat(desconto_total.toFixed(2)),
        total: parseFloat((subtotal - desconto_total).toFixed(2))
      }
    });
  } catch (error) {
    logger.error('Erro ao listar carrinho:', error);
    throw error;
  }
}

/**
 * PUT /api/carrinho/:item_id
 * Atualiza quantidade do item
 */
function atualizar(req, res) {
  try {
    const { item_id } = req.params;
    const { quantidade } = req.body;
    
    const coreDb = db.getCore();
    
    const item = coreDb.prepare(`
      SELECT ci.*, pv.estoque
      FROM carrinho_item ci
      JOIN produto_variante pv ON ci.produto_variante_id = pv.id
      WHERE ci.id = ?
    `).get(item_id);
    
    if (!item) {
      return notFound(res, 'Item não encontrado');
    }
    
    if (item.estoque < quantidade) {
      return validationError(res, [{ field: 'quantidade', issue: `Estoque insuficiente. Disponível: ${item.estoque}` }]);
    }
    
    coreDb.prepare(`
      UPDATE carrinho_item SET quantidade = ?, atualizado_em = datetime('now')
      WHERE id = ?
    `).run(quantidade, item_id);
    
    const itemAtualizado = coreDb.prepare('SELECT * FROM carrinho_item WHERE id = ?').get(item_id);
    
    logger.info('Item do carrinho atualizado', { itemId: item_id });
    
    return success(res, itemAtualizado, 'Quantidade atualizada');
  } catch (error) {
    logger.error('Erro ao atualizar carrinho:', error);
    throw error;
  }
}

/**
 * DELETE /api/carrinho/:item_id
 * Remove item do carrinho
 */
function remover(req, res) {
  try {
    const { item_id } = req.params;
    const coreDb = db.getCore();
    
    const item = coreDb.prepare('SELECT * FROM carrinho_item WHERE id = ?').get(item_id);
    if (!item) {
      return notFound(res, 'Item não encontrado');
    }
    
    coreDb.prepare('DELETE FROM carrinho_item WHERE id = ?').run(item_id);
    
    logger.info('Item removido do carrinho', { itemId: item_id });
    
    return success(res, null, 'Item removido do carrinho');
  } catch (error) {
    logger.error('Erro ao remover do carrinho:', error);
    throw error;
  }
}

/**
 * POST /api/carrinho/:cliente_id/limpar
 * Limpa carrinho do cliente
 */
function limpar(req, res) {
  try {
    const { cliente_id } = req.params;
    const coreDb = db.getCore();
    
    const result = coreDb.prepare('DELETE FROM carrinho_item WHERE cliente_id = ?').run(cliente_id);
    
    logger.info('Carrinho limpo', { clienteId: cliente_id, itensRemovidos: result.changes });
    
    return success(res, { itens_removidos: result.changes }, 'Carrinho limpo');
  } catch (error) {
    logger.error('Erro ao limpar carrinho:', error);
    throw error;
  }
}

module.exports = {
  adicionar,
  listar,
  atualizar,
  remover,
  limpar
};
