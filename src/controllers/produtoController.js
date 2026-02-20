/**
 * BOUTIQUE DINIZ API - Controller de Produtos
 * Desenvolvido por Estúdio Atlas
 */

const db = require('../config/database');
const { success, successPaginated, created, notFound } = require('../utils/response');
const { getPaginationParams } = require('../utils/pagination');
const auditService = require('../services/auditService');
const { extractAuditInfo } = require('../middlewares/auth');
const { getRelativePath, removeFile } = require('../middlewares/upload');
const config = require('../config');
const logger = require('../utils/logger');
const path = require('path');
const fs = require('fs');

/**
 * Converte um caminho relativo de imagem em uma string Base64. Caso o arquivo
 * não exista, retorna null. A função deduz o tipo MIME com base na extensão.
 * @param {string|null} caminho Caminho relativo (iniciado por '/uploads')
 * @returns {string|null} Data URI base64 ou null
 */
function toBase64(caminho) {
  if (!caminho) return null;
  const relative = caminho.replace(/^\/?uploads\/?/, '');
  const filePath = path.join(config.upload.path, relative);
  try {
    const buffer = fs.readFileSync(filePath);
    const ext = path.extname(filePath).toLowerCase().slice(1);
    let mime;
    switch (ext) {
      case 'jpg':
      case 'jpeg':
        mime = 'image/jpeg';
        break;
      case 'png':
        mime = 'image/png';
        break;
      case 'webp':
        mime = 'image/webp';
        break;
      case 'gif':
        mime = 'image/gif';
        break;
      default:
        mime = 'application/octet-stream';
    }
    return `data:${mime};base64,${buffer.toString('base64')}`;
  } catch (err) {
    return null;
  }
}

/**
 * POST /api/produtos
 * Cria novo produto
 */
function criar(req, res) {
  try {
    const { 
      sku, nome, descricao, fornecedor_id, filial_id, preco, 
      desconto_valor, desconto_percent, parcelavel, parcelas_max,
      categoria_id
    } = req.body;
    
    const coreDb = db.getCore();
    
    const result = coreDb.prepare(`
      INSERT INTO produto (sku, nome, descricao, fornecedor_id, filial_id, preco, desconto_valor, desconto_percent, parcelavel, parcelas_max, categoria_id)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      sku || null, nome, descricao || null, fornecedor_id || null, filial_id,
      preco, desconto_valor || null, desconto_percent || null, parcelavel ? 1 : 0, parcelas_max || null,
      categoria_id || null
    );
    
    const produto = coreDb.prepare('SELECT * FROM produto WHERE id = ?').get(result.lastInsertRowid);
    
    auditService.logCreate('produto', produto.id, produto, extractAuditInfo(req));
    
    logger.info('Produto criado', { produtoId: produto.id });
    
    return created(res, produto, 'Produto criado com sucesso');
  } catch (error) {
    logger.error('Erro ao criar produto:', error);
    throw error;
  }
}

/**
 * GET /api/produtos
 * Lista produtos com paginação
 */
function listar(req, res) {
  try {
    const { page, pageSize, offset } = getPaginationParams(req.query);
    const { q, ativo, filial_id, fornecedor_id } = req.query;
    
    const coreDb = db.getCore();
    
    let sql = `
      SELECT p.*, 
             f.nome as filial_nome, 
             fo.nome_fantasia as fornecedor_nome,
             c.id as categoria_id,
             c.nome as categoria_nome,
             c.logo_caminho as categoria_logo_caminho,
             c.imagem_caminho as categoria_imagem_caminho
      FROM produto p
      LEFT JOIN filial f ON p.filial_id = f.id
      LEFT JOIN fornecedor fo ON p.fornecedor_id = fo.id
      LEFT JOIN categoria c ON p.categoria_id = c.id
      WHERE 1=1
    `;
    const params = [];
    
    if (q) {
      sql += ' AND (p.nome LIKE ? OR p.sku LIKE ? OR p.descricao LIKE ?)';
      const search = `%${q}%`;
      params.push(search, search, search);
    }
    
    if (ativo !== undefined) {
      sql += ' AND p.ativo = ?';
      params.push(parseInt(ativo));
    }
    
    if (filial_id) {
      sql += ' AND p.filial_id = ?';
      params.push(filial_id);
    }
    
    if (fornecedor_id) {
      sql += ' AND p.fornecedor_id = ?';
      params.push(fornecedor_id);
    }
    
    // Contar total — usa query independente para evitar falha de regex
    let wherePart = sql.substring(sql.indexOf('WHERE'));
    const countSql = `SELECT COUNT(*) as total FROM produto p
      LEFT JOIN filial f ON p.filial_id = f.id
      LEFT JOIN fornecedor fo ON p.fornecedor_id = fo.id
      LEFT JOIN categoria c ON p.categoria_id = c.id
      ${wherePart}`;
    const countResult = coreDb.prepare(countSql).get(...params);
    const total = countResult ? countResult.total : 0;
    
    // Buscar com paginação
    sql += ' ORDER BY p.criado_em DESC LIMIT ? OFFSET ?';
    params.push(pageSize, offset);
    
    const produtos = coreDb.prepare(sql).all(...params);
    

    // Buscar imagens de cada produto e converter para Base64. Também montar objeto da categoria.
    produtos.forEach(produto => {
      // Carregar imagens
      const imagens = coreDb.prepare(`
        SELECT id, caminho, mime, ordem FROM produto_imagem WHERE produto_id = ? ORDER BY ordem
      `).all(produto.id);
      produto.imagens = imagens.map(img => {
        return Object.assign({}, img, {
          base64: toBase64(img.caminho)
        });
      });
      // Montar categoria
      if (produto.categoria_id) {
        produto.categoria = {
          id: produto.categoria_id,
          nome: produto.categoria_nome,
          logo_base64: toBase64(produto.categoria_logo_caminho),
          imagem_base64: toBase64(produto.categoria_imagem_caminho)
        };
      } else {
        produto.categoria = null;
      }
      // Remover campos auxiliares
      delete produto.categoria_nome;
      delete produto.categoria_logo_caminho;
      delete produto.categoria_imagem_caminho;
    });
    
    return successPaginated(res, produtos, page, pageSize, total);
  } catch (error) {
    logger.error('Erro ao listar produtos:', error);
    throw error;
  }
}

/**
 * GET /api/produtos/:id
 * Busca produto por ID
 */
function buscar(req, res) {
  try {
    const { id } = req.params;
    const coreDb = db.getCore();
    
    const produto = coreDb.prepare(`
      SELECT p.*, 
             f.nome as filial_nome, 
             fo.nome_fantasia as fornecedor_nome,
             c.id as categoria_id,
             c.nome as categoria_nome,
             c.logo_caminho as categoria_logo_caminho,
             c.imagem_caminho as categoria_imagem_caminho
      FROM produto p
      LEFT JOIN filial f ON p.filial_id = f.id
      LEFT JOIN fornecedor fo ON p.fornecedor_id = fo.id
      LEFT JOIN categoria c ON p.categoria_id = c.id
      WHERE p.id = ?
    `).get(id);
    
    if (!produto) {
      return notFound(res, 'Produto não encontrado');
    }
    
    // Buscar variantes
    produto.variantes = coreDb.prepare(`
      SELECT * FROM produto_variante WHERE produto_id = ? ORDER BY tamanho, cor
    `).all(id);
    // Buscar imagens e converter para Base64
    const imagensBrutas = coreDb.prepare(`
      SELECT * FROM produto_imagem WHERE produto_id = ? ORDER BY ordem
    `).all(id);
    produto.imagens = imagensBrutas.map(img => {
      return Object.assign({}, img, {
        base64: toBase64(img.caminho)
      });
    });
    // Montar categoria
    if (produto.categoria_id) {
      produto.categoria = {
        id: produto.categoria_id,
        nome: produto.categoria_nome,
        logo_base64: toBase64(produto.categoria_logo_caminho),
        imagem_base64: toBase64(produto.categoria_imagem_caminho)
      };
    } else {
      produto.categoria = null;
    }
    delete produto.categoria_nome;
    delete produto.categoria_logo_caminho;
    delete produto.categoria_imagem_caminho;
    
    return success(res, produto);
  } catch (error) {
    logger.error('Erro ao buscar produto:', error);
    throw error;
  }
}

/**
 * PUT /api/produtos/:id
 * Atualiza produto
 */
function atualizar(req, res) {
  try {
    const { id } = req.params;
    const { 
      sku, nome, descricao, fornecedor_id, filial_id, preco, 
      desconto_valor, desconto_percent, parcelavel, parcelas_max, ativo,
      categoria_id
    } = req.body;
    
    const coreDb = db.getCore();
    
    const produtoAntes = coreDb.prepare('SELECT * FROM produto WHERE id = ?').get(id);
    if (!produtoAntes) {
      return notFound(res, 'Produto não encontrado');
    }
    
    const updates = [];
    const params = [];
    
    if (sku !== undefined) { updates.push('sku = ?'); params.push(sku); }
    if (nome !== undefined) { updates.push('nome = ?'); params.push(nome); }
    if (descricao !== undefined) { updates.push('descricao = ?'); params.push(descricao); }
    if (fornecedor_id !== undefined) { updates.push('fornecedor_id = ?'); params.push(fornecedor_id); }
    if (filial_id !== undefined) { updates.push('filial_id = ?'); params.push(filial_id); }
    if (preco !== undefined) { updates.push('preco = ?'); params.push(preco); }
    if (desconto_valor !== undefined) { updates.push('desconto_valor = ?'); params.push(desconto_valor); }
    if (desconto_percent !== undefined) { updates.push('desconto_percent = ?'); params.push(desconto_percent); }
    if (parcelavel !== undefined) { updates.push('parcelavel = ?'); params.push(parcelavel ? 1 : 0); }
    if (parcelas_max !== undefined) { updates.push('parcelas_max = ?'); params.push(parcelas_max); }
    if (ativo !== undefined) { updates.push('ativo = ?'); params.push(ativo ? 1 : 0); }
    if (categoria_id !== undefined) { updates.push('categoria_id = ?'); params.push(categoria_id || null); }
    
    if (updates.length > 0) {
      updates.push('atualizado_em = datetime(\'now\')');
      params.push(id);
      coreDb.prepare(`UPDATE produto SET ${updates.join(', ')} WHERE id = ?`).run(...params);
    }
    
    const produtoDepois = coreDb.prepare('SELECT * FROM produto WHERE id = ?').get(id);
    
    auditService.logUpdate('produto', id, produtoAntes, produtoDepois, extractAuditInfo(req));
    
    logger.info('Produto atualizado', { produtoId: id });
    
    return success(res, produtoDepois, 'Produto atualizado com sucesso');
  } catch (error) {
    logger.error('Erro ao atualizar produto:', error);
    throw error;
  }
}

/**
 * PATCH /api/produtos/:id/status
 * Atualiza apenas status do produto
 */
function atualizarStatus(req, res) {
  try {
    const { id } = req.params;
    const { ativo } = req.body;
    
    const coreDb = db.getCore();
    
    const produto = coreDb.prepare('SELECT * FROM produto WHERE id = ?').get(id);
    if (!produto) {
      return notFound(res, 'Produto não encontrado');
    }
    
    coreDb.prepare(`
      UPDATE produto SET ativo = ?, atualizado_em = datetime('now') WHERE id = ?
    `).run(ativo ? 1 : 0, id);
    
    auditService.logStatusChange('produto', id, produto.ativo, ativo ? 1 : 0, extractAuditInfo(req));
    
    logger.info('Status do produto atualizado', { produtoId: id, ativo });
    
    return success(res, { id, ativo: ativo ? 1 : 0 }, 'Status atualizado com sucesso');
  } catch (error) {
    logger.error('Erro ao atualizar status:', error);
    throw error;
  }
}

/**
 * POST /api/produtos/:id/imagens
 * Upload de imagens do produto
 */
function uploadImagens(req, res) {
  try {
    const { id } = req.params;
    const coreDb = db.getCore();
    
    const produto = coreDb.prepare('SELECT id FROM produto WHERE id = ?').get(id);
    if (!produto) {
      return notFound(res, 'Produto não encontrado');
    }
    
    if (!req.files || req.files.length === 0) {
      return success(res, [], 'Nenhuma imagem enviada');
    }
    
    const imagens = [];
    const ultimaOrdem = coreDb.prepare('SELECT MAX(ordem) as max FROM produto_imagem WHERE produto_id = ?').get(id);
    let ordem = (ultimaOrdem.max || 0) + 1;
    
    for (const file of req.files) {
      const caminho = getRelativePath(file.path);
      
      const result = coreDb.prepare(`
        INSERT INTO produto_imagem (produto_id, caminho, mime, size_bytes, ordem)
        VALUES (?, ?, ?, ?, ?)
      `).run(id, caminho, file.mimetype, file.size, ordem++);
      
      imagens.push({
        id: result.lastInsertRowid,
        caminho,
        mime: file.mimetype,
        ordem: ordem - 1
      });
    }
    
    logger.info('Imagens do produto enviadas', { produtoId: id, quantidade: imagens.length });
    
    return created(res, imagens, 'Imagens enviadas com sucesso');
  } catch (error) {
    logger.error('Erro ao enviar imagens:', error);
    throw error;
  }
}

/**
 * DELETE /api/produtos/:id/imagens/:imagemId
 * Remove imagem do produto
 */
function removerImagem(req, res) {
  try {
    const { id, imagemId } = req.params;
    const coreDb = db.getCore();
    
    const imagem = coreDb.prepare(`
      SELECT * FROM produto_imagem WHERE id = ? AND produto_id = ?
    `).get(imagemId, id);
    
    if (!imagem) {
      return notFound(res, 'Imagem não encontrada');
    }
    
    // Remover arquivo físico
    const config = require('../config');
    const filePath = path.join(config.upload.path, imagem.caminho.replace('/uploads', ''));
    removeFile(filePath);
    
    // Remover do banco
    coreDb.prepare('DELETE FROM produto_imagem WHERE id = ?').run(imagemId);
    
    logger.info('Imagem do produto removida', { produtoId: id, imagemId });
    
    return success(res, null, 'Imagem removida com sucesso');
  } catch (error) {
    logger.error('Erro ao remover imagem:', error);
    throw error;
  }
}

module.exports = {
  criar,
  listar,
  buscar,
  atualizar,
  atualizarStatus,
  uploadImagens,
  removerImagem
};
