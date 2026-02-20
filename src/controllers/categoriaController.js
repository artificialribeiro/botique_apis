/**
 * BOUTIQUE DINIZ API - Controller de Categorias de Produtos
 *
 * Este controlador gerencia as categorias dos produtos. Permite listar, criar,
 * buscar e atualizar categorias. As categorias possuem nome, logo (imagem)
 * e uma imagem principal opcional. As imagens são armazenadas no disco
 * (pasta uploads/categorias) e convertidas para base64 quando retornadas
 * pela API para evitar problemas com caminhos de URLs externos.
 */

const fs = require('fs');
const path = require('path');
const db = require('../config/database');
const config = require('../config');
const { success, successPaginated, created, notFound, validationError } = require('../utils/response');
const { getPaginationParams } = require('../utils/pagination');
const { extractAuditInfo } = require('../middlewares/auth');
const auditService = require('../services/auditService');
const logger = require('../utils/logger');
const { getRelativePath } = require('../middlewares/upload');

/**
 * Utilitário: Converte uma imagem armazenada no disco em uma string Base64.
 * Recebe o caminho relativo (começando com '/uploads') e retorna uma data URI
 * com tipo MIME apropriado. Se o arquivo não existir, retorna null.
 */
function toBase64(caminho) {
  if (!caminho) return null;
  // Remover prefixo '/uploads' se presente e normalizar sem barras iniciais
  const relative = caminho.replace(/^\/?uploads\/?/, '');
  const filePath = path.join(config.upload.path, relative);
  try {
    const buffer = fs.readFileSync(filePath);
    // Determinar tipo MIME pela extensão do arquivo
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
 * GET /api/categorias
 * Lista categorias com paginação opcional e filtros
 */
function listar(req, res) {
  try {
    const { page, pageSize, offset } = getPaginationParams(req.query);
    const { q, ativo } = req.query;
    const coreDb = db.getCore();
    let sql = 'SELECT * FROM categoria WHERE 1=1';
    const params = [];
    if (q) {
      sql += ' AND nome LIKE ?';
      params.push(`%${q}%`);
    }
    if (ativo !== undefined) {
      sql += ' AND ativo = ?';
      params.push(parseInt(ativo));
    }
    // Contar total
    const countSql = sql.replace(/SELECT \*/i, 'SELECT COUNT(*) as total');
    const { total } = coreDb.prepare(countSql).get(...params);
    // Buscar registros com paginação
    sql += ' ORDER BY criado_em DESC LIMIT ? OFFSET ?';
    params.push(pageSize, offset);
    const categorias = coreDb.prepare(sql).all(...params);
    // Converter imagens para Base64
    categorias.forEach(cat => {
      cat.logo_base64 = toBase64(cat.logo_caminho);
      cat.imagem_base64 = toBase64(cat.imagem_caminho);
    });
    return successPaginated(res, categorias, page, pageSize, total);
  } catch (error) {
    logger.error('Erro ao listar categorias:', error);
    throw error;
  }
}

/**
 * GET /api/categorias/:id
 * Retorna categoria específica
 */
function buscar(req, res) {
  try {
    const { id } = req.params;
    const coreDb = db.getCore();
    const cat = coreDb.prepare('SELECT * FROM categoria WHERE id = ?').get(id);
    if (!cat) {
      return notFound(res, 'Categoria não encontrada');
    }
    cat.logo_base64 = toBase64(cat.logo_caminho);
    cat.imagem_base64 = toBase64(cat.imagem_caminho);
    return success(res, cat);
  } catch (error) {
    logger.error('Erro ao buscar categoria:', error);
    throw error;
  }
}

/**
 * POST /api/categorias
 * Cria nova categoria. Aceita campos nome, ativo e upload de arquivos
 * (logo e imagem) via multipart/form-data. Os arquivos são processados
 * pelo middleware de upload e armazenados no disco. Retorna a categoria
 * criada.
 */
function criar(req, res) {
  try {
    const { nome, ativo } = req.body;
    if (!nome) {
      return validationError(res, [{ field: 'nome', issue: 'Nome é obrigatório' }]);
    }
    const coreDb = db.getCore();
    // Manipular uploads: multer armazena arquivos em req.files
    let logoCaminho = null;
    let imagemCaminho = null;
    if (req.files && req.files.logo && req.files.logo[0]) {
      logoCaminho = getRelativePath(req.files.logo[0].path);
    }
    if (req.files && req.files.imagem && req.files.imagem[0]) {
      imagemCaminho = getRelativePath(req.files.imagem[0].path);
    }
    const result = coreDb.prepare(`
      INSERT INTO categoria (nome, logo_caminho, imagem_caminho, ativo)
      VALUES (?, ?, ?, ?)
    `).run(nome, logoCaminho, imagemCaminho, ativo !== undefined ? (ativo ? 1 : 0) : 1);
    const id = result.lastInsertRowid;
    const categoria = coreDb.prepare('SELECT * FROM categoria WHERE id = ?').get(id);
    categoria.logo_base64 = toBase64(categoria.logo_caminho);
    categoria.imagem_base64 = toBase64(categoria.imagem_caminho);
    // Registrar auditoria
    auditService.logCreate('categoria', id, categoria, extractAuditInfo(req));
    logger.info('Categoria criada', { categoriaId: id });
    return created(res, categoria, 'Categoria criada com sucesso');
  } catch (error) {
    logger.error('Erro ao criar categoria:', error);
    throw error;
  }
}

/**
 * PUT /api/categorias/:id
 * Atualiza uma categoria existente. Aceita alteração de nome, ativo e
 * reenvio de logo/imagem. Se novos arquivos forem enviados, remove os
 * antigos do disco. O corpo da requisição pode ser multipart/form-data.
 */
function atualizar(req, res) {
  try {
    const { id } = req.params;
    const { nome, ativo } = req.body;
    const coreDb = db.getCore();
    const categoriaAntes = coreDb.prepare('SELECT * FROM categoria WHERE id = ?').get(id);
    if (!categoriaAntes) {
      return notFound(res, 'Categoria não encontrada');
    }
    let logoCaminho = categoriaAntes.logo_caminho;
    let imagemCaminho = categoriaAntes.imagem_caminho;
    // Se novos arquivos foram enviados, salvar e remover antigos
    if (req.files && req.files.logo && req.files.logo[0]) {
      // Remover arquivo antigo
      if (categoriaAntes.logo_caminho) {
        const oldPath = path.join(config.upload.path, categoriaAntes.logo_caminho.replace(/^\/?uploads\/?/, ''));
        if (fs.existsSync(oldPath)) {
          fs.unlinkSync(oldPath);
        }
      }
      logoCaminho = getRelativePath(req.files.logo[0].path);
    }
    if (req.files && req.files.imagem && req.files.imagem[0]) {
      if (categoriaAntes.imagem_caminho) {
        const oldPath = path.join(config.upload.path, categoriaAntes.imagem_caminho.replace(/^\/?uploads\/?/, ''));
        if (fs.existsSync(oldPath)) {
          fs.unlinkSync(oldPath);
        }
      }
      imagemCaminho = getRelativePath(req.files.imagem[0].path);
    }
    // Construir cláusulas de atualização
    const updates = [];
    const params = [];
    if (nome !== undefined) {
      updates.push('nome = ?');
      params.push(nome);
    }
    if (ativo !== undefined) {
      updates.push('ativo = ?');
      params.push(ativo ? 1 : 0);
    }
    if (logoCaminho !== categoriaAntes.logo_caminho) {
      updates.push('logo_caminho = ?');
      params.push(logoCaminho);
    }
    if (imagemCaminho !== categoriaAntes.imagem_caminho) {
      updates.push('imagem_caminho = ?');
      params.push(imagemCaminho);
    }
    if (updates.length > 0) {
      updates.push('atualizado_em = datetime(\'now\')');
      const sql = `UPDATE categoria SET ${updates.join(', ')} WHERE id = ?`;
      params.push(id);
      coreDb.prepare(sql).run(...params);
    }
    const categoriaDepois = coreDb.prepare('SELECT * FROM categoria WHERE id = ?').get(id);
    categoriaDepois.logo_base64 = toBase64(categoriaDepois.logo_caminho);
    categoriaDepois.imagem_base64 = toBase64(categoriaDepois.imagem_caminho);
    auditService.logUpdate('categoria', id, categoriaAntes, categoriaDepois, extractAuditInfo(req));
    logger.info('Categoria atualizada', { categoriaId: id });
    return success(res, categoriaDepois, 'Categoria atualizada com sucesso');
  } catch (error) {
    logger.error('Erro ao atualizar categoria:', error);
    throw error;
  }
}

module.exports = {
  listar,
  buscar,
  criar,
  atualizar
};