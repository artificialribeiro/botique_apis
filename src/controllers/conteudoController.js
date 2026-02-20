/**
 * BOUTIQUE DINIZ API - Controller de Conteúdo (Banners, Cupons, Notificações, Pós-venda)
 * Desenvolvido por Estúdio Atlas
 */

const db = require('../config/database');
const { success, successPaginated, created, notFound, validationError } = require('../utils/response');
const { getPaginationParams } = require('../utils/pagination');
const auditService = require('../services/auditService');
const { extractAuditInfo } = require('../middlewares/auth');
const { getRelativePath, removeFile } = require('../middlewares/upload');
const logger = require('../utils/logger');
const path = require('path');

// ============================================
// BANNERS
// ============================================

/**
 * POST /api/banners
 * Cria banner
 */
function criarBanner(req, res) {
  try {
    const { titulo, link, ativo, ordem } = req.body;
    const coreDb = db.getCore();
    
    if (!req.file) {
      return validationError(res, [{ field: 'imagem', issue: 'Imagem é obrigatória' }]);
    }
    
    const caminho = getRelativePath(req.file.path);
    
    const result = coreDb.prepare(`
      INSERT INTO banner (titulo, caminho_imagem, link, ativo, ordem)
      VALUES (?, ?, ?, ?, ?)
    `).run(titulo || null, caminho, link || null, ativo !== undefined ? ativo : 1, ordem || 0);
    
    const banner = coreDb.prepare('SELECT * FROM banner WHERE id = ?').get(result.lastInsertRowid);
    
    auditService.logCreate('banner', banner.id, banner, extractAuditInfo(req));
    
    logger.info('Banner criado', { bannerId: banner.id });
    
    return created(res, banner, 'Banner criado com sucesso');
  } catch (error) {
    logger.error('Erro ao criar banner:', error);
    throw error;
  }
}

/**
 * GET /api/banners
 * Lista banners
 */
function listarBanners(req, res) {
  try {
    const { ativo } = req.query;
    const coreDb = db.getCore();
    
    let sql = 'SELECT * FROM banner WHERE 1=1';
    const params = [];
    
    if (ativo !== undefined) {
      sql += ' AND ativo = ?';
      params.push(parseInt(ativo));
    }
    
    sql += ' ORDER BY ordem ASC, criado_em DESC';
    
    const banners = coreDb.prepare(sql).all(...params);
    
    return success(res, banners);
  } catch (error) {
    logger.error('Erro ao listar banners:', error);
    throw error;
  }
}

/**
 * PUT /api/banners/:id
 * Atualiza banner
 */
function atualizarBanner(req, res) {
  try {
    const { id } = req.params;
    const { titulo, link, ativo, ordem } = req.body;
    
    const coreDb = db.getCore();
    
    const bannerAntes = coreDb.prepare('SELECT * FROM banner WHERE id = ?').get(id);
    if (!bannerAntes) {
      return notFound(res, 'Banner não encontrado');
    }
    
    const updates = [];
    const params = [];
    
    if (titulo !== undefined) { updates.push('titulo = ?'); params.push(titulo); }
    if (link !== undefined) { updates.push('link = ?'); params.push(link); }
    if (ativo !== undefined) { updates.push('ativo = ?'); params.push(ativo ? 1 : 0); }
    if (ordem !== undefined) { updates.push('ordem = ?'); params.push(ordem); }
    
    if (req.file) {
      // Remover imagem antiga
      const config = require('../config');
      const oldPath = path.join(config.upload.path, bannerAntes.caminho_imagem.replace('/uploads', ''));
      removeFile(oldPath);
      
      updates.push('caminho_imagem = ?');
      params.push(getRelativePath(req.file.path));
    }
    
    if (updates.length > 0) {
      params.push(id);
      coreDb.prepare(`UPDATE banner SET ${updates.join(', ')} WHERE id = ?`).run(...params);
    }
    
    const bannerDepois = coreDb.prepare('SELECT * FROM banner WHERE id = ?').get(id);
    
    auditService.logUpdate('banner', id, bannerAntes, bannerDepois, extractAuditInfo(req));
    
    logger.info('Banner atualizado', { bannerId: id });
    
    return success(res, bannerDepois, 'Banner atualizado com sucesso');
  } catch (error) {
    logger.error('Erro ao atualizar banner:', error);
    throw error;
  }
}

/**
 * DELETE /api/banners/:id
 * Remove banner
 */
function removerBanner(req, res) {
  try {
    const { id } = req.params;
    const coreDb = db.getCore();
    
    const banner = coreDb.prepare('SELECT * FROM banner WHERE id = ?').get(id);
    if (!banner) {
      return notFound(res, 'Banner não encontrado');
    }
    
    // Remover imagem
    const config = require('../config');
    const filePath = path.join(config.upload.path, banner.caminho_imagem.replace('/uploads', ''));
    removeFile(filePath);
    
    coreDb.prepare('DELETE FROM banner WHERE id = ?').run(id);
    
    auditService.logDelete('banner', id, banner, extractAuditInfo(req));
    
    logger.info('Banner removido', { bannerId: id });
    
    return success(res, null, 'Banner removido com sucesso');
  } catch (error) {
    logger.error('Erro ao remover banner:', error);
    throw error;
  }
}

// ============================================
// CUPONS
// ============================================

/**
 * POST /api/cupons
 * Cria cupom
 */
function criarCupom(req, res) {
  try {
    const { codigo, percentual, valor_fixo, quantidade_total, data_inicio, data_fim } = req.body;
    const coreDb = db.getCore();
    
    const result = coreDb.prepare(`
      INSERT INTO cupom (codigo, percentual, valor_fixo, quantidade_total, data_inicio, data_fim)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(codigo.toUpperCase(), percentual || null, valor_fixo || null, quantidade_total, data_inicio || null, data_fim || null);
    
    const cupom = coreDb.prepare('SELECT * FROM cupom WHERE id = ?').get(result.lastInsertRowid);
    
    auditService.logCreate('cupom', cupom.id, cupom, extractAuditInfo(req));
    
    logger.info('Cupom criado', { cupomId: cupom.id, codigo });
    
    return created(res, cupom, 'Cupom criado com sucesso');
  } catch (error) {
    logger.error('Erro ao criar cupom:', error);
    throw error;
  }
}

/**
 * GET /api/cupons
 * Lista cupons
 */
function listarCupons(req, res) {
  try {
    const { page, pageSize, offset } = getPaginationParams(req.query);
    const { ativo } = req.query;
    
    const coreDb = db.getCore();
    
    let sql = 'SELECT * FROM cupom WHERE 1=1';
    const params = [];
    
    if (ativo !== undefined) {
      sql += ' AND ativo = ?';
      params.push(parseInt(ativo));
    }
    
    const countSql = sql.replace('SELECT *', 'SELECT COUNT(*) as total');
    const { total } = coreDb.prepare(countSql).get(...params);
    
    sql += ' ORDER BY criado_em DESC LIMIT ? OFFSET ?';
    params.push(pageSize, offset);
    
    const cupons = coreDb.prepare(sql).all(...params);
    
    return successPaginated(res, cupons, page, pageSize, total);
  } catch (error) {
    logger.error('Erro ao listar cupons:', error);
    throw error;
  }
}

/**
 * POST /api/cupons/validar
 * Valida cupom
 */
function validarCupom(req, res) {
  try {
    const { codigo, valor_carrinho } = req.body;
    const coreDb = db.getCore();
    
    const cupom = coreDb.prepare(`
      SELECT * FROM cupom 
      WHERE codigo = ? AND ativo = 1 
      AND (data_inicio IS NULL OR date(data_inicio) <= date('now'))
      AND (data_fim IS NULL OR date(data_fim) >= date('now'))
      AND quantidade_usada < quantidade_total
    `).get(codigo.toUpperCase());
    
    if (!cupom) {
      return success(res, { valido: false }, 'Cupom inválido ou expirado');
    }
    
    let desconto = 0;
    if (cupom.percentual) {
      desconto = valor_carrinho * (cupom.percentual / 100);
    } else if (cupom.valor_fixo) {
      desconto = Math.min(cupom.valor_fixo, valor_carrinho);
    }
    
    return success(res, {
      valido: true,
      cupom: {
        codigo: cupom.codigo,
        tipo: cupom.percentual ? 'percentual' : 'valor_fixo',
        valor: cupom.percentual || cupom.valor_fixo
      },
      desconto: parseFloat(desconto.toFixed(2)),
      valor_final: parseFloat((valor_carrinho - desconto).toFixed(2))
    }, 'Cupom válido');
  } catch (error) {
    logger.error('Erro ao validar cupom:', error);
    throw error;
  }
}

// ============================================
// NOTIFICAÇÕES
// ============================================

/**
 * POST /api/notificacoes
 * Cria notificação
 */
function criarNotificacao(req, res) {
  try {
    const { cliente_id, titulo, mensagem, link } = req.body;
    const coreDb = db.getCore();
    
    const result = coreDb.prepare(`
      INSERT INTO notificacao (cliente_id, titulo, mensagem, link)
      VALUES (?, ?, ?, ?)
    `).run(cliente_id || null, titulo, mensagem, link || null);
    
    const notificacao = coreDb.prepare('SELECT * FROM notificacao WHERE id = ?').get(result.lastInsertRowid);
    
    logger.info('Notificação criada', { notificacaoId: notificacao.id });
    
    return created(res, notificacao, 'Notificação criada com sucesso');
  } catch (error) {
    logger.error('Erro ao criar notificação:', error);
    throw error;
  }
}

/**
 * GET /api/notificacoes
 * Lista notificações
 */
function listarNotificacoes(req, res) {
  try {
    const { page, pageSize, offset } = getPaginationParams(req.query);
    const { cliente_id, lida } = req.query;
    
    const coreDb = db.getCore();
    
    let sql = 'SELECT * FROM notificacao WHERE 1=1';
    const params = [];
    
    if (cliente_id) {
      sql += ' AND (cliente_id = ? OR cliente_id IS NULL)';
      params.push(cliente_id);
    }
    
    if (lida !== undefined) {
      sql += ' AND lida = ?';
      params.push(parseInt(lida));
    }
    
    const countSql = sql.replace('SELECT *', 'SELECT COUNT(*) as total');
    const { total } = coreDb.prepare(countSql).get(...params);
    
    sql += ' ORDER BY criado_em DESC LIMIT ? OFFSET ?';
    params.push(pageSize, offset);
    
    const notificacoes = coreDb.prepare(sql).all(...params);
    
    return successPaginated(res, notificacoes, page, pageSize, total);
  } catch (error) {
    logger.error('Erro ao listar notificações:', error);
    throw error;
  }
}

/**
 * PUT /api/notificacoes/:id
 * Marca notificação como lida
 */
function marcarLida(req, res) {
  try {
    const { id } = req.params;
    const coreDb = db.getCore();
    
    const notificacao = coreDb.prepare('SELECT id FROM notificacao WHERE id = ?').get(id);
    if (!notificacao) {
      return notFound(res, 'Notificação não encontrada');
    }
    
    coreDb.prepare('UPDATE notificacao SET lida = 1 WHERE id = ?').run(id);
    
    return success(res, { id, lida: 1 }, 'Notificação marcada como lida');
  } catch (error) {
    logger.error('Erro ao marcar notificação:', error);
    throw error;
  }
}

// ============================================
// PÓS-VENDA
// ============================================

/**
 * POST /api/posvenda
 * Cria cancelamento/devolução
 */
function criarPosVenda(req, res) {
  try {
    const { pedido_id, tipo, motivo } = req.body;
    const coreDb = db.getCore();
    
    const pedido = coreDb.prepare('SELECT id, total FROM pedido WHERE id = ?').get(pedido_id);
    if (!pedido) {
      return notFound(res, 'Pedido não encontrado');
    }
    
    const result = coreDb.prepare(`
      INSERT INTO cancelamento_devolucao (pedido_id, tipo, motivo, status_reembolso, valor_reembolso)
      VALUES (?, ?, ?, 'pendente', ?)
    `).run(pedido_id, tipo, motivo, pedido.total);
    
    const posvenda = coreDb.prepare('SELECT * FROM cancelamento_devolucao WHERE id = ?').get(result.lastInsertRowid);
    
    auditService.logCreate('cancelamento_devolucao', posvenda.id, posvenda, extractAuditInfo(req));
    
    logger.info('Pós-venda criado', { posvendaId: posvenda.id, tipo });
    
    return created(res, posvenda, `${tipo === 'cancelamento' ? 'Cancelamento' : 'Devolução'} registrado com sucesso`);
  } catch (error) {
    logger.error('Erro ao criar pós-venda:', error);
    throw error;
  }
}

/**
 * GET /api/posvenda
 * Lista pós-vendas
 */
function listarPosVenda(req, res) {
  try {
    const { page, pageSize, offset } = getPaginationParams(req.query);
    const { tipo, status_reembolso } = req.query;
    
    const coreDb = db.getCore();
    
    let sql = `
      SELECT cd.*, p.cliente_id, c.nome_completo as cliente_nome
      FROM cancelamento_devolucao cd
      JOIN pedido p ON cd.pedido_id = p.id
      JOIN cliente c ON p.cliente_id = c.id
      WHERE 1=1
    `;
    const params = [];
    
    if (tipo) {
      sql += ' AND cd.tipo = ?';
      params.push(tipo);
    }
    
    if (status_reembolso) {
      sql += ' AND cd.status_reembolso = ?';
      params.push(status_reembolso);
    }
    
    let posVendaWhere = sql.substring(sql.indexOf('WHERE'));
    const countSql = `SELECT COUNT(*) as total FROM cancelamento_devolucao cd
      JOIN pedido p ON cd.pedido_id = p.id
      JOIN cliente c ON p.cliente_id = c.id
      ${posVendaWhere}`;
    const countResult = coreDb.prepare(countSql).get(...params);
    const total = countResult ? countResult.total : 0;
    
    sql += ' ORDER BY cd.criado_em DESC LIMIT ? OFFSET ?';
    params.push(pageSize, offset);
    
    const posvendas = coreDb.prepare(sql).all(...params);
    
    return successPaginated(res, posvendas, page, pageSize, total);
  } catch (error) {
    logger.error('Erro ao listar pós-vendas:', error);
    throw error;
  }
}

/**
 * PATCH /api/posvenda/:id/status-reembolso
 * Atualiza status do reembolso
 */
function atualizarStatusReembolso(req, res) {
  try {
    const { id } = req.params;
    const { status_reembolso, processado_por_usuario_id } = req.body;
    
    const coreDb = db.getCore();
    
    const posvenda = coreDb.prepare('SELECT * FROM cancelamento_devolucao WHERE id = ?').get(id);
    if (!posvenda) {
      return notFound(res, 'Registro não encontrado');
    }
    
    const statusAnterior = posvenda.status_reembolso;
    
    coreDb.prepare(`
      UPDATE cancelamento_devolucao 
      SET status_reembolso = ?, processado_por_usuario_id = ?, atualizado_em = datetime('now')
      WHERE id = ?
    `).run(status_reembolso, processado_por_usuario_id || null, id);
    
    auditService.logStatusChange('cancelamento_devolucao', id, statusAnterior, status_reembolso, extractAuditInfo(req));
    
    logger.info('Status de reembolso atualizado', { posvendaId: id, status: status_reembolso });
    
    return success(res, { id, status_reembolso }, 'Status atualizado com sucesso');
  } catch (error) {
    logger.error('Erro ao atualizar status:', error);
    throw error;
  }
}

// ============================================
// RECLAMAÇÕES
// ============================================

/**
 * POST /api/reclamacoes
 * Cria reclamação
 */
function criarReclamacao(req, res) {
  try {
    const { pedido_id, cliente_id, descricao } = req.body;
    const coreDb = db.getCore();
    
    const result = coreDb.prepare(`
      INSERT INTO reclamacao (pedido_id, cliente_id, descricao)
      VALUES (?, ?, ?)
    `).run(pedido_id, cliente_id, descricao);
    
    const reclamacao = coreDb.prepare('SELECT * FROM reclamacao WHERE id = ?').get(result.lastInsertRowid);
    
    auditService.logCreate('reclamacao', reclamacao.id, reclamacao, extractAuditInfo(req));
    
    logger.info('Reclamação criada', { reclamacaoId: reclamacao.id });
    
    return created(res, reclamacao, 'Reclamação registrada com sucesso');
  } catch (error) {
    logger.error('Erro ao criar reclamação:', error);
    throw error;
  }
}

/**
 * POST /api/reclamacoes/:id/midia
 * Upload de mídia da reclamação
 */
function uploadMidiaReclamacao(req, res) {
  try {
    const { id } = req.params;
    const coreDb = db.getCore();
    
    const reclamacao = coreDb.prepare('SELECT id FROM reclamacao WHERE id = ?').get(id);
    if (!reclamacao) {
      return notFound(res, 'Reclamação não encontrada');
    }
    
    if (!req.files || req.files.length === 0) {
      return success(res, [], 'Nenhuma mídia enviada');
    }
    
    const midias = [];
    
    for (const file of req.files) {
      const caminho = getRelativePath(file.path);
      const tipo = file.mimetype.startsWith('video/') ? 'video' : 'imagem';
      
      const result = coreDb.prepare(`
        INSERT INTO reclamacao_midia (reclamacao_id, tipo, caminho, mime, size_bytes)
        VALUES (?, ?, ?, ?, ?)
      `).run(id, tipo, caminho, file.mimetype, file.size);
      
      midias.push({
        id: result.lastInsertRowid,
        tipo,
        caminho,
        mime: file.mimetype
      });
    }
    
    logger.info('Mídias da reclamação enviadas', { reclamacaoId: id, quantidade: midias.length });
    
    return created(res, midias, 'Mídias enviadas com sucesso');
  } catch (error) {
    logger.error('Erro ao enviar mídias:', error);
    throw error;
  }
}

/**
 * GET /api/reclamacoes
 * Lista reclamações
 */
function listarReclamacoes(req, res) {
  try {
    const { page, pageSize, offset } = getPaginationParams(req.query);
    const { status, cliente_id } = req.query;
    
    const coreDb = db.getCore();
    
    let sql = `
      SELECT r.*, c.nome_completo as cliente_nome
      FROM reclamacao r
      JOIN cliente c ON r.cliente_id = c.id
      WHERE 1=1
    `;
    const params = [];
    
    if (status) {
      sql += ' AND r.status = ?';
      params.push(status);
    }
    
    if (cliente_id) {
      sql += ' AND r.cliente_id = ?';
      params.push(cliente_id);
    }
    
    let reclamacaoWhere = sql.substring(sql.indexOf('WHERE'));
    const countSqlR = `SELECT COUNT(*) as total FROM reclamacao r
      JOIN cliente c ON r.cliente_id = c.id
      ${reclamacaoWhere}`;
    const countResultR = coreDb.prepare(countSqlR).get(...params);
    const total = countResultR ? countResultR.total : 0;
    
    sql += ' ORDER BY r.criado_em DESC LIMIT ? OFFSET ?';
    params.push(pageSize, offset);
    
    const reclamacoes = coreDb.prepare(sql).all(...params);
    
    // Buscar mídias de cada reclamação
    reclamacoes.forEach(r => {
      r.midias = coreDb.prepare('SELECT * FROM reclamacao_midia WHERE reclamacao_id = ?').all(r.id);
    });
    
    return successPaginated(res, reclamacoes, page, pageSize, total);
  } catch (error) {
    logger.error('Erro ao listar reclamações:', error);
    throw error;
  }
}

/**
 * PUT /api/reclamacoes/:id
 * Atualiza reclamação
 */
function atualizarReclamacao(req, res) {
  try {
    const { id } = req.params;
    const { status, descricao } = req.body;
    
    const coreDb = db.getCore();
    
    const reclamacaoAntes = coreDb.prepare('SELECT * FROM reclamacao WHERE id = ?').get(id);
    if (!reclamacaoAntes) {
      return notFound(res, 'Reclamação não encontrada');
    }
    
    const updates = [];
    const params = [];
    
    if (status !== undefined) { updates.push('status = ?'); params.push(status); }
    if (descricao !== undefined) { updates.push('descricao = ?'); params.push(descricao); }
    
    if (updates.length > 0) {
      updates.push('atualizado_em = datetime(\'now\')');
      params.push(id);
      coreDb.prepare(`UPDATE reclamacao SET ${updates.join(', ')} WHERE id = ?`).run(...params);
    }
    
    const reclamacaoDepois = coreDb.prepare('SELECT * FROM reclamacao WHERE id = ?').get(id);
    
    if (status && status !== reclamacaoAntes.status) {
      auditService.logStatusChange('reclamacao', id, reclamacaoAntes.status, status, extractAuditInfo(req));
    }
    
    logger.info('Reclamação atualizada', { reclamacaoId: id });
    
    return success(res, reclamacaoDepois, 'Reclamação atualizada com sucesso');
  } catch (error) {
    logger.error('Erro ao atualizar reclamação:', error);
    throw error;
  }
}

// ============================================
// TEMA
// ============================================

/**
 * GET /api/tema
 * Retorna configurações de tema
 */
function getTema(req, res) {
  try {
    const coreDb = db.getCore();
    
    const tema = coreDb.prepare('SELECT * FROM tema WHERE id = 1').get();
    const banners = coreDb.prepare('SELECT * FROM banner WHERE ativo = 1 ORDER BY ordem').all();
    
    return success(res, {
      ...tema,
      banners
    });
  } catch (error) {
    logger.error('Erro ao buscar tema:', error);
    throw error;
  }
}

/**
 * PUT /api/tema
 * Atualiza configurações de tema
 */
function atualizarTema(req, res) {
  try {
    const { cor_primaria, cor_secundaria, cor_destaque, logo_path, favicon_path } = req.body;
    const coreDb = db.getCore();
    
    const updates = [];
    const params = [];
    
    if (cor_primaria !== undefined) { updates.push('cor_primaria = ?'); params.push(cor_primaria); }
    if (cor_secundaria !== undefined) { updates.push('cor_secundaria = ?'); params.push(cor_secundaria); }
    if (cor_destaque !== undefined) { updates.push('cor_destaque = ?'); params.push(cor_destaque); }
    if (logo_path !== undefined) { updates.push('logo_path = ?'); params.push(logo_path); }
    if (favicon_path !== undefined) { updates.push('favicon_path = ?'); params.push(favicon_path); }
    
    if (updates.length > 0) {
      updates.push('atualizado_em = datetime(\'now\')');
      coreDb.prepare(`UPDATE tema SET ${updates.join(', ')} WHERE id = 1`).run(...params);
    }
    
    const tema = coreDb.prepare('SELECT * FROM tema WHERE id = 1').get();
    
    logger.info('Tema atualizado');
    
    return success(res, tema, 'Tema atualizado com sucesso');
  } catch (error) {
    logger.error('Erro ao atualizar tema:', error);
    throw error;
  }
}

module.exports = {
  // Banners
  criarBanner,
  listarBanners,
  atualizarBanner,
  removerBanner,
  // Cupons
  criarCupom,
  listarCupons,
  validarCupom,
  // Notificações
  criarNotificacao,
  listarNotificacoes,
  marcarLida,
  // Pós-venda
  criarPosVenda,
  listarPosVenda,
  atualizarStatusReembolso,
  // Reclamações
  criarReclamacao,
  uploadMidiaReclamacao,
  listarReclamacoes,
  atualizarReclamacao,
  // Tema
  getTema,
  atualizarTema
};
