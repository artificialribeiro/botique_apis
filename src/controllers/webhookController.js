/**
 * BOUTIQUE DINIZ API - Controller de Webhook
 * Desenvolvido por Estúdio Atlas
 *
 * Gerencia a configuração do webhook e consulta de logs de envio.
 * Também expõe endpoint para receber callbacks (ex.: aprovação de dispositivo).
 */

const db = require('../config/database');
const {
  success, successPaginated, created, notFound, validationError
} = require('../utils/response');
const { getPaginationParams } = require('../utils/pagination');
const logger = require('../utils/logger');

// ============================================
// CONFIGURAÇÃO DO WEBHOOK
// ============================================

/**
 * GET /api/webhook/config
 * Retorna a configuração atual do webhook
 */
function getConfig(req, res) {
  try {
    const authDb = db.getAuth();
    const config = authDb.prepare('SELECT * FROM webhook_config WHERE id = 1').get();

    if (!config) {
      return success(res, {
        url: process.env.WEBHOOK_URL || null,
        secret: process.env.WEBHOOK_SECRET ? '***configurado***' : null,
        ativo: !!process.env.WEBHOOK_URL,
        origem: 'env'
      }, 'Configuração via variável de ambiente');
    }

    return success(res, {
      id: config.id,
      url: config.url,
      secret: config.secret ? '***configurado***' : null,
      ativo: !!config.ativo,
      origem: 'banco',
      criado_em: config.criado_em,
      atualizado_em: config.atualizado_em
    });
  } catch (error) {
    logger.error('Erro ao buscar config webhook:', error);
    throw error;
  }
}

/**
 * PUT /api/webhook/config
 * Atualiza a configuração do webhook
 */
function updateConfig(req, res) {
  try {
    const { url, secret, ativo } = req.body;

    if (!url) {
      return validationError(res, [{ field: 'url', issue: 'URL do webhook é obrigatória' }]);
    }

    const authDb = db.getAuth();

    const existing = authDb.prepare('SELECT id FROM webhook_config WHERE id = 1').get();

    if (existing) {
      authDb.prepare(`
        UPDATE webhook_config SET url = ?, secret = ?, ativo = ?, atualizado_em = datetime('now')
        WHERE id = 1
      `).run(url, secret || null, ativo !== undefined ? (ativo ? 1 : 0) : 1);
    } else {
      authDb.prepare(`
        INSERT INTO webhook_config (id, url, secret, ativo) VALUES (1, ?, ?, ?)
      `).run(url, secret || null, ativo !== undefined ? (ativo ? 1 : 0) : 1);
    }

    const config = authDb.prepare('SELECT * FROM webhook_config WHERE id = 1').get();

    logger.info('Configuração de webhook atualizada', { url });

    return success(res, {
      ...config,
      secret: config.secret ? '***configurado***' : null
    }, 'Webhook configurado com sucesso');
  } catch (error) {
    logger.error('Erro ao atualizar config webhook:', error);
    throw error;
  }
}

/**
 * POST /api/webhook/testar
 * Envia um evento de teste para o webhook configurado
 */
function testar(req, res) {
  try {
    const webhookService = require('../services/webhookService');
    const config = webhookService.getWebhookConfig();

    if (!config.ativo || !config.url) {
      return validationError(res, [{ field: 'url', issue: 'Webhook não está configurado ou está inativo' }]);
    }

    webhookService.dispararEvento('teste.ping', {
      mensagem: 'Teste de conexão do webhook Boutique Diniz',
      timestamp: new Date().toISOString()
    }, {
      email: 'teste@boutiqudiniz.com',
      telefone: null,
      nome: 'Sistema'
    });

    return success(res, { url: config.url }, 'Evento de teste enviado. Verifique o serviço receptor.');
  } catch (error) {
    logger.error('Erro ao testar webhook:', error);
    throw error;
  }
}

// ============================================
// LOGS DE WEBHOOK
// ============================================

/**
 * GET /api/webhook/logs
 * Lista logs de envio de webhook
 */
function listarLogs(req, res) {
  try {
    const { page, pageSize, offset } = getPaginationParams(req.query);
    const { event_type, status } = req.query;

    const authDb = db.getAuth();

    let sql = 'SELECT * FROM webhook_log WHERE 1=1';
    const params = [];

    if (event_type) {
      sql += ' AND event_type = ?';
      params.push(event_type);
    }
    if (status) {
      sql += ' AND status = ?';
      params.push(status);
    }

    let wherePart = sql.substring(sql.indexOf('WHERE'));
    const countSql = `SELECT COUNT(*) as total FROM webhook_log ${wherePart}`;
    const countResult = authDb.prepare(countSql).get(...params);
    const total = countResult ? countResult.total : 0;

    sql += ' ORDER BY criado_em DESC LIMIT ? OFFSET ?';
    params.push(pageSize, offset);

    const logs = authDb.prepare(sql).all(...params);

    return successPaginated(res, logs, page, pageSize, total);
  } catch (error) {
    logger.error('Erro ao listar logs webhook:', error);
    throw error;
  }
}

// ============================================
// CALLBACK DE DISPOSITIVO (recebe resposta do serviço externo)
// ============================================

/**
 * POST /api/webhook/callback/dispositivo
 * Recebe a resposta do serviço externo sobre aprovação/rejeição de dispositivo
 *
 * Body esperado:
 * {
 *   solicitacao_id: number,
 *   aprovado: boolean,
 *   aprovado_por: string (nome do dono)
 * }
 */
function callbackDispositivo(req, res) {
  try {
    const { solicitacao_id, aprovado, aprovado_por } = req.body;

    if (!solicitacao_id || aprovado === undefined) {
      return validationError(res, [
        { field: 'solicitacao_id', issue: 'ID da solicitação é obrigatório' },
        { field: 'aprovado', issue: 'Campo aprovado (true/false) é obrigatório' }
      ]);
    }

    const authDb = db.getAuth();

    const solicitacao = authDb.prepare('SELECT * FROM dispositivo_autenticacao WHERE id = ?').get(solicitacao_id);
    if (!solicitacao) {
      return notFound(res, 'Solicitação de autenticação não encontrada');
    }

    if (solicitacao.status !== 'pendente') {
      return success(res, solicitacao, 'Solicitação já foi processada anteriormente');
    }

    if (aprovado) {
      // Gerar token de dispositivo
      const crypto = require('crypto');
      const token = crypto.randomBytes(48).toString('hex');
      const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

      authDb.prepare(`
        UPDATE dispositivo_autenticacao SET
          status = 'aprovado',
          token_hash = ?,
          aprovado_por = ?,
          aprovado_em = datetime('now')
        WHERE id = ?
      `).run(tokenHash, aprovado_por || 'dono', solicitacao_id);

      const solicitacaoAtualizada = authDb.prepare('SELECT * FROM dispositivo_autenticacao WHERE id = ?').get(solicitacao_id);

      // Disparar evento de aprovação
      const webhookService = require('../services/webhookService');
      webhookService.dispararEvento(
        webhookService.WEBHOOK_EVENTS.DISPOSITIVO_AUTENTICACAO_APROVADA,
        {
          solicitacao_id,
          dispositivo_id: solicitacao.dispositivo_id,
          token: token, // Token em texto claro para o dispositivo armazenar
          funcionario_id: solicitacao.usuario_id
        }
      );

      logger.info('Dispositivo aprovado', { solicitacaoId: solicitacao_id, dispositivoId: solicitacao.dispositivo_id });

      return success(res, {
        ...solicitacaoAtualizada,
        token: token // Retorna o token em texto claro apenas nesta resposta
      }, 'Dispositivo aprovado e token gerado');
    } else {
      // Rejeitar
      authDb.prepare(`
        UPDATE dispositivo_autenticacao SET
          status = 'rejeitado',
          aprovado_por = ?,
          aprovado_em = datetime('now')
        WHERE id = ?
      `).run(aprovado_por || 'dono', solicitacao_id);

      const webhookService = require('../services/webhookService');
      webhookService.dispararEvento(
        webhookService.WEBHOOK_EVENTS.DISPOSITIVO_AUTENTICACAO_REJEITADA,
        { solicitacao_id, dispositivo_id: solicitacao.dispositivo_id }
      );

      logger.info('Dispositivo rejeitado', { solicitacaoId: solicitacao_id });

      return success(res, null, 'Dispositivo rejeitado');
    }
  } catch (error) {
    logger.error('Erro no callback de dispositivo:', error);
    throw error;
  }
}

module.exports = {
  getConfig,
  updateConfig,
  testar,
  listarLogs,
  callbackDispositivo
};
