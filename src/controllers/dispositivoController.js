/**
 * BOUTIQUE DINIZ API - Controller de Autenticação de Dispositivos
 * Desenvolvido por Estúdio Atlas
 *
 * Fluxo de autenticação de dispositivo:
 *   1. Funcionário solicita autenticação → POST /api/dispositivos/solicitar
 *      - Envia: dispositivo_id (identificador único), funcionario_id
 *      - Sistema registra solicitação com status 'pendente'
 *      - Dispara webhook com: dispositivo_id, IP, nome do funcionário
 *
 *   2. Dono aprova/rejeita via serviço externo → POST /api/webhook/callback/dispositivo
 *      - Se aprovado: gera token persistente para o dispositivo
 *      - Se rejeitado: marca como rejeitado
 *
 *   3. Dispositivo consulta status → GET /api/dispositivos/status/:solicitacao_id
 *      - Retorna status atual e token se aprovado
 *
 *   4. Requisições futuras usam o token → GET /api/dispositivos/validar
 *      - Header: X-Device-Token: <token>
 *      - Se token válido: retorna dados do dispositivo/funcionário
 *      - Token não expira (persistente até revogação)
 */

const db = require('../config/database');
const {
  success, created, notFound, validationError, unauthorized, conflict
} = require('../utils/response');
const { getPaginationParams } = require('../utils/pagination');
const logger = require('../utils/logger');
const crypto = require('crypto');

/**
 * POST /api/dispositivos/solicitar
 * Solicita autenticação de um novo dispositivo
 */
function solicitar(req, res) {
  try {
    const { dispositivo_id, funcionario_id } = req.body;

    if (!dispositivo_id || !funcionario_id) {
      return validationError(res, [
        { field: 'dispositivo_id', issue: 'ID do dispositivo é obrigatório' },
        { field: 'funcionario_id', issue: 'ID do funcionário é obrigatório' }
      ]);
    }

    const authDb = db.getAuth();

    // Verificar se o funcionário existe
    const funcionario = authDb.prepare('SELECT * FROM usuario_sistema WHERE id = ? AND ativo = 1').get(funcionario_id);
    if (!funcionario) {
      return notFound(res, 'Funcionário não encontrado ou inativo');
    }

    // Verificar se já existe uma solicitação pendente para este dispositivo
    const pendente = authDb.prepare(`
      SELECT * FROM dispositivo_autenticacao
      WHERE dispositivo_id = ? AND usuario_id = ? AND status = 'pendente'
    `).get(dispositivo_id, funcionario_id);

    if (pendente) {
      return success(res, {
        solicitacao_id: pendente.id,
        status: 'pendente',
        mensagem: 'Já existe uma solicitação pendente para este dispositivo'
      });
    }

    // Verificar se já existe um token ativo para este dispositivo
    const ativo = authDb.prepare(`
      SELECT * FROM dispositivo_autenticacao
      WHERE dispositivo_id = ? AND usuario_id = ? AND status = 'aprovado'
    `).get(dispositivo_id, funcionario_id);

    if (ativo) {
      return success(res, {
        solicitacao_id: ativo.id,
        status: 'aprovado',
        mensagem: 'Este dispositivo já está autenticado'
      });
    }

    // Capturar IP e user-agent
    const ip = req.ip || req.connection.remoteAddress || 'desconhecido';
    const userAgent = req.headers['user-agent'] || 'desconhecido';

    // Criar solicitação
    const result = authDb.prepare(`
      INSERT INTO dispositivo_autenticacao (dispositivo_id, usuario_id, ip, user_agent, status)
      VALUES (?, ?, ?, ?, 'pendente')
    `).run(dispositivo_id, funcionario_id, ip, userAgent);

    const solicitacao = authDb.prepare('SELECT * FROM dispositivo_autenticacao WHERE id = ?').get(result.lastInsertRowid);

    // Disparar webhook para o dono aprovar
    try {
      const webhookService = require('../services/webhookService');
      webhookService.eventoDispositivoAutenticacao(solicitacao, funcionario);
    } catch (whErr) {
      logger.warn('Falha ao disparar webhook de autenticação de dispositivo:', whErr.message);
    }

    logger.info('Solicitação de autenticação de dispositivo criada', {
      solicitacaoId: solicitacao.id,
      dispositivoId: dispositivo_id,
      funcionarioId: funcionario_id
    });

    return created(res, {
      solicitacao_id: solicitacao.id,
      status: 'pendente',
      mensagem: 'Solicitação enviada. Aguardando aprovação do administrador.'
    }, 'Solicitação de autenticação criada');
  } catch (error) {
    logger.error('Erro ao solicitar autenticação de dispositivo:', error);
    throw error;
  }
}

/**
 * GET /api/dispositivos/status/:solicitacaoId
 * Consulta o status de uma solicitação de autenticação
 */
function consultarStatus(req, res) {
  try {
    const { solicitacaoId } = req.params;
    const authDb = db.getAuth();

    const solicitacao = authDb.prepare(`
      SELECT da.*, us.nome_completo AS funcionario_nome, us.login AS funcionario_login
      FROM dispositivo_autenticacao da
      JOIN usuario_sistema us ON da.usuario_id = us.id
      WHERE da.id = ?
    `).get(solicitacaoId);

    if (!solicitacao) {
      return notFound(res, 'Solicitação não encontrada');
    }

    const response = {
      solicitacao_id: solicitacao.id,
      dispositivo_id: solicitacao.dispositivo_id,
      funcionario_nome: solicitacao.funcionario_nome,
      status: solicitacao.status,
      criado_em: solicitacao.criado_em
    };

    // Se aprovado, não retorna o token aqui por segurança
    // O token é retornado apenas no callback de aprovação
    if (solicitacao.status === 'aprovado') {
      response.aprovado_em = solicitacao.aprovado_em;
      response.mensagem = 'Dispositivo aprovado. Use o token recebido no callback.';
    } else if (solicitacao.status === 'rejeitado') {
      response.mensagem = 'Dispositivo rejeitado pelo administrador.';
    } else {
      response.mensagem = 'Aguardando aprovação do administrador.';
    }

    return success(res, response);
  } catch (error) {
    logger.error('Erro ao consultar status do dispositivo:', error);
    throw error;
  }
}

/**
 * GET /api/dispositivos/validar
 * Valida um token de dispositivo
 * Header: X-Device-Token: <token>
 *
 * Se o token for válido, retorna os dados do dispositivo e funcionário.
 * O token é persistente — não precisa reautenticar.
 */
function validarToken(req, res) {
  try {
    const token = req.headers['x-device-token'];

    if (!token) {
      return unauthorized(res, 'Token de dispositivo não fornecido. Use o header X-Device-Token.');
    }

    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const authDb = db.getAuth();

    const dispositivo = authDb.prepare(`
      SELECT da.*, us.nome_completo AS funcionario_nome, us.login AS funcionario_login,
             us.email AS funcionario_email, us.telefone AS funcionario_telefone
      FROM dispositivo_autenticacao da
      JOIN usuario_sistema us ON da.usuario_id = us.id
      WHERE da.token_hash = ? AND da.status = 'aprovado'
    `).get(tokenHash);

    if (!dispositivo) {
      return unauthorized(res, 'Token de dispositivo inválido ou revogado');
    }

    // Atualizar último uso
    authDb.prepare("UPDATE dispositivo_autenticacao SET ultimo_uso = datetime('now') WHERE id = ?").run(dispositivo.id);

    return success(res, {
      valido: true,
      dispositivo_id: dispositivo.dispositivo_id,
      funcionario: {
        id: dispositivo.usuario_id,
        nome: dispositivo.funcionario_nome,
        login: dispositivo.funcionario_login,
        email: dispositivo.funcionario_email,
        telefone: dispositivo.funcionario_telefone
      },
      aprovado_em: dispositivo.aprovado_em,
      ultimo_uso: dispositivo.ultimo_uso
    }, 'Token válido');
  } catch (error) {
    logger.error('Erro ao validar token de dispositivo:', error);
    throw error;
  }
}

/**
 * DELETE /api/dispositivos/:id/revogar
 * Revoga a autenticação de um dispositivo (admin)
 */
function revogar(req, res) {
  try {
    const { id } = req.params;
    const authDb = db.getAuth();

    const dispositivo = authDb.prepare('SELECT * FROM dispositivo_autenticacao WHERE id = ?').get(id);
    if (!dispositivo) {
      return notFound(res, 'Dispositivo não encontrado');
    }

    authDb.prepare("UPDATE dispositivo_autenticacao SET status = 'revogado', token_hash = NULL WHERE id = ?").run(id);

    logger.info('Dispositivo revogado', { dispositivoId: dispositivo.dispositivo_id });

    return success(res, null, 'Autenticação do dispositivo revogada com sucesso');
  } catch (error) {
    logger.error('Erro ao revogar dispositivo:', error);
    throw error;
  }
}

/**
 * GET /api/dispositivos
 * Lista todos os dispositivos autenticados (admin)
 */
function listar(req, res) {
  try {
    const { page, pageSize, offset } = getPaginationParams(req.query);
    const { status, funcionario_id } = req.query;

    const authDb = db.getAuth();

    let sql = `
      SELECT da.*, us.nome_completo AS funcionario_nome, us.login AS funcionario_login
      FROM dispositivo_autenticacao da
      JOIN usuario_sistema us ON da.usuario_id = us.id
      WHERE 1=1
    `;
    const params = [];

    if (status) {
      sql += ' AND da.status = ?';
      params.push(status);
    }
    if (funcionario_id) {
      sql += ' AND da.usuario_id = ?';
      params.push(funcionario_id);
    }

    let wherePart = sql.substring(sql.indexOf('WHERE'));
    const countSql = `SELECT COUNT(*) as total FROM dispositivo_autenticacao da
      JOIN usuario_sistema us ON da.usuario_id = us.id
      ${wherePart}`;
    const countResult = authDb.prepare(countSql).get(...params);
    const total = countResult ? countResult.total : 0;

    sql += ' ORDER BY da.criado_em DESC LIMIT ? OFFSET ?';
    params.push(pageSize, offset);

    const dispositivos = authDb.prepare(sql).all(...params);

    return require('../utils/response').successPaginated(res, dispositivos, page, pageSize, total);
  } catch (error) {
    logger.error('Erro ao listar dispositivos:', error);
    throw error;
  }
}

module.exports = {
  solicitar,
  consultarStatus,
  validarToken,
  revogar,
  listar
};
