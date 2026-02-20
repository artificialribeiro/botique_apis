/**
 * BOUTIQUE DINIZ API - Controller do Sistema
 * Desenvolvido por Estúdio Atlas
 */

const db = require('../config/database');
const config = require('../config');
const { success, unauthorized } = require('../utils/response');
const { generateToken, sha256 } = require('../utils/crypto');
const logger = require('../utils/logger');

/**
 * GET /api/health
 * Verifica status do servidor
 */
function health(req, res) {
  try {
    // Verificar conexão com bancos
    const coreDb = db.getCore();
    const authDb = db.getAuth();
    const auditDb = db.getAudit();
    
    // Testar queries simples
    coreDb.prepare('SELECT 1').get();
    authDb.prepare('SELECT 1').get();
    auditDb.prepare('SELECT 1').get();
    
    return success(res, {
      status: 'online',
      timestamp: new Date().toISOString(),
      version: config.api.version,
      environment: config.env,
      databases: {
        core: 'connected',
        auth: 'connected',
        audit: 'connected'
      },
      developer: 'Estúdio Atlas'
    }, 'Sistema operacional');
  } catch (error) {
    logger.error('Erro no health check:', error);
    return success(res, {
      status: 'degraded',
      timestamp: new Date().toISOString(),
      version: config.api.version,
      error: error.message
    }, 'Sistema com problemas');
  }
}

/**
 * POST /api/token
 * Gera token de integração
 */
function gerarToken(req, res) {
  try {
    const apiKey = req.headers['x-api-key'];
    
    // Verificar API Key
    if (!apiKey || apiKey !== config.security.apiKey) {
      logger.warn('Tentativa de gerar token com API Key inválida', { ip: req.ip });
      return unauthorized(res, 'API Key inválida');
    }
    
    const authDb = db.getAuth();
    
    // Gerar token
    const token = generateToken(16); // 32 caracteres hex
    const tokenHash = sha256(token);
    const expiresAt = new Date(Date.now() + config.security.tokenExpirationSeconds * 1000).toISOString();
    
    // Salvar token (apenas o hash)
    authDb.prepare(`
      INSERT INTO integracao_token (token_hash, expira_em)
      VALUES (?, ?)
    `).run(tokenHash, expiresAt);
    
    logger.info('Token de integração gerado', { ip: req.ip });
    
    return success(res, {
      token,
      expires_in_seconds: config.security.tokenExpirationSeconds
    }, 'Token gerado com sucesso');
  } catch (error) {
    logger.error('Erro ao gerar token:', error);
    throw error;
  }
}

/**
 * POST /api/token/revoke
 * Revoga token de integração
 */
function revogarToken(req, res) {
  try {
    const { token } = req.body;
    
    if (!token) {
      return unauthorized(res, 'Token não fornecido');
    }
    
    const authDb = db.getAuth();
    const tokenHash = sha256(token);
    
    const result = authDb.prepare(`
      UPDATE integracao_token 
      SET revogado = 1 
      WHERE token_hash = ?
    `).run(tokenHash);
    
    if (result.changes === 0) {
      return unauthorized(res, 'Token não encontrado');
    }
    
    logger.info('Token revogado', { ip: req.ip });
    
    return success(res, null, 'Token revogado com sucesso');
  } catch (error) {
    logger.error('Erro ao revogar token:', error);
    throw error;
  }
}

/**
 * Limpa tokens expirados (chamado pelo cron)
 */
function limparTokensExpirados() {
  try {
    const authDb = db.getAuth();
    
    const result = authDb.prepare(`
      DELETE FROM integracao_token 
      WHERE datetime(expira_em) < datetime('now')
      OR revogado = 1
    `).run();
    
    if (result.changes > 0) {
      logger.info(`${result.changes} tokens expirados removidos`);
    }
  } catch (error) {
    logger.error('Erro ao limpar tokens:', error);
  }
}

module.exports = {
  health,
  gerarToken,
  revogarToken,
  limparTokensExpirados
};
