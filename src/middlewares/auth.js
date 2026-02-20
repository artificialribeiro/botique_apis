/**
 * BOUTIQUE DINIZ API - Middleware de Autenticação
 * Desenvolvido por Estúdio Atlas
 */

const config = require('../config');
const db = require('../config/database');
const { unauthorized, forbidden } = require('../utils/response');
const { sha256 } = require('../utils/crypto');
const logger = require('../utils/logger');

/**
 * Verifica API Key (obrigatório em todas as rotas protegidas)
 */
function verifyApiKey(req, res, next) {
  const apiKey = req.headers['x-api-key'];
  
  if (!apiKey) {
    logger.warn('Requisição sem API Key', { ip: req.ip, path: req.path });
    return unauthorized(res, 'API Key não fornecida');
  }
  
  if (apiKey !== config.security.apiKey) {
    logger.warn('API Key inválida', { ip: req.ip, path: req.path });
    return unauthorized(res, 'API Key inválida');
  }
  
  next();
}

/**
 * Verifica Token de Integração
 */
function verifyToken(req, res, next) {
  // Lê token do cabeçalho "x-api-token" ou do padrão "Authorization: Bearer <token>"
  let token = req.headers['x-api-token'];
  if (!token && req.headers['authorization']) {
    const authHeader = req.headers['authorization'];
    const parts = authHeader.split(' ');
    if (parts.length === 2 && /^Bearer$/i.test(parts[0])) {
      token = parts[1];
    }
  }

  if (!token) {
    logger.warn('Requisição sem Token', { ip: req.ip, path: req.path });
    return unauthorized(res, 'Token de integração não fornecido');
  }

  try {
    const authDb = db.getAuth();
    const tokenHash = sha256(token);

    const tokenRecord = authDb.prepare(`
      SELECT * FROM integracao_token 
      WHERE token_hash = ? 
        AND revogado = 0 
        AND datetime(expira_em) > datetime('now')
    `).get(tokenHash);

    if (!tokenRecord) {
      logger.warn('Token inválido ou expirado', { ip: req.ip, path: req.path });
      return unauthorized(res, 'Token inválido ou expirado');
    }

    req.tokenId = tokenRecord.id;
    next();
  } catch (error) {
    logger.error('Erro ao verificar token:', error);
    return unauthorized(res, 'Erro ao verificar token');
  }
}

/**
 * Middleware combinado: API Key + Token
 */
function authenticate(req, res, next) {
  verifyApiKey(req, res, (err) => {
    if (err) return;
    verifyToken(req, res, next);
  });
}

/**
 * Verifica permissão específica
 */
function requirePermission(permissaoCodigo) {
  return (req, res, next) => {
    const usuarioId = req.headers['x-user-id'];
    
    if (!usuarioId) {
      return forbidden(res, 'Usuário não identificado');
    }
    
    try {
      const authDb = db.getAuth();
      
      // Buscar permissões do usuário
      // A relação entre usuários e permissões é intermediada pela tabela
      // grupo_permissao, que utiliza a coluna grupo_id para referenciar
      // grupo_acesso. A condição anterior usava gp.grupo_acesso_id,
      // coluna inexistente, gerando erro e impedindo validação correta.
      const hasPermission = authDb.prepare(`
        SELECT 1 FROM usuario_sistema u
        JOIN grupo_permissao gp ON u.grupo_acesso_id = gp.grupo_id
        JOIN permissao p ON gp.permissao_id = p.id
        WHERE u.id = ? AND p.codigo = ? AND u.ativo = 1
      `).get(usuarioId, permissaoCodigo);
      
      if (!hasPermission) {
        logger.warn('Acesso negado', { usuarioId, permissao: permissaoCodigo });
        return forbidden(res, 'Você não tem permissão para esta ação');
      }
      
      req.usuarioId = usuarioId;
      next();
    } catch (error) {
      logger.error('Erro ao verificar permissão:', error);
      return forbidden(res, 'Erro ao verificar permissão');
    }
  };
}

/**
 * Extrai informações do request para auditoria
 */
function extractAuditInfo(req) {
  return {
    ip: req.ip || req.connection.remoteAddress,
    userAgent: req.headers['user-agent'],
    usuarioId: req.headers['x-user-id'] || null,
    usuarioTipo: req.headers['x-user-type'] || 'sistema'
  };
}

module.exports = {
  verifyApiKey,
  verifyToken,
  authenticate,
  requirePermission,
  extractAuditInfo
};
