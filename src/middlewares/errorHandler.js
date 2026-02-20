/**
 * BOUTIQUE DINIZ API - Middleware de Tratamento de Erros
 * Desenvolvido por Estúdio Atlas
 */

const logger = require('../utils/logger');
const { internalError, validationError } = require('../utils/response');

/**
 * Handler de erros global
 */
function errorHandler(err, req, res, next) {
  // Log do erro
  logger.error('Erro não tratado:', {
    message: err.message,
    stack: err.stack,
    path: req.path,
    method: req.method,
    ip: req.ip
  });
  
  // Erro de validação do express-validator
  if (err.array && typeof err.array === 'function') {
    return validationError(res, err.array());
  }
  
  // Erro de JSON inválido
  if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
    return validationError(res, [{ field: 'body', issue: 'JSON inválido' }]);
  }
  
  // Erro de arquivo muito grande (Multer)
  if (err.code === 'LIMIT_FILE_SIZE') {
    return validationError(res, [{ field: 'file', issue: 'Arquivo muito grande' }]);
  }
  
  // Erro de tipo de arquivo não permitido
  if (err.code === 'LIMIT_UNEXPECTED_FILE') {
    return validationError(res, [{ field: 'file', issue: 'Tipo de arquivo não permitido' }]);
  }

  // Erro de tipo de arquivo personalizado (upload.js)
  if (err.message && err.message.toLowerCase().includes('tipo de arquivo')) {
    return validationError(res, [{ field: 'file', issue: err.message }]);
  }
  
  // Erro de banco de dados SQLite
  if (err.code && err.code.startsWith('SQLITE')) {
    logger.error('Erro de banco de dados:', err);
    
    if (err.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      return validationError(res, [{ field: 'unknown', issue: 'Registro duplicado' }]);
    }
    
    return internalError(res, 'Erro no banco de dados');
  }
  
  // Erro genérico
  return internalError(res, 
    process.env.NODE_ENV === 'development' 
      ? err.message 
      : 'Erro interno do servidor'
  );
}

/**
 * Handler para rotas não encontradas
 */
function notFoundHandler(req, res) {
  res.status(404).json({
    success: false,
    message: 'Rota não encontrada',
    error: {
      code: 'NOT_FOUND',
      details: {
        path: req.path,
        method: req.method
      }
    }
  });
}

module.exports = {
  errorHandler,
  notFoundHandler
};
