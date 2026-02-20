/**
 * BOUTIQUE DINIZ API - Utilitários de Resposta
 * Desenvolvido por Estúdio Atlas
 * 
 * Padrão de resposta:
 * - Sucesso: { success: true, message?, data, meta? }
 * - Erro: { success: false, message, error: { code, details? } }
 */

/**
 * Resposta de sucesso
 */
function success(res, data, message = null, meta = null, statusCode = 200) {
  const response = {
    success: true,
    data
  };
  
  if (message) {
    response.message = message;
  }
  
  if (meta) {
    response.meta = meta;
  }
  
  return res.status(statusCode).json(response);
}

/**
 * Resposta de sucesso com paginação
 */
function successPaginated(res, data, page, pageSize, total, message = null) {
  const hasNext = (page * pageSize) < total;
  
  return success(res, data, message, {
    page: parseInt(page),
    page_size: parseInt(pageSize),
    total: parseInt(total),
    has_next: hasNext
  });
}

/**
 * Resposta de erro
 */
function error(res, message, code = 'INTERNAL_ERROR', details = null, statusCode = 500) {
  const response = {
    success: false,
    message,
    error: {
      code
    }
  };
  
  if (details) {
    response.error.details = details;
  }
  
  return res.status(statusCode).json(response);
}

/**
 * Erro de validação
 */
function validationError(res, details) {
  return error(res, 'Erro de validação', 'VALIDATION_ERROR', details, 400);
}

/**
 * Erro de não autorizado
 */
function unauthorized(res, message = 'Não autorizado') {
  return error(res, message, 'UNAUTHORIZED', null, 401);
}

/**
 * Erro de proibido
 */
function forbidden(res, message = 'Acesso negado') {
  return error(res, message, 'FORBIDDEN', null, 403);
}

/**
 * Erro de não encontrado
 */
function notFound(res, message = 'Recurso não encontrado') {
  return error(res, message, 'NOT_FOUND', null, 404);
}

/**
 * Erro de conflito
 */
function conflict(res, message = 'Conflito de dados') {
  return error(res, message, 'CONFLICT', null, 409);
}

/**
 * Erro interno
 */
function internalError(res, message = 'Erro interno do servidor') {
  return error(res, message, 'INTERNAL_ERROR', null, 500);
}

/**
 * Resposta de criação
 */
function created(res, data, message = 'Recurso criado com sucesso') {
  return success(res, data, message, null, 201);
}

/**
 * Resposta sem conteúdo
 */
function noContent(res) {
  return res.status(204).send();
}

module.exports = {
  success,
  successPaginated,
  error,
  validationError,
  unauthorized,
  forbidden,
  notFound,
  conflict,
  internalError,
  created,
  noContent
};
