/**
 * BOUTIQUE DINIZ API - Utilitários de Paginação
 * Desenvolvido por Estúdio Atlas
 */

const config = require('../config');

/**
 * Extrai parâmetros de paginação da query
 */
function getPaginationParams(query) {
  let page = parseInt(query.page, 10) || 1;
  let pageSize = parseInt(query.page_size, 10) || config.pagination.defaultPageSize;
  
  // Limites
  if (page < 1) page = 1;
  if (pageSize < 1) pageSize = 1;
  if (pageSize > config.pagination.maxPageSize) pageSize = config.pagination.maxPageSize;
  
  const offset = (page - 1) * pageSize;
  
  return { page, pageSize, offset };
}

/**
 * Aplica paginação a uma query SQL
 */
function applyPagination(sql, offset, limit) {
  return `${sql} LIMIT ${limit} OFFSET ${offset}`;
}

/**
 * Gera objeto meta de paginação
 */
function getMeta(page, pageSize, total) {
  return {
    page: parseInt(page),
    page_size: parseInt(pageSize),
    total: parseInt(total),
    has_next: (page * pageSize) < total
  };
}

module.exports = {
  getPaginationParams,
  applyPagination,
  getMeta
};
