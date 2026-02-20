/**
 * BOUTIQUE DINIZ API - Validadores Comuns
 * Desenvolvido por Estúdio Atlas
 */

const { body, param, query, validationResult } = require('express-validator');
const { validationError } = require('../utils/response');
const { validateCpf, normalizeCpf } = require('../utils/crypto');

/**
 * Middleware para processar erros de validação
 */
const handleValidation = (req, res, next) => {
  const errors = validationResult(req);
  
  if (!errors.isEmpty()) {
    const details = errors.array().map(err => ({
      field: err.path || err.param,
      issue: err.msg
    }));
    return validationError(res, details);
  }
  
  next();
};

/**
 * Validação de ID
 */
const validateId = [
  param('id')
    .isInt({ min: 1 })
    .withMessage('ID deve ser um número inteiro positivo'),
  handleValidation
];

/**
 * Validação de CPF
 */
const cpfValidator = body('cpf')
  .notEmpty().withMessage('CPF é obrigatório')
  .customSanitizer(value => normalizeCpf(value || ''))
  .custom(value => {
    if (!validateCpf(value)) {
      throw new Error('CPF inválido');
    }
    return true;
  });

/**
 * Validação de e-mail
 */
const emailValidator = body('email')
  .optional()
  .isEmail().withMessage('E-mail inválido')
  .normalizeEmail();

/**
 * Validação de celular
 */
const celularValidator = body('celular')
  .optional()
  .matches(/^\d{10,11}$/).withMessage('Celular deve ter 10 ou 11 dígitos');

/**
 * Validação de senha
 */
const senhaValidator = body('senha')
  .isLength({ min: 6 }).withMessage('Senha deve ter no mínimo 6 caracteres')
  .matches(/[A-Z]/).withMessage('Senha deve conter pelo menos uma letra maiúscula')
  .matches(/[a-z]/).withMessage('Senha deve conter pelo menos uma letra minúscula')
  .matches(/[0-9]/).withMessage('Senha deve conter pelo menos um número');

/**
 * Validação de paginação
 */
const paginationValidator = [
  query('page')
    .optional()
    .isInt({ min: 1 }).withMessage('Página deve ser um número inteiro positivo'),
  query('page_size')
    .optional()
    .isInt({ min: 1, max: 100 }).withMessage('Tamanho da página deve ser entre 1 e 100'),
  handleValidation
];

/**
 * Validação de data ISO
 */
const dateValidator = (field) => body(field)
  .optional()
  .isISO8601().withMessage(`${field} deve ser uma data válida (ISO 8601)`);

/**
 * Validação de valor monetário
 */
const moneyValidator = (field) => body(field)
  .isFloat({ min: 0 }).withMessage(`${field} deve ser um valor monetário válido`);

/**
 * Validação de quantidade
 */
const quantityValidator = (field) => body(field)
  .isInt({ min: 1 }).withMessage(`${field} deve ser um número inteiro positivo`);

/**
 * Validação de status de pedido
 */
const statusPedidoValidator = body('status_pedido')
  .isIn(['novo', 'separando', 'enviado', 'entregue', 'cancelado', 'devolvido'])
  .withMessage('Status de pedido inválido');

/**
 * Validação de status de pagamento
 */
const statusPagamentoValidator = body('status_pagamento')
  .isIn(['aguardando', 'pago', 'recusado', 'estornado', 'reembolsado'])
  .withMessage('Status de pagamento inválido');

module.exports = {
  handleValidation,
  validateId,
  cpfValidator,
  emailValidator,
  celularValidator,
  senhaValidator,
  paginationValidator,
  dateValidator,
  moneyValidator,
  quantityValidator,
  statusPedidoValidator,
  statusPagamentoValidator
};
