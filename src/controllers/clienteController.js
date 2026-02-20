/**
 * BOUTIQUE DINIZ API - Controller de Clientes
 * Desenvolvido por Estúdio Atlas
 */

const db = require('../config/database');
const { success, successPaginated, created, notFound, conflict, unauthorized } = require('../utils/response');
const { hashPasswordSync, verifyPasswordSync, sha256, normalizeCpf, generateRecoveryCode } = require('../utils/crypto');
const { getPaginationParams } = require('../utils/pagination');
const auditService = require('../services/auditService');
const notificacaoService = require('../services/notificacaoService');
const { extractAuditInfo } = require('../middlewares/auth');
const logger = require('../utils/logger');

/**
 * POST /api/clientes/login
 * Login do cliente
 */
function login(req, res) {
  try {
    const { cpf, senha } = req.body;
    const cpfNormalizado = normalizeCpf(cpf);
    const cpfHash = sha256(cpfNormalizado);
    
    const coreDb = db.getCore();
    
    const cliente = coreDb.prepare(`
      SELECT id, nome_completo, cpf, email, celular, senha_hash, ativo
      FROM cliente WHERE cpf_hash = ?
    `).get(cpfHash);
    
    if (!cliente) {
      logger.warn('Tentativa de login com CPF não cadastrado', { cpf: cpfNormalizado });
      return unauthorized(res, 'CPF ou senha inválidos');
    }
    
    if (!cliente.ativo) {
      return unauthorized(res, 'Cliente inativo');
    }
    
    if (!cliente.senha_hash || !verifyPasswordSync(senha, cliente.senha_hash)) {
      logger.warn('Tentativa de login com senha incorreta', { clienteId: cliente.id });
      return unauthorized(res, 'CPF ou senha inválidos');
    }
    
    // Registrar login na auditoria
    auditService.logLogin(cliente.id, 'cliente', extractAuditInfo(req));
    
    // Enviar notificação de login
    notificacaoService.notificarLogin({
      id: cliente.id,
      nome_completo: cliente.nome_completo,
      cpf: cliente.cpf,
      email: cliente.email,
      ip: req.ip,
      navegador: req.headers['user-agent']
    }).catch(err => {
      logger.error('Erro ao enviar notificação de login', err);
    });
    
    // Remover senha do retorno
    delete cliente.senha_hash;
    
    logger.info('Login de cliente realizado', { clienteId: cliente.id });
    
    return success(res, cliente, 'Login realizado com sucesso');
  } catch (error) {
    logger.error('Erro no login:', error);
    throw error;
  }
}

/**
 * POST /api/clientes/recuperar-senha
 * Gera código de recuperação
 */
function recuperarSenha(req, res) {
  try {
    const { cpf } = req.body;
    const cpfNormalizado = normalizeCpf(cpf);
    const cpfHash = sha256(cpfNormalizado);
    
    const coreDb = db.getCore();
    const authDb = db.getAuth();
    
    const cliente = coreDb.prepare(`
      SELECT id, email FROM cliente WHERE cpf_hash = ? AND ativo = 1
    `).get(cpfHash);
    
    if (!cliente) {
      // Por segurança, não informamos se o CPF existe ou não
      return success(res, null, 'Se o CPF estiver cadastrado, um código será enviado para o e-mail');
    }
    
    if (!cliente.email) {
      return success(res, null, 'Se o CPF estiver cadastrado, um código será enviado para o e-mail');
    }
    
    // Gerar código
    const codigo = generateRecoveryCode();
    // Armazenamos sempre o hash do código em maiúsculo. Caso o código
    // contenha letras (ex.: ABCD), a função generateRecoveryCode já
    // retorna em maiúsculo, mas reforçamos para evitar discrepâncias.
    const codigoHash = sha256(codigo.toUpperCase());
    const expiraEm = new Date(Date.now() + 30 * 60 * 1000).toISOString(); // 30 minutos
    
    // Salvar código
    authDb.prepare(`
      INSERT INTO recuperacao_senha (cliente_id, codigo_hash, expira_em)
      VALUES (?, ?, ?)
    `).run(cliente.id, codigoHash, expiraEm);
    
    // Enviar notificação de recuperação de senha
    notificacaoService.notificarRecuperacaoSenha(cliente, codigo).catch(err => {
      logger.error('Erro ao enviar notificação de recuperação de senha', err);
    });
    
    logger.info('Código de recuperação gerado', { clienteId: cliente.id, codigo });
    
    return success(res, null, 'Código enviado para o e-mail cadastrado');
  } catch (error) {
    logger.error('Erro na recuperação de senha:', error);
    throw error;
  }
}

/**
 * POST /api/clientes/redefinir-senha
 * Redefine senha com código
 */
function redefinirSenha(req, res) {
  try {
    const { cpf, codigo, nova_senha } = req.body;
    const cpfNormalizado = normalizeCpf(cpf);
    const cpfHash = sha256(cpfNormalizado);
    // Comparação de código deve ser case-insensível. Muitas vezes o usuário
    // insere letras minúsculas, enquanto o código enviado é maiúsculo.
    // Para evitar rejeição injusta, normalizamos para maiúsculo antes de
    // aplicar SHA‑256.
    const codigoHash = sha256(String(codigo).toUpperCase());
    
    const coreDb = db.getCore();
    const authDb = db.getAuth();
    
    const cliente = coreDb.prepare(`
      SELECT id, nome_completo, email FROM cliente WHERE cpf_hash = ? AND ativo = 1
    `).get(cpfHash);
    
    if (!cliente) {
      return unauthorized(res, 'Dados inválidos');
    }
    
    // Verificar código
    const recuperacao = authDb.prepare(`
      SELECT id FROM recuperacao_senha 
      WHERE cliente_id = ? 
      AND codigo_hash = ? 
      AND datetime(expira_em) > datetime('now')
      AND usado_em IS NULL
    `).get(cliente.id, codigoHash);
    
    if (!recuperacao) {
      return unauthorized(res, 'Código inválido ou expirado');
    }
    
    // Atualizar senha
    const senhaHash = hashPasswordSync(nova_senha);
    coreDb.prepare(`
      UPDATE cliente SET senha_hash = ?, atualizado_em = datetime('now')
      WHERE id = ?
    `).run(senhaHash, cliente.id);
    
    // Marcar código como usado
    authDb.prepare(`
      UPDATE recuperacao_senha SET usado_em = datetime('now')
      WHERE id = ?
    `).run(recuperacao.id);
    
    // Enviar email de confirmação
    if (cliente.email) {
      notificacaoService.notificarSenhaRedefinida({
        id: cliente.id,
        nome_completo: cliente.nome_completo,
        email: cliente.email,
        ip: req.ip,
        navegador: req.headers['user-agent']
      }).catch(err => {
        logger.error('Erro ao enviar email de senha redefinida', err);
      });
    }
    
    logger.info('Senha redefinida com sucesso', { clienteId: cliente.id });
    
    return success(res, null, 'Senha redefinida com sucesso');
  } catch (error) {
    logger.error('Erro ao redefinir senha:', error);
    throw error;
  }
}

/**
 * POST /api/clientes
 * Cria novo cliente
 */
function criar(req, res) {
  try {
    const { nome_completo, cpf, email, celular, sexo, senha } = req.body;
    
    if (!cpf) {
      return res.status(400).json({ success: false, message: 'CPF é obrigatório' });
    }

    const cpfNormalizado = normalizeCpf(cpf);
    
    // Validar formato do CPF
    const { validateCpf } = require('../utils/crypto');
    if (!validateCpf(cpfNormalizado)) {
      return res.status(400).json({ success: false, message: 'CPF inválido' });
    }

    const cpfHash = sha256(cpfNormalizado);
    const coreDb = db.getCore();
    
    // Verificar se CPF já existe (usando o hash para busca rápida e segura)
    const existente = coreDb.prepare('SELECT id FROM cliente WHERE cpf_hash = ?').get(cpfHash);
    if (existente) {
      logger.warn('Tentativa de cadastro com CPF já existente', { cpf: cpfNormalizado });
      return conflict(res, 'Este CPF já possui uma conta cadastrada');
    }
    
    const senhaHash = senha ? hashPasswordSync(senha) : null;
    
    const result = coreDb.prepare(`
      INSERT INTO cliente (nome_completo, cpf, cpf_hash, email, celular, sexo, senha_hash)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(nome_completo, cpfNormalizado, cpfHash, email || null, celular || null, sexo || null, senhaHash);
    
    const cliente = coreDb.prepare('SELECT * FROM cliente WHERE id = ?').get(result.lastInsertRowid);
    delete cliente.senha_hash;
    delete cliente.cpf_hash;
    
    // Auditoria
    auditService.logCreate('cliente', cliente.id, cliente, extractAuditInfo(req));
    
    // Enviar email de boas-vindas
    if (cliente.email) {
      notificacaoService.notificarBoasVindas({
        id: cliente.id,
        nome_completo: cliente.nome_completo,
        cpf: cliente.cpf,
        email: cliente.email
      }).catch(err => {
        logger.error('Erro ao enviar email de boas-vindas', err);
      });
    }
    
    logger.info('Cliente criado com sucesso', { clienteId: cliente.id });
    
    return created(res, cliente, 'Cliente criado com sucesso');
  } catch (error) {
    logger.error('Erro ao criar cliente:', error);
    throw error;
  }
}

/**
 * GET /api/clientes
 * Lista clientes com paginação
 */
function listar(req, res) {
  try {
    const { page, pageSize, offset } = getPaginationParams(req.query);
    const { q, ativo } = req.query;
    
    const coreDb = db.getCore();
    
    let sql = 'SELECT id, nome_completo, cpf, email, celular, sexo, ativo, criado_em FROM cliente WHERE 1=1';
    const params = [];
    
    if (q) {
      sql += ' AND (nome_completo LIKE ? OR email LIKE ? OR celular LIKE ?)';
      const search = `%${q}%`;
      params.push(search, search, search);
    }
    
    if (ativo !== undefined) {
      sql += ' AND ativo = ?';
      params.push(parseInt(ativo));
    }
    
    // Contar total
    const countSql = sql.replace('SELECT id, nome_completo, cpf, email, celular, sexo, ativo, criado_em', 'SELECT COUNT(*) as total');
    const { total } = coreDb.prepare(countSql).get(...params);
    
    // Buscar com paginação
    sql += ' ORDER BY criado_em DESC LIMIT ? OFFSET ?';
    params.push(pageSize, offset);
    
    const clientes = coreDb.prepare(sql).all(...params);
    
    return successPaginated(res, clientes, page, pageSize, total);
  } catch (error) {
    logger.error('Erro ao listar clientes:', error);
    throw error;
  }
}

/**
 * GET /api/clientes/:id
 * Busca cliente por ID
 */
function buscar(req, res) {
  try {
    const { id } = req.params;
    const coreDb = db.getCore();
    
    const cliente = coreDb.prepare(`
      SELECT id, nome_completo, cpf, email, celular, sexo, ativo, criado_em, atualizado_em
      FROM cliente WHERE id = ?
    `).get(id);
    
    if (!cliente) {
      return notFound(res, 'Cliente não encontrado');
    }
    
    return success(res, cliente);
  } catch (error) {
    logger.error('Erro ao buscar cliente:', error);
    throw error;
  }
}

/**
 * PUT /api/clientes/:id
 * Atualiza cliente
 */
function atualizar(req, res) {
  try {
    const { id } = req.params;
    const { nome_completo, email, celular, sexo, ativo, senha } = req.body;
    
    const coreDb = db.getCore();
    
    // Buscar cliente atual
    const clienteAntes = coreDb.prepare('SELECT * FROM cliente WHERE id = ?').get(id);
    if (!clienteAntes) {
      return notFound(res, 'Cliente não encontrado');
    }
    
    // Montar update dinâmico
    const updates = [];
    const params = [];
    
    if (nome_completo !== undefined) {
      updates.push('nome_completo = ?');
      params.push(nome_completo);
    }
    if (email !== undefined) {
      updates.push('email = ?');
      params.push(email);
    }
    if (celular !== undefined) {
      updates.push('celular = ?');
      params.push(celular);
    }
    if (sexo !== undefined) {
      updates.push('sexo = ?');
      params.push(sexo);
    }
    if (ativo !== undefined) {
      updates.push('ativo = ?');
      params.push(ativo);
    }
    if (senha) {
      updates.push('senha_hash = ?');
      params.push(hashPasswordSync(senha));
    }
    
    if (updates.length === 0) {
      return success(res, clienteAntes, 'Nenhuma alteração realizada');
    }
    
    updates.push('atualizado_em = datetime(\'now\')');
    params.push(id);
    
    coreDb.prepare(`UPDATE cliente SET ${updates.join(', ')} WHERE id = ?`).run(...params);
    
    const clienteDepois = coreDb.prepare('SELECT * FROM cliente WHERE id = ?').get(id);
    delete clienteDepois.senha_hash;
    delete clienteDepois.cpf_hash;
    
    // Auditoria
    auditService.logUpdate('cliente', id, clienteAntes, clienteDepois, extractAuditInfo(req));
    
    logger.info('Cliente atualizado', { clienteId: id });
    
    return success(res, clienteDepois, 'Cliente atualizado com sucesso');
  } catch (error) {
    logger.error('Erro ao atualizar cliente:', error);
    throw error;
  }
}

/**
 * DELETE /api/clientes/:id
 * Remove cliente (soft delete)
 */
function remover(req, res) {
  try {
    const { id } = req.params;
    const coreDb = db.getCore();
    
    const cliente = coreDb.prepare('SELECT * FROM cliente WHERE id = ?').get(id);
    if (!cliente) {
      return notFound(res, 'Cliente não encontrado');
    }
    
    // Soft delete
    coreDb.prepare('UPDATE cliente SET ativo = 0, atualizado_em = datetime(\'now\') WHERE id = ?').run(id);
    
    // Auditoria
    auditService.logDelete('cliente', id, cliente, extractAuditInfo(req));
    
    logger.info('Cliente removido', { clienteId: id });
    
    return success(res, null, 'Cliente removido com sucesso');
  } catch (error) {
    logger.error('Erro ao remover cliente:', error);
    throw error;
  }
}

module.exports = {
  login,
  recuperarSenha,
  redefinirSenha,
  criar,
  listar,
  buscar,
  atualizar,
  remover
};
