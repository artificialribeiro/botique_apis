/**
 * BOUTIQUE DINIZ API - Controller de Usuários do Sistema
 *
 * Este controlador gerencia os usuários internos do sistema (funcionários). As
 * rotas definidas em `routes/index.js` utilizam a autenticação padrão (API Key
 * + Token de integração) através do middleware `authenticate`. Nenhuma rota
 * aqui gera tokens de sessão separados – o modelo segue a padronização das
 * demais APIs, utilizando apenas a chave da API e o token de integração para
 * autenticar as chamadas.
 */

const db = require('../config/database');
const { success, created, notFound, conflict, unauthorized } = require('../utils/response');
const { hashPasswordSync, verifyPasswordSync, sha256, generateRecoveryCode } = require('../utils/crypto');
const { getPaginationParams } = require('../utils/pagination');
const logger = require('../utils/logger');
const notificacaoService = require('../services/notificacaoService');

/**
 * POST /api/usuarios/login
 *
 * Autentica um usuário do sistema. Esta rota não gera token de sessão: ela
 * apenas valida o login e a senha e retorna as informações básicas do usuário.
 * A rota está protegida pelo middleware `authenticate`, portanto exige a
 * presença da chave de API e de um token de integração válido.
 */
function login(req, res) {
  try {
    const { login, senha } = req.body;
    if (!login || !senha) {
      return unauthorized(res, 'Login ou senha não fornecidos');
    }

    const authDb = db.getAuth();
    const usuario = authDb.prepare(
      `SELECT id, nome_completo, login, senha_hash, filial_id, grupo_acesso_id, ativo
       FROM usuario_sistema WHERE login = ?`
    ).get(login);

    if (!usuario || !usuario.ativo) {
      logger.warn('Tentativa de login de usuário do sistema inválida', { login });
      return unauthorized(res, 'Login ou senha inválidos');
    }

    if (!verifyPasswordSync(senha, usuario.senha_hash)) {
      logger.warn('Senha incorreta para usuário do sistema', { usuarioId: usuario.id });
      return unauthorized(res, 'Login ou senha inválidos');
    }

    // Atualizar último login
    authDb.prepare(
      `UPDATE usuario_sistema SET ultimo_login = datetime('now'), atualizado_em = datetime('now')
       WHERE id = ?`
    ).run(usuario.id);

    // Não retornar hash de senha
    delete usuario.senha_hash;

    logger.info('Login de usuário do sistema realizado', { usuarioId: usuario.id });
    return success(res, usuario, 'Login realizado com sucesso');
  } catch (error) {
    logger.error('Erro no login de usuário do sistema:', error);
    throw error;
  }
}

/**
 * GET /api/usuarios
 *
 * Lista usuários do sistema. Aceita parâmetros de paginação padrão
 * (page, pageSize) através do middleware `paginationValidator`.
 */
function listar(req, res) {
  try {
    const authDb = db.getAuth();
    const { page, pageSize, offset } = getPaginationParams(req.query);
    const usuarios = authDb.prepare(
      `SELECT id, nome_completo, login, filial_id, grupo_acesso_id, ativo, ultimo_login
       FROM usuario_sistema
       LIMIT ? OFFSET ?`
    ).all(pageSize, offset);

    const total = authDb.prepare(
      `SELECT COUNT(1) AS total FROM usuario_sistema`
    ).get().total;

    return success(res, { itens: usuarios, total, page, pageSize }, 'Usuários listados com sucesso');
  } catch (error) {
    logger.error('Erro ao listar usuários do sistema:', error);
    throw error;
  }
}

/**
 * POST /api/usuarios
 *
 * Cria um novo usuário do sistema. Requer campos básicos: nome_completo,
 * login, senha e grupo_acesso_id. Opcionalmente aceita filial_id. O login
 * deve ser único. A senha é armazenada com hash bcrypt.
 */
function criar(req, res) {
  try {
    const { nome_completo, login, senha, filial_id, grupo_acesso_id } = req.body;
    if (!nome_completo || !login || !senha || !grupo_acesso_id) {
      return unauthorized(res, 'Dados obrigatórios não fornecidos');
    }
    const authDb = db.getAuth();
    // Verificar se login já existe
    const existente = authDb.prepare(
      `SELECT id FROM usuario_sistema WHERE login = ?`
    ).get(login);
    if (existente) {
      return conflict(res, 'Login já utilizado por outro usuário');
    }

    const senhaHash = hashPasswordSync(senha);
    const stmt = authDb.prepare(
      `INSERT INTO usuario_sistema (nome_completo, login, senha_hash, filial_id, grupo_acesso_id)
       VALUES (?, ?, ?, ?, ?)`
    );
    const info = stmt.run(nome_completo, login, senhaHash, filial_id || null, grupo_acesso_id);

    logger.info('Usuário do sistema criado', { usuarioId: info.lastInsertRowid });
    return created(res, { id: info.lastInsertRowid }, 'Usuário criado com sucesso');
  } catch (error) {
    logger.error('Erro ao criar usuário do sistema:', error);
    throw error;
  }
}

/**
 * PUT /api/usuarios/:id
 *
 * Atualiza um usuário do sistema. Permite modificar nome, login, senha,
 * filial_id, grupo_acesso_id e status ativo. Caso a senha seja enviada,
 * ela será re-hashada.
 */
function atualizar(req, res) {
  try {
    const { id } = req.params;
    const { nome_completo, login, senha, filial_id, grupo_acesso_id, ativo } = req.body;
    const authDb = db.getAuth();
    const usuario = authDb.prepare(
      `SELECT id FROM usuario_sistema WHERE id = ?`
    ).get(id);
    if (!usuario) {
      return notFound(res, 'Usuário não encontrado');
    }

    const updates = [];
    const params = [];
    if (nome_completo !== undefined) { updates.push('nome_completo = ?'); params.push(nome_completo); }
    if (login !== undefined) { updates.push('login = ?'); params.push(login); }
    if (senha !== undefined) {
      const senhaHash = hashPasswordSync(senha);
      updates.push('senha_hash = ?');
      params.push(senhaHash);
    }
    if (filial_id !== undefined) { updates.push('filial_id = ?'); params.push(filial_id); }
    if (grupo_acesso_id !== undefined) { updates.push('grupo_acesso_id = ?'); params.push(grupo_acesso_id); }
    if (ativo !== undefined) { updates.push('ativo = ?'); params.push(ativo ? 1 : 0); }

    if (updates.length === 0) {
      return success(res, null, 'Nenhuma alteração informada');
    }

    updates.push('atualizado_em = datetime(\'now\')');
    const sql = `UPDATE usuario_sistema SET ${updates.join(', ')} WHERE id = ?`;
    params.push(id);
    authDb.prepare(sql).run(...params);

    logger.info('Usuário do sistema atualizado', { usuarioId: id });
    return success(res, null, 'Usuário atualizado com sucesso');
  } catch (error) {
    logger.error('Erro ao atualizar usuário do sistema:', error);
    throw error;
  }
}

/**
 * PUT /api/usuarios/:id/grupos
 *
 * Altera o grupo de acesso principal de um usuário. Aceita um campo
 * `grupo_acesso_id` no corpo da requisição. Caso desejado suportar múltiplos
 * grupos, será necessária uma tabela de relação (não implementada aqui).
 */
function atualizarGrupo(req, res) {
  try {
    const { id } = req.params;
    const { grupo_acesso_id } = req.body;
    if (!grupo_acesso_id) {
      return unauthorized(res, 'Grupo de acesso não fornecido');
    }
    const authDb = db.getAuth();
    const usuario = authDb.prepare(
      `SELECT id FROM usuario_sistema WHERE id = ?`
    ).get(id);
    if (!usuario) {
      return notFound(res, 'Usuário não encontrado');
    }
    authDb.prepare(
      `UPDATE usuario_sistema SET grupo_acesso_id = ?, atualizado_em = datetime('now')
       WHERE id = ?`
    ).run(grupo_acesso_id, id);
    logger.info('Grupo de acesso de usuário do sistema atualizado', { usuarioId: id, grupo_acesso_id });
    return success(res, null, 'Grupo de acesso atualizado com sucesso');
  } catch (error) {
    logger.error('Erro ao atualizar grupo de acesso do usuário:', error);
    throw error;
  }
}

/**
 * GET /api/grupos
 *
 * Lista os grupos de acesso existentes. Retorna id e nome de cada grupo.
 */
function listarGrupos(req, res) {
  try {
    const authDb = db.getAuth();
    const grupos = authDb.prepare(
      `SELECT id, nome, descricao FROM grupo_acesso`
    ).all();
    return success(res, grupos, 'Grupos listados com sucesso');
  } catch (error) {
    logger.error('Erro ao listar grupos de acesso:', error);
    throw error;
  }
}

/**
 * POST /api/usuarios/recuperar-senha
 *
 * Gera um código de recuperação de senha para o usuário do sistema.
 * O corpo da requisição deve conter `login` ou `email` para
 * identificação do usuário. Se o usuário existir e possuir email
 * cadastrado, um código será gerado e enviado por e-mail. Por
 * segurança, a mensagem de retorno não revela se o login/email existe.
 */
function recuperarSenha(req, res) {
  try {
    const { login, email } = req.body;
    if (!login && !email) {
      return success(res, null, 'Se os dados estiverem corretos, um código será enviado para o e-mail');
    }
    const authDb = db.getAuth();
    // Procurar usuário pelo login ou email
    const usuario = authDb.prepare(
      `SELECT id, nome_completo, email FROM usuario_sistema
       WHERE (login = ? OR email = ?) AND ativo = 1`
    ).get(login || null, email || null);
    if (!usuario || !usuario.email) {
      return success(res, null, 'Se os dados estiverem corretos, um código será enviado para o e-mail');
    }
    // Gerar código de recuperação
    const codigo = generateRecoveryCode();
    const codigoHash = sha256(String(codigo).toUpperCase());
    const expiraEm = new Date(Date.now() + 30 * 60 * 1000).toISOString();
    // Salvar código na tabela de usuários
    authDb.prepare(
      `INSERT INTO recuperacao_senha_usuario (usuario_id, codigo_hash, expira_em)
       VALUES (?, ?, ?)`
    ).run(usuario.id, codigoHash, expiraEm);
    // Enviar e-mail de recuperação
    // Construir objeto compatível com notificacaoService. Espera-se que as
    // funções de notificação utilizem campos similares aos de cliente. Como
    // usuários do sistema não possuem CPF registrado, utilizamos o login
    // como identificador genérico.
    const destinatario = {
      id: usuario.id,
      nome_completo: usuario.nome_completo,
      email: usuario.email,
      cpf: usuario.login
    };
    notificacaoService.notificarRecuperacaoSenha(destinatario, codigo).catch(err => {
      logger.error('Erro ao enviar notificação de recuperação de senha de usuário', err);
    });
    logger.info('Código de recuperação gerado para usuário do sistema', { usuarioId: usuario.id });
    return success(res, null, 'Se os dados estiverem corretos, um código será enviado para o e-mail');
  } catch (error) {
    logger.error('Erro na recuperação de senha de usuário do sistema:', error);
    throw error;
  }
}

/**
 * POST /api/usuarios/redefinir-senha
 *
 * Redefine a senha de um usuário do sistema usando o código de
 * recuperação. O corpo da requisição deve conter `login` (ou `email`),
 * `codigo` e `nova_senha`. Se o código for válido e não expirado, a
 * senha será atualizada e o código marcado como usado.
 */
function redefinirSenha(req, res) {
  try {
    const { login, email, codigo, nova_senha } = req.body;
    if ((!login && !email) || !codigo || !nova_senha) {
      return unauthorized(res, 'Dados inválidos');
    }
    const authDb = db.getAuth();
    // Buscar usuário
    const usuario = authDb.prepare(
      `SELECT id, nome_completo, email FROM usuario_sistema
       WHERE (login = ? OR email = ?) AND ativo = 1`
    ).get(login || null, email || null);
    if (!usuario) {
      return unauthorized(res, 'Dados inválidos');
    }
    // Verificar código
    const codigoHash = sha256(String(codigo).toUpperCase());
    const recuperacao = authDb.prepare(
      `SELECT id FROM recuperacao_senha_usuario
       WHERE usuario_id = ? AND codigo_hash = ?
       AND datetime(expira_em) > datetime('now') AND usado_em IS NULL`
    ).get(usuario.id, codigoHash);
    if (!recuperacao) {
      return unauthorized(res, 'Código inválido ou expirado');
    }
    // Atualizar senha
    const senhaHash = hashPasswordSync(nova_senha);
    authDb.prepare(
      `UPDATE usuario_sistema SET senha_hash = ?, atualizado_em = datetime('now') WHERE id = ?`
    ).run(senhaHash, usuario.id);
    // Marcar código como usado
    authDb.prepare(
      `UPDATE recuperacao_senha_usuario SET usado_em = datetime('now') WHERE id = ?`
    ).run(recuperacao.id);
    // Notificar usuário que a senha foi redefinida
    const destinatario = {
      id: usuario.id,
      nome_completo: usuario.nome_completo,
      email: usuario.email,
      cpf: usuario.login
    };
    notificacaoService.notificarSenhaRedefinida(destinatario).catch(err => {
      logger.error('Erro ao enviar notificação de senha redefinida de usuário', err);
    });
    logger.info('Senha de usuário do sistema redefinida com sucesso', { usuarioId: usuario.id });
    return success(res, null, 'Senha redefinida com sucesso');
  } catch (error) {
    logger.error('Erro ao redefinir senha de usuário do sistema:', error);
    throw error;
  }
}

module.exports = {
  login,
  listar,
  criar,
  atualizar,
  atualizarGrupo,
  listarGrupos,
  recuperarSenha,
  redefinirSenha
};