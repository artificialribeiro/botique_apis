/**
 * BOUTIQUE DINIZ API - Controller Administrativo
 * Desenvolvido por Estúdio Atlas
 *
 * CORREÇÃO v4:
 *   - Cadastro de URLs protegido por chave de segurança "1526105"
 *   - Login admin mantém senha '1526' para acesso ao painel
 *   - Para ADICIONAR ou REMOVER URLs, o usuário precisa informar a chave "1526105"
 *   - A chave pode vir no body (campo "chave") ou no header "X-Admin-Key"
 *   - Todas as queries usam better-sqlite3 síncrono (sem await)
 */

const db = require('../config/database');
const config = require('../config');
const { success, unauthorized, internalError, notFound, validationError, created, forbidden } = require('../utils/response');
const logger = require('../utils/logger');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

// ============================================
// CHAVE DE SEGURANÇA PARA GERENCIAMENTO DE URLs
// ============================================
const ADMIN_SECURITY_KEY = process.env.ADMIN_SECURITY_KEY || '1526105';

/**
 * Valida a chave de segurança para operações com URLs
 * A chave pode vir de:
 *   1. Header "X-Admin-Key"
 *   2. Body campo "chave"
 *   3. Query param "chave"
 */
function validarChaveSeguranca(req) {
  const chaveHeader = req.headers['x-admin-key'];
  const chaveBody = req.body && req.body.chave;
  const chaveQuery = req.query && req.query.chave;

  const chaveRecebida = chaveHeader || chaveBody || chaveQuery;

  if (!chaveRecebida) {
    return { valido: false, motivo: 'Chave de segurança não fornecida. Informe a chave para autorizar esta operação.' };
  }

  if (String(chaveRecebida).trim() !== ADMIN_SECURITY_KEY) {
    return { valido: false, motivo: 'Chave de segurança incorreta.' };
  }

  return { valido: true };
}

/**
 * GET /admin/config
 * Retorna a página administrativa
 */
function getAdminPage(req, res) {
  res.sendFile(require('path').join(__dirname, '../public/admin.html'));
}

/**
 * POST /api/admin/login
 * Autenticação administrativa simples com senha fixa
 */
function login(req, res) {
  try {
    const { password } = req.body;

    if (!password) {
      return validationError(res, [{ field: 'password', issue: 'Senha é obrigatória' }]);
    }

    if (password === '1526') {
      logger.info('Login admin bem-sucedido', { ip: req.ip });
      return success(res, { authenticated: true }, 'Autenticado com sucesso');
    }

    logger.warn('Tentativa de login admin com senha incorreta', { ip: req.ip });
    return unauthorized(res, 'Senha incorreta');
  } catch (error) {
    logger.error('Erro no login admin:', error);
    return internalError(res, 'Erro interno no login');
  }
}

/**
 * GET /api/admin/urls
 * Lista as URLs autorizadas (não precisa de chave, apenas estar logado)
 */
function listarUrls(req, res) {
  try {
    const authDb = db.getAuth();
    const urls = authDb.prepare('SELECT * FROM urls_autorizadas ORDER BY criado_em DESC').all();
    return success(res, urls);
  } catch (error) {
    logger.error('Erro ao listar URLs autorizadas:', error);
    return internalError(res, 'Erro ao listar URLs');
  }
}

/**
 * POST /api/admin/urls
 * Adiciona uma nova URL autorizada
 * REQUER: chave de segurança "1526105" (via header X-Admin-Key, body.chave ou query.chave)
 */
function adicionarUrl(req, res) {
  // Validar chave de segurança
  const validacao = validarChaveSeguranca(req);
  if (!validacao.valido) {
    logger.warn('Tentativa de adicionar URL sem chave válida', { ip: req.ip, motivo: validacao.motivo });
    return forbidden(res, validacao.motivo);
  }

  const { url, descricao } = req.body;

  if (!url) {
    return validationError(res, [{ field: 'url', issue: 'URL é obrigatória' }]);
  }

  try {
    const authDb = db.getAuth();
    authDb.prepare(`
      INSERT INTO urls_autorizadas (url, descricao)
      VALUES (?, ?)
    `).run(url, descricao || '');

    logger.info('Nova URL autorizada adicionada: ' + url, { ip: req.ip });
    return success(res, null, 'URL adicionada com sucesso');
  } catch (error) {
    if (error.message && error.message.includes('UNIQUE')) {
      return internalError(res, 'Esta URL já está autorizada');
    }
    logger.error('Erro ao adicionar URL autorizada:', error);
    return internalError(res, 'Erro ao adicionar URL');
  }
}

/**
 * DELETE /api/admin/urls/:id
 * Remove uma URL autorizada
 * REQUER: chave de segurança "1526105" (via header X-Admin-Key, body.chave ou query.chave)
 */
function removerUrl(req, res) {
  // Validar chave de segurança
  const validacao = validarChaveSeguranca(req);
  if (!validacao.valido) {
    logger.warn('Tentativa de remover URL sem chave válida', { ip: req.ip, motivo: validacao.motivo });
    return forbidden(res, validacao.motivo);
  }

  const { id } = req.params;

  try {
    const authDb = db.getAuth();
    const result = authDb.prepare('DELETE FROM urls_autorizadas WHERE id = ?').run(id);

    if (result.changes === 0) {
      return notFound(res, 'URL não encontrada');
    }

    logger.info('URL autorizada removida, id: ' + id, { ip: req.ip });
    return success(res, null, 'URL removida com sucesso');
  } catch (error) {
    logger.error('Erro ao remover URL autorizada:', error);
    return internalError(res, 'Erro ao remover URL');
  }
}

// ============================================
// RECUPERAÇÃO DE SENHA DE FUNCIONÁRIOS
// ============================================

/**
 * POST /api/admin/funcionarios/recuperar-senha
 * Solicita recuperação de senha de um funcionário.
 * Gera código, salva hash no banco, e dispara webhook com código + email/telefone.
 */
function solicitarRecuperacaoSenha(req, res) {
  try {
    const { login: loginFuncionario } = req.body;

    if (!loginFuncionario) {
      return validationError(res, [{ field: 'login', issue: 'Login do funcionário é obrigatório' }]);
    }

    const authDb = db.getAuth();
    const funcionario = authDb.prepare('SELECT * FROM usuario_sistema WHERE login = ? AND ativo = 1').get(loginFuncionario);

    if (!funcionario) {
      // Não revelar se o login existe ou não (segurança)
      return success(res, null, 'Se o login existir, um código de recuperação será enviado');
    }

    if (!funcionario.email && !funcionario.telefone) {
      logger.warn('Funcionário sem email/telefone para recuperação', { login: loginFuncionario });
      return success(res, null, 'Se o login existir, um código de recuperação será enviado');
    }

    // Gerar código de 6 dígitos
    const codigo = Math.floor(100000 + Math.random() * 900000).toString();
    const codigoHash = crypto.createHash('sha256').update(codigo).digest('hex').toUpperCase();

    // Expiração em 30 minutos
    const expiraEm = new Date(Date.now() + 30 * 60 * 1000).toISOString();

    // Invalidar códigos anteriores não usados
    authDb.prepare(`
      UPDATE recuperacao_senha_usuario SET usado_em = datetime('now')
      WHERE usuario_id = ? AND usado_em IS NULL
    `).run(funcionario.id);

    // Salvar novo código
    authDb.prepare(`
      INSERT INTO recuperacao_senha_usuario (usuario_id, codigo_hash, expira_em)
      VALUES (?, ?, ?)
    `).run(funcionario.id, codigoHash, expiraEm);

    // Disparar webhook com código e dados de contato
    try {
      const webhookService = require('../services/webhookService');
      webhookService.eventoRecuperacaoSenhaFuncionario(funcionario, codigo);
    } catch (whErr) {
      logger.warn('Falha ao disparar webhook de recuperação:', whErr.message);
    }

    logger.info('Recuperação de senha solicitada para funcionário', { login: loginFuncionario });

    return success(res, null, 'Se o login existir, um código de recuperação será enviado');
  } catch (error) {
    logger.error('Erro na recuperação de senha:', error);
    return internalError(res, 'Erro ao processar recuperação de senha');
  }
}

/**
 * POST /api/admin/funcionarios/redefinir-senha
 * Redefine a senha usando o código de recuperação
 */
function redefinirSenha(req, res) {
  try {
    const { login: loginFuncionario, codigo, nova_senha } = req.body;

    if (!loginFuncionario || !codigo || !nova_senha) {
      return validationError(res, [
        { field: 'login', issue: 'Login é obrigatório' },
        { field: 'codigo', issue: 'Código de recuperação é obrigatório' },
        { field: 'nova_senha', issue: 'Nova senha é obrigatória' }
      ]);
    }

    if (nova_senha.length < 4) {
      return validationError(res, [{ field: 'nova_senha', issue: 'Senha deve ter pelo menos 4 caracteres' }]);
    }

    const authDb = db.getAuth();
    const funcionario = authDb.prepare('SELECT id FROM usuario_sistema WHERE login = ? AND ativo = 1').get(loginFuncionario);

    if (!funcionario) {
      return unauthorized(res, 'Código inválido ou expirado');
    }

    const codigoHash = crypto.createHash('sha256').update(codigo).digest('hex').toUpperCase();

    const recuperacao = authDb.prepare(`
      SELECT * FROM recuperacao_senha_usuario
      WHERE usuario_id = ? AND codigo_hash = ? AND usado_em IS NULL AND expira_em > datetime('now')
    `).get(funcionario.id, codigoHash);

    if (!recuperacao) {
      return unauthorized(res, 'Código inválido ou expirado');
    }

    // Marcar código como usado
    authDb.prepare("UPDATE recuperacao_senha_usuario SET usado_em = datetime('now') WHERE id = ?").run(recuperacao.id);

    // Atualizar senha
    const senhaHash = bcrypt.hashSync(nova_senha, 10);
    authDb.prepare("UPDATE usuario_sistema SET senha_hash = ?, atualizado_em = datetime('now') WHERE id = ?").run(senhaHash, funcionario.id);

    logger.info('Senha de funcionário redefinida com sucesso', { login: loginFuncionario });

    return success(res, null, 'Senha redefinida com sucesso');
  } catch (error) {
    logger.error('Erro ao redefinir senha:', error);
    return internalError(res, 'Erro ao redefinir senha');
  }
}

module.exports = {
  getAdminPage,
  login,
  listarUrls,
  adicionarUrl,
  removerUrl,
  solicitarRecuperacaoSenha,
  redefinirSenha
};
