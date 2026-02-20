/**
 * BOUTIQUE DINIZ API - Controller de Grupos de Acesso
 *
 * Este controlador gerencia os grupos de acesso do sistema. Permite
 * listar grupos com suas permissões associadas, criar novos grupos,
 * atualizar grupos existentes (incluindo a lista de permissões) e
 * remover grupos. As rotas que utilizam estas funções devem estar
 * protegidas pelo middleware `authenticate` e, opcionalmente,
 * `requirePermission` com a permissão apropriada (ex.: 'admin_grupos').
 */

const db = require('../config/database');
const { success, created, notFound, conflict } = require('../utils/response');
const logger = require('../utils/logger');

/**
 * GET /api/grupos/:id
 *
 * Retorna um grupo de acesso específico com suas permissões.
 */
function buscar(req, res) {
  try {
    const { id } = req.params;
    const authDb = db.getAuth();
    const grupo = authDb.prepare(
      `SELECT id, nome, descricao FROM grupo_acesso WHERE id = ?`
    ).get(id);
    if (!grupo) {
      return notFound(res, 'Grupo de acesso não encontrado');
    }
    const permissoes = authDb.prepare(
      `SELECT p.id, p.codigo, p.nome, p.modulo
       FROM permissao p
       JOIN grupo_permissao gp ON gp.permissao_id = p.id
       WHERE gp.grupo_id = ?`
    ).all(id);
    grupo.permissoes = permissoes;
    return success(res, grupo, 'Grupo obtido com sucesso');
  } catch (error) {
    logger.error('Erro ao buscar grupo de acesso:', error);
    throw error;
  }
}

/**
 * POST /api/grupos
 *
 * Cria um novo grupo de acesso. Aceita um corpo contendo:
 * - nome: nome único do grupo
 * - descricao: descrição opcional
 * - permissoes: array de IDs de permissões a serem associadas
 */
function criar(req, res) {
  try {
    const { nome, descricao, permissoes } = req.body;
    if (!nome) {
      return conflict(res, 'Nome do grupo não fornecido');
    }
    const authDb = db.getAuth();
    // Verificar se já existe grupo com o mesmo nome
    const existente = authDb.prepare(
      `SELECT id FROM grupo_acesso WHERE nome = ?`
    ).get(nome);
    if (existente) {
      return conflict(res, 'Nome de grupo já utilizado');
    }
    // Inserir grupo
    const info = authDb.prepare(
      `INSERT INTO grupo_acesso (nome, descricao) VALUES (?, ?)`
    ).run(nome, descricao || null);
    const grupoId = info.lastInsertRowid;
    // Inserir permissões, se fornecidas
    if (Array.isArray(permissoes) && permissoes.length > 0) {
      const insertGp = authDb.prepare(
        `INSERT INTO grupo_permissao (grupo_id, permissao_id) VALUES (?, ?)`
      );
      const tx = authDb.transaction((list) => {
        for (const permId of list) {
          insertGp.run(grupoId, permId);
        }
      });
      tx(permissoes);
    }
    logger.info('Grupo de acesso criado', { grupoId, nome });
    return created(res, { id: grupoId }, 'Grupo criado com sucesso');
  } catch (error) {
    logger.error('Erro ao criar grupo de acesso:', error);
    throw error;
  }
}

/**
 * PUT /api/grupos/:id
 *
 * Atualiza um grupo de acesso. Permite alterar nome, descrição e
 * redefinir totalmente a lista de permissões associadas. O corpo da
 * requisição pode conter os campos `nome`, `descricao` e `permissoes`
 * (array de IDs). Se o nome for alterado, verifica se não há outro
 * grupo com o mesmo nome.
 */
function atualizar(req, res) {
  try {
    const { id } = req.params;
    const { nome, descricao, permissoes } = req.body;
    const authDb = db.getAuth();
    const grupo = authDb.prepare(
      `SELECT id, nome FROM grupo_acesso WHERE id = ?`
    ).get(id);
    if (!grupo) {
      return notFound(res, 'Grupo de acesso não encontrado');
    }
    // Verificar nome duplicado
    if (nome && nome !== grupo.nome) {
      const existeOutro = authDb.prepare(
        `SELECT id FROM grupo_acesso WHERE nome = ? AND id != ?`
      ).get(nome, id);
      if (existeOutro) {
        return conflict(res, 'Nome de grupo já utilizado');
      }
    }
    // Atualizar informações básicas
    const updates = [];
    const params = [];
    if (nome !== undefined) { updates.push('nome = ?'); params.push(nome); }
    if (descricao !== undefined) { updates.push('descricao = ?'); params.push(descricao); }
    if (updates.length > 0) {
      const sql = `UPDATE grupo_acesso SET ${updates.join(', ')} WHERE id = ?`;
      params.push(id);
      authDb.prepare(sql).run(...params);
    }
    // Atualizar permissões, se fornecido array
    if (Array.isArray(permissoes)) {
      // Apagar permissões atuais
      authDb.prepare(
        `DELETE FROM grupo_permissao WHERE grupo_id = ?`
      ).run(id);
      // Inserir novas permissões
      if (permissoes.length > 0) {
        const insertGp = authDb.prepare(
          `INSERT INTO grupo_permissao (grupo_id, permissao_id) VALUES (?, ?)`
        );
        const tx = authDb.transaction((list) => {
          for (const permId of list) {
            insertGp.run(id, permId);
          }
        });
        tx(permissoes);
      }
    }
    logger.info('Grupo de acesso atualizado', { grupoId: id });
    return success(res, null, 'Grupo atualizado com sucesso');
  } catch (error) {
    logger.error('Erro ao atualizar grupo de acesso:', error);
    throw error;
  }
}

/**
 * DELETE /api/grupos/:id
 *
 * Remove um grupo de acesso. A exclusão só é permitida se não existir
 * nenhum usuário associado a este grupo. Caso contrário, retorna
 * conflito. As permissões associadas são removidas automaticamente
 * pelo ON DELETE CASCADE.
 */
function remover(req, res) {
  try {
    const { id } = req.params;
    const authDb = db.getAuth();
    const grupo = authDb.prepare(
      `SELECT id FROM grupo_acesso WHERE id = ?`
    ).get(id);
    if (!grupo) {
      return notFound(res, 'Grupo de acesso não encontrado');
    }
    // Verificar se existem usuários associados
    const possuiUsuarios = authDb.prepare(
      `SELECT 1 FROM usuario_sistema WHERE grupo_acesso_id = ? LIMIT 1`
    ).get(id);
    if (possuiUsuarios) {
      return conflict(res, 'Não é possível remover um grupo com usuários vinculados');
    }
    authDb.prepare(
      `DELETE FROM grupo_acesso WHERE id = ?`
    ).run(id);
    logger.info('Grupo de acesso removido', { grupoId: id });
    return success(res, null, 'Grupo removido com sucesso');
  } catch (error) {
    logger.error('Erro ao remover grupo de acesso:', error);
    throw error;
  }
}

module.exports = {
  buscar,
  criar,
  atualizar,
  remover
};