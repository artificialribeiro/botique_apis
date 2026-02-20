/**
 * BOUTIQUE DINIZ API - Camada de Compatibilidade SQLite
 * Desenvolvido por Estúdio Atlas
 *
 * CORREÇÃO v2 — Bug crítico resolvido (CPF sempre "já existe"):
 *
 * CAUSA: A implementação anterior usava sqlite3 (callbacks/Promises), mas todos os
 * controllers chamavam .get(), .run() e .all() de forma síncrona, sem await.
 * Resultado:
 *   - .get() retornava uma Promise pendente (truthy), nunca null
 *   - Verificações como `if (existente)` eram SEMPRE verdadeiras
 *   - O sistema rejeitava todo cadastro de cliente com "CPF já existe"
 *   - Nenhuma gravação era de fato executada no banco
 *
 * SOLUÇÃO: Migração para better-sqlite3, que é 100% síncrono.
 * A API pública é idêntica — nenhum controller precisa ser alterado.
 */

const Database = require('better-sqlite3');

module.exports = Database;
