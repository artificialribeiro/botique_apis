#!/usr/bin/env node
/**
 * BOUTIQUE DINIZ API — Migração: Módulo Financeiro + Sessões de Caixa
 * Desenvolvido por Estúdio Atlas
 *
 * Execução: node scripts/migrar-financeiro.js
 *
 * O que este script faz:
 *   1. Adiciona a coluna sessao_id em caixa_lancamento (retro-compatível)
 *   2. Cria a tabela caixa_sessao (abertura/fechamento formal de caixa)
 *   3. Cria a tabela financeiro_conta_pagar
 *   4. Cria a tabela financeiro_conta_receber
 *   5. Cria a tabela financeiro_fechamento
 *
 * Seguro para re-execução: usa IF NOT EXISTS / IF NOT EXISTS em todas as operações.
 */

require('dotenv').config();
const path = require('path');
const fs   = require('fs');

const dbPath = path.resolve(process.cwd(), './data/core.db');

if (!fs.existsSync(dbPath)) {
  console.error('❌ core.db não encontrado em ./data/core.db');
  console.error('   Execute primeiro: node scripts/init-database.js');
  process.exit(1);
}

let Database;
try {
  Database = require('better-sqlite3');
} catch (e) {
  console.error('❌ better-sqlite3 não instalado. Execute: npm install');
  process.exit(1);
}

const db = new Database(dbPath);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

console.log('');
console.log('╔════════════════════════════════════════════════════════════╗');
console.log('║     BOUTIQUE DINIZ — Migração: Módulo Financeiro          ║');
console.log('║           Desenvolvido por Estúdio Atlas                   ║');
console.log('╚════════════════════════════════════════════════════════════╝');
console.log('');

try {
  db.transaction(() => {

    // ─────────────────────────────────────────────────────────────
    // 1. CAIXA_SESSAO — controle formal de abertura/fechamento
    // ─────────────────────────────────────────────────────────────
    console.log('📦 Criando tabela caixa_sessao...');
    db.exec(`
      CREATE TABLE IF NOT EXISTS caixa_sessao (
        id                        INTEGER PRIMARY KEY AUTOINCREMENT,
        filial_id                 INTEGER NOT NULL,
        usuario_abertura_id       INTEGER,
        usuario_fechamento_id     INTEGER,
        usuario_aprovacao_id      INTEGER,
        valor_abertura            REAL    NOT NULL DEFAULT 0,
        valor_fechamento_declarado REAL,
        total_entradas            REAL,
        total_saidas              REAL,
        saldo_calculado           REAL,
        diferenca                 REAL,
        status                    TEXT    NOT NULL DEFAULT 'aberto'
          CHECK(status IN ('aberto','pendente_aprovacao','aprovado','rejeitado')),
        observacoes_abertura      TEXT,
        observacoes_fechamento    TEXT,
        observacoes_aprovacao     TEXT,
        aberto_em                 TEXT    NOT NULL DEFAULT (datetime('now')),
        fechado_em                TEXT,
        aprovado_em               TEXT,
        FOREIGN KEY (filial_id) REFERENCES filial(id)
      );
    `);

    // ─────────────────────────────────────────────────────────────
    // 2. Adicionar sessao_id em caixa_lancamento (se não existir)
    // ─────────────────────────────────────────────────────────────
    console.log('🔗 Vinculando caixa_lancamento a caixa_sessao...');

    // Verificar se a coluna sessao_id já existe
    const cols = db.prepare("PRAGMA table_info(caixa_lancamento)").all();
    const temSessaoId = cols.some(c => c.name === 'sessao_id');

    if (!temSessaoId) {
      // Verificar se a tabela caixa_lancamento já existe
      const temTabela = db.prepare(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='caixa_lancamento'"
      ).get();

      if (temTabela) {
        db.exec('ALTER TABLE caixa_lancamento ADD COLUMN sessao_id INTEGER REFERENCES caixa_sessao(id)');
        console.log('   ✅ Coluna sessao_id adicionada à caixa_lancamento');
      } else {
        // Criar tabela do zero com a coluna incluída
        db.exec(`
          CREATE TABLE IF NOT EXISTS caixa_lancamento (
            id                   INTEGER PRIMARY KEY AUTOINCREMENT,
            sessao_id            INTEGER REFERENCES caixa_sessao(id),
            filial_id            INTEGER NOT NULL,
            pedido_id            INTEGER,
            produto_variante_id  INTEGER,
            tipo                 TEXT    NOT NULL CHECK(tipo IN ('entrada','saida')),
            descricao            TEXT    NOT NULL,
            valor                REAL    NOT NULL,
            forma_pagamento      TEXT,
            parcelas             INTEGER,
            cliente_id           INTEGER,
            usuario_vendedor_id  INTEGER,
            origem               TEXT    NOT NULL DEFAULT 'loja'
              CHECK(origem IN ('loja','site')),
            criado_em            TEXT    NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (filial_id) REFERENCES filial(id),
            FOREIGN KEY (sessao_id) REFERENCES caixa_sessao(id)
          );
        `);
        console.log('   ✅ Tabela caixa_lancamento criada');
      }
    } else {
      console.log('   ℹ️  sessao_id já existe em caixa_lancamento — nenhuma alteração necessária');
    }

    // ─────────────────────────────────────────────────────────────
    // 3. FINANCEIRO_CONTA_PAGAR
    // ─────────────────────────────────────────────────────────────
    console.log('📦 Criando tabela financeiro_conta_pagar...');
    db.exec(`
      CREATE TABLE IF NOT EXISTS financeiro_conta_pagar (
        id                    INTEGER PRIMARY KEY AUTOINCREMENT,
        filial_id             INTEGER,
        fornecedor_id         INTEGER,
        descricao             TEXT    NOT NULL,
        valor                 REAL    NOT NULL,
        valor_pago            REAL,
        data_vencimento       TEXT    NOT NULL,
        data_pagamento        TEXT,
        forma_pagamento       TEXT,
        numero_documento      TEXT,
        status                TEXT    NOT NULL DEFAULT 'pendente'
          CHECK(status IN ('pendente','pago','cancelado')),
        observacoes           TEXT,
        criado_por_usuario_id INTEGER,
        pago_por_usuario_id   INTEGER,
        criado_em             TEXT    NOT NULL DEFAULT (datetime('now')),
        FOREIGN KEY (filial_id)    REFERENCES filial(id),
        FOREIGN KEY (fornecedor_id) REFERENCES fornecedor(id)
      );
    `);

    // ─────────────────────────────────────────────────────────────
    // 4. FINANCEIRO_CONTA_RECEBER
    // ─────────────────────────────────────────────────────────────
    console.log('📦 Criando tabela financeiro_conta_receber...');
    db.exec(`
      CREATE TABLE IF NOT EXISTS financeiro_conta_receber (
        id                        INTEGER PRIMARY KEY AUTOINCREMENT,
        filial_id                 INTEGER,
        cliente_id                INTEGER,
        descricao                 TEXT    NOT NULL,
        valor                     REAL    NOT NULL,
        valor_recebido            REAL,
        data_vencimento           TEXT    NOT NULL,
        data_recebimento          TEXT,
        forma_pagamento           TEXT,
        numero_documento          TEXT,
        status                    TEXT    NOT NULL DEFAULT 'pendente'
          CHECK(status IN ('pendente','recebido','cancelado')),
        observacoes               TEXT,
        criado_por_usuario_id     INTEGER,
        recebido_por_usuario_id   INTEGER,
        criado_em                 TEXT    NOT NULL DEFAULT (datetime('now')),
        FOREIGN KEY (filial_id)  REFERENCES filial(id),
        FOREIGN KEY (cliente_id) REFERENCES cliente(id)
      );
    `);

    // ─────────────────────────────────────────────────────────────
    // 5. FINANCEIRO_FECHAMENTO
    // ─────────────────────────────────────────────────────────────
    console.log('📦 Criando tabela financeiro_fechamento...');
    db.exec(`
      CREATE TABLE IF NOT EXISTS financeiro_fechamento (
        id                    INTEGER PRIMARY KEY AUTOINCREMENT,
        data_inicio           TEXT    NOT NULL,
        data_fim              TEXT    NOT NULL,
        filiais_json          TEXT,
        total_receitas        REAL    NOT NULL DEFAULT 0,
        total_despesas        REAL    NOT NULL DEFAULT 0,
        resultado             REAL    NOT NULL DEFAULT 0,
        resumo_json           TEXT,
        observacoes           TEXT,
        status                TEXT    NOT NULL DEFAULT 'gerado'
          CHECK(status IN ('gerado','cancelado')),
        criado_por_usuario_id INTEGER,
        criado_em             TEXT    NOT NULL DEFAULT (datetime('now'))
      );
    `);

    // ─────────────────────────────────────────────────────────────
    // 6. ÍNDICES para performance
    // ─────────────────────────────────────────────────────────────
    console.log('🔍 Criando índices...');
    db.exec(`
      CREATE INDEX IF NOT EXISTS idx_caixa_sessao_filial_status
        ON caixa_sessao(filial_id, status);
      CREATE INDEX IF NOT EXISTS idx_caixa_sessao_status
        ON caixa_sessao(status);
      CREATE INDEX IF NOT EXISTS idx_caixa_lancamento_sessao
        ON caixa_lancamento(sessao_id);
      CREATE INDEX IF NOT EXISTS idx_conta_pagar_status_vencimento
        ON financeiro_conta_pagar(status, data_vencimento);
      CREATE INDEX IF NOT EXISTS idx_conta_receber_status_vencimento
        ON financeiro_conta_receber(status, data_vencimento);
    `);

  })();

  console.log('');
  console.log('✅ MIGRAÇÃO CONCLUÍDA COM SUCESSO!');
  console.log('');
  console.log('Tabelas criadas/atualizadas:');
  console.log('  ✔ caixa_sessao              — controle de abertura/fechamento');
  console.log('  ✔ caixa_lancamento          — coluna sessao_id adicionada');
  console.log('  ✔ financeiro_conta_pagar    — contas a pagar');
  console.log('  ✔ financeiro_conta_receber  — contas a receber');
  console.log('  ✔ financeiro_fechamento     — fechamento consolidado');
  console.log('');
  console.log('Novos endpoints disponíveis após reiniciar o servidor:');
  console.log('  POST   /api/caixa/abrir');
  console.log('  POST   /api/caixa/:id/fechar');
  console.log('  GET    /api/caixa/sessoes');
  console.log('  GET    /api/financeiro/dashboard');
  console.log('  GET    /api/financeiro/caixas-pendentes');
  console.log('  POST   /api/financeiro/caixas/:id/aprovar');
  console.log('  POST   /api/financeiro/caixas/:id/rejeitar');
  console.log('  POST   /api/financeiro/contas-pagar');
  console.log('  PATCH  /api/financeiro/contas-pagar/:id/baixar');
  console.log('  POST   /api/financeiro/contas-receber');
  console.log('  PATCH  /api/financeiro/contas-receber/:id/baixar');
  console.log('  POST   /api/financeiro/fechamento');
  console.log('');

  db.close();
} catch (err) {
  console.error('');
  console.error('❌ ERRO NA MIGRAÇÃO:', err.message);
  console.error(err.stack);
  db.close();
  process.exit(1);
}
