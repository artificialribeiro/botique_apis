#!/usr/bin/env node
/**
 * BOUTIQUE DINIZ API - Inicialização COMPLETA do Banco de Dados
 * Desenvolvido por Estúdio Atlas
 * Compatible: Windows/Linux/Mac - better-sqlite3 (sem compilação)
 *
 * CORREÇÃO v3 — Schema alinhado 100% com os controllers:
 *   - estoque_movimento: adicionadas colunas referencia_tipo e referencia_id
 *   - caixa_sessao: adicionadas colunas usuario_abertura_id, usuario_fechamento_id,
 *     valor_fechamento_declarado, total_entradas, total_saidas, saldo_calculado,
 *     diferenca, usuario_aprovacao_id, aprovado_em, observacoes_aprovacao
 *   - caixa_lancamento: adicionadas colunas filial_id, produto_variante_id,
 *     parcelas, cliente_id, usuario_vendedor_id, origem, categoria nullable
 *   - banner: coluna imagem_caminho renomeada para caminho_imagem (controller)
 *   - cupom: adicionadas colunas percentual, valor_fixo, quantidade_total, quantidade_usada
 *   - notificacao: adicionada coluna link, tipo nullable
 *   - pedido: schema alinhado com pedidoController (filial_origem_id, pagamento_tipo, etc.)
 *   - pedido_item: schema alinhado (produto_variante_id, preco_unit, desconto_unit, total_item)
 *   - carrinho_item: tabela correta para carrinhoController
 *   - cancelamento_devolucao: tabela para pós-venda
 *   - reclamacao_midia: adicionadas colunas mime e size_bytes
 *   - tema: adicionadas colunas cor_destaque, favicon_path
 *   - financeiro_conta_pagar, financeiro_conta_receber, financeiro_fechamento: tabelas corretas
 *   - cupom_uso: tabela para registro de uso de cupons
 */

require('dotenv').config();
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');

// Caminhos dos bancos
const dataDir = path.resolve(process.cwd(), './data');
const corePath = path.resolve(dataDir, 'core.db');
const authPath = path.resolve(dataDir, 'auth.db');
const auditPath = path.resolve(dataDir, 'audit.db');

// Garantir que o diretório existe
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
  console.log('📁 Diretório data/ criado');
}

console.log('\n╔════════════════════════════════════════════════════════════╗');
console.log('║     BOUTIQUE DINIZ API - Inicialização do Banco de Dados   ║');
console.log('║          Compatible: Windows/Linux/Mac (better-sqlite3)    ║');
console.log('╚════════════════════════════════════════════════════════════╝\n');

try {
  // ============================================
  // 1. CORE.DB - Dados principais do sistema
  // ============================================
  console.log('📦 Criando CORE.DB (Dados principais)...');
  const coreDb = new Database(corePath);
  
  // Configurações de performance
  coreDb.pragma('journal_mode = WAL');
  coreDb.pragma('foreign_keys = ON');
  coreDb.pragma('synchronous = NORMAL');
  
  // TABELA: Filiais
  coreDb.exec(`
    CREATE TABLE IF NOT EXISTS filial (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      nome TEXT UNIQUE NOT NULL,
      tipo TEXT NOT NULL CHECK(tipo IN ('loja', 'site', 'estoque', 'adm')),
      ativo INTEGER NOT NULL DEFAULT 1,
      criado_em TEXT NOT NULL DEFAULT (datetime('now'))
    );
  `);
  
  // TABELA: Clientes
  coreDb.exec(`
    CREATE TABLE IF NOT EXISTS cliente (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      nome_completo TEXT NOT NULL,
      cpf TEXT UNIQUE NOT NULL,
      cpf_hash TEXT UNIQUE NOT NULL,
      email TEXT,
      celular TEXT,
      sexo TEXT CHECK(sexo IN ('M', 'F', 'O', 'N')),
      senha_hash TEXT,
      ativo INTEGER NOT NULL DEFAULT 1,
      criado_em TEXT NOT NULL DEFAULT (datetime('now')),
      atualizado_em TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_cliente_cpf_hash ON cliente(cpf_hash);
    CREATE INDEX IF NOT EXISTS idx_cliente_email ON cliente(email);
  `);
  
  // TABELA: Endereços dos clientes
  coreDb.exec(`
    CREATE TABLE IF NOT EXISTS cliente_endereco (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      cliente_id INTEGER NOT NULL,
      tipo TEXT NOT NULL CHECK(tipo IN ('casa', 'trabalho', 'outro')),
      rua TEXT NOT NULL,
      numero TEXT,
      complemento TEXT,
      bairro TEXT,
      cidade TEXT NOT NULL,
      estado TEXT NOT NULL,
      cep TEXT,
      referencia TEXT,
      principal INTEGER NOT NULL DEFAULT 0,
      criado_em TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (cliente_id) REFERENCES cliente(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_endereco_cliente ON cliente_endereco(cliente_id);
  `);
  
  // TABELA: Fornecedores
  coreDb.exec(`
    CREATE TABLE IF NOT EXISTS fornecedor (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      nome_fantasia TEXT NOT NULL,
      razao_social TEXT,
      cnpj TEXT UNIQUE,
      contato_nome TEXT,
      telefone TEXT,
      email TEXT,
      prazo_entrega_dias INTEGER,
      observacoes TEXT,
      ativo INTEGER NOT NULL DEFAULT 1,
      criado_em TEXT NOT NULL DEFAULT (datetime('now'))
    );
  `);

  // TABELA: Categorias de produtos
  coreDb.exec(`
    CREATE TABLE IF NOT EXISTS categoria (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      nome TEXT NOT NULL,
      logo_caminho TEXT,
      imagem_caminho TEXT,
      ativo INTEGER NOT NULL DEFAULT 1,
      criado_em TEXT NOT NULL DEFAULT (datetime('now')),
      atualizado_em TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_categoria_nome ON categoria(nome);
  `);
  
  // TABELA: Produtos
  coreDb.exec(`
    CREATE TABLE IF NOT EXISTS produto (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      sku TEXT UNIQUE,
      nome TEXT NOT NULL,
      descricao TEXT,
      fornecedor_id INTEGER,
      filial_id INTEGER NOT NULL,
      categoria_id INTEGER,
      preco REAL NOT NULL,
      desconto_valor REAL,
      desconto_percent REAL,
      parcelavel INTEGER NOT NULL DEFAULT 0,
      parcelas_max INTEGER,
      ativo INTEGER NOT NULL DEFAULT 1,
      criado_em TEXT NOT NULL DEFAULT (datetime('now')),
      atualizado_em TEXT,
      atualizado_por_usuario_id INTEGER,
      FOREIGN KEY (fornecedor_id) REFERENCES fornecedor(id),
      FOREIGN KEY (filial_id) REFERENCES filial(id),
      FOREIGN KEY (categoria_id) REFERENCES categoria(id)
    );
    CREATE INDEX IF NOT EXISTS idx_produto_sku ON produto(sku);
    CREATE INDEX IF NOT EXISTS idx_produto_filial ON produto(filial_id);
    CREATE INDEX IF NOT EXISTS idx_produto_categoria ON produto(categoria_id);
  `);
  
  // TABELA: Variantes de produtos
  coreDb.exec(`
    CREATE TABLE IF NOT EXISTS produto_variante (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      produto_id INTEGER NOT NULL,
      tamanho TEXT NOT NULL,
      cor TEXT NOT NULL,
      estoque INTEGER NOT NULL DEFAULT 0,
      estoque_minimo INTEGER NOT NULL DEFAULT 0,
      ativo INTEGER NOT NULL DEFAULT 1,
      criado_em TEXT NOT NULL DEFAULT (datetime('now')),
      atualizado_em TEXT,
      FOREIGN KEY (produto_id) REFERENCES produto(id) ON DELETE CASCADE,
      UNIQUE(produto_id, tamanho, cor)
    );
    CREATE INDEX IF NOT EXISTS idx_variante_produto ON produto_variante(produto_id);
  `);
  
  // TABELA: Imagens de produtos
  coreDb.exec(`
    CREATE TABLE IF NOT EXISTS produto_imagem (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      produto_id INTEGER NOT NULL,
      variante_id INTEGER,
      caminho TEXT NOT NULL,
      mime TEXT,
      size_bytes INTEGER,
      ordem INTEGER NOT NULL DEFAULT 0,
      criado_em TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (produto_id) REFERENCES produto(id) ON DELETE CASCADE,
      FOREIGN KEY (variante_id) REFERENCES produto_variante(id) ON DELETE SET NULL
    );
    CREATE INDEX IF NOT EXISTS idx_imagem_produto ON produto_imagem(produto_id);
  `);

  // TABELA: Cartões Presente
  coreDb.exec(`
    CREATE TABLE IF NOT EXISTS cartao_presente (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      numero TEXT UNIQUE NOT NULL,
      codigo_seguranca TEXT NOT NULL,
      valor_original REAL NOT NULL,
      saldo REAL NOT NULL,
      validade TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'ativo',
      comprador_id INTEGER,
      criado_em TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (comprador_id) REFERENCES cliente(id)
    );
    CREATE INDEX IF NOT EXISTS idx_cartao_numero ON cartao_presente(numero);
    CREATE INDEX IF NOT EXISTS idx_cartao_comprador ON cartao_presente(comprador_id);
  `);
  
  // TABELA: Carrinho de compras (alinhado com carrinhoController)
  coreDb.exec(`
    CREATE TABLE IF NOT EXISTS carrinho_item (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      cliente_id INTEGER NOT NULL,
      produto_variante_id INTEGER NOT NULL,
      quantidade INTEGER NOT NULL DEFAULT 1,
      criado_em TEXT NOT NULL DEFAULT (datetime('now')),
      atualizado_em TEXT,
      FOREIGN KEY (cliente_id) REFERENCES cliente(id) ON DELETE CASCADE,
      FOREIGN KEY (produto_variante_id) REFERENCES produto_variante(id) ON DELETE CASCADE,
      UNIQUE(cliente_id, produto_variante_id)
    );
    CREATE INDEX IF NOT EXISTS idx_carrinho_item_cliente ON carrinho_item(cliente_id);
  `);
  
  // TABELA: Pedidos (alinhado com pedidoController)
  coreDb.exec(`
    CREATE TABLE IF NOT EXISTS pedido (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      cliente_id INTEGER NOT NULL,
      filial_origem_id INTEGER,
      status_pedido TEXT NOT NULL DEFAULT 'novo',
      status_pagamento TEXT NOT NULL DEFAULT 'aguardando',
      pagamento_id_externo TEXT,
      pagamento_status_detalhado TEXT,
      pagamento_tipo TEXT,
      pagamento_parcelas INTEGER,
      subtotal REAL NOT NULL,
      desconto_total REAL DEFAULT 0,
      frete REAL DEFAULT 0,
      total REAL NOT NULL,
      cupom_id INTEGER,
      endereco_entrega_id INTEGER,
      codigo_rastreio TEXT,
      link_acompanhamento TEXT,
      data_prevista_entrega TEXT,
      separado_por_usuario_id INTEGER,
      observacoes TEXT,
      criado_em TEXT NOT NULL DEFAULT (datetime('now')),
      atualizado_em TEXT,
      FOREIGN KEY (cliente_id) REFERENCES cliente(id),
      FOREIGN KEY (filial_origem_id) REFERENCES filial(id),
      FOREIGN KEY (cupom_id) REFERENCES cupom(id),
      FOREIGN KEY (endereco_entrega_id) REFERENCES cliente_endereco(id)
    );
    CREATE INDEX IF NOT EXISTS idx_pedido_cliente ON pedido(cliente_id);
    CREATE INDEX IF NOT EXISTS idx_pedido_status ON pedido(status_pedido);
    CREATE INDEX IF NOT EXISTS idx_pedido_pagamento ON pedido(status_pagamento);
  `);
  
  // TABELA: Itens do pedido (alinhado com pedidoController)
  coreDb.exec(`
    CREATE TABLE IF NOT EXISTS pedido_item (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      pedido_id INTEGER NOT NULL,
      produto_id INTEGER NOT NULL,
      produto_variante_id INTEGER,
      quantidade INTEGER NOT NULL,
      preco_unit REAL NOT NULL,
      desconto_unit REAL DEFAULT 0,
      total_item REAL NOT NULL,
      criado_em TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (pedido_id) REFERENCES pedido(id) ON DELETE CASCADE,
      FOREIGN KEY (produto_id) REFERENCES produto(id),
      FOREIGN KEY (produto_variante_id) REFERENCES produto_variante(id)
    );
    CREATE INDEX IF NOT EXISTS idx_item_pedido ON pedido_item(pedido_id);
  `);
  
  // TABELA: Movimentos de estoque (alinhado com estoqueController e pedidoController)
  coreDb.exec(`
    CREATE TABLE IF NOT EXISTS estoque_movimento (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      variante_id INTEGER,
      produto_variante_id INTEGER,
      tipo TEXT NOT NULL CHECK(tipo IN ('entrada', 'saida', 'ajuste', 'devolucao')),
      quantidade INTEGER NOT NULL,
      motivo TEXT,
      referencia_tipo TEXT,
      referencia_id INTEGER,
      pedido_id INTEGER,
      usuario_id INTEGER,
      criado_em TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (variante_id) REFERENCES produto_variante(id),
      FOREIGN KEY (produto_variante_id) REFERENCES produto_variante(id),
      FOREIGN KEY (pedido_id) REFERENCES pedido(id)
    );
    CREATE INDEX IF NOT EXISTS idx_movimento_variante ON estoque_movimento(variante_id);
    CREATE INDEX IF NOT EXISTS idx_movimento_produto_variante ON estoque_movimento(produto_variante_id);
    CREATE INDEX IF NOT EXISTS idx_movimento_tipo ON estoque_movimento(tipo);
  `);
  
  // TABELA: Banners (alinhado com conteudoController — coluna caminho_imagem)
  coreDb.exec(`
    CREATE TABLE IF NOT EXISTS banner (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      titulo TEXT,
      subtitulo TEXT,
      caminho_imagem TEXT NOT NULL,
      link TEXT,
      ordem INTEGER NOT NULL DEFAULT 0,
      ativo INTEGER NOT NULL DEFAULT 1,
      criado_em TEXT NOT NULL DEFAULT (datetime('now')),
      atualizado_em TEXT
    );
  `);
  
  // TABELA: Carrossel de Produtos
  coreDb.exec(`
    CREATE TABLE IF NOT EXISTS carrossel (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      titulo TEXT,
      descricao TEXT,
      imagem_caminho TEXT NOT NULL,
      produto_id INTEGER,
      link TEXT,
      ordem INTEGER NOT NULL DEFAULT 0,
      ativo INTEGER NOT NULL DEFAULT 1,
      criado_em TEXT NOT NULL DEFAULT (datetime('now')),
      atualizado_em TEXT,
      FOREIGN KEY (produto_id) REFERENCES produto(id) ON DELETE SET NULL
    );
    CREATE INDEX IF NOT EXISTS idx_carrossel_ordem ON carrossel(ordem);
    CREATE INDEX IF NOT EXISTS idx_carrossel_ativo ON carrossel(ativo);
    CREATE INDEX IF NOT EXISTS idx_carrossel_produto ON carrossel(produto_id);
  `);
  
  // TABELA: Cupons de desconto (alinhado com conteudoController e pedidoController)
  coreDb.exec(`
    CREATE TABLE IF NOT EXISTS cupom (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      codigo TEXT UNIQUE NOT NULL,
      percentual REAL,
      valor_fixo REAL,
      quantidade_total INTEGER NOT NULL DEFAULT 0,
      quantidade_usada INTEGER NOT NULL DEFAULT 0,
      data_inicio TEXT,
      data_fim TEXT,
      ativo INTEGER NOT NULL DEFAULT 1,
      criado_em TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_cupom_codigo ON cupom(codigo);
  `);

  // TABELA: Registro de uso de cupons (alinhado com pedidoController)
  coreDb.exec(`
    CREATE TABLE IF NOT EXISTS cupom_uso (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      cupom_id INTEGER NOT NULL,
      pedido_id INTEGER NOT NULL,
      cliente_id INTEGER NOT NULL,
      valor_desconto REAL NOT NULL,
      criado_em TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (cupom_id) REFERENCES cupom(id),
      FOREIGN KEY (pedido_id) REFERENCES pedido(id),
      FOREIGN KEY (cliente_id) REFERENCES cliente(id)
    );
    CREATE INDEX IF NOT EXISTS idx_cupom_uso_cupom ON cupom_uso(cupom_id);
    CREATE INDEX IF NOT EXISTS idx_cupom_uso_pedido ON cupom_uso(pedido_id);
  `);
  
  // TABELA: Notificações (alinhado com conteudoController — coluna link, tipo nullable)
  coreDb.exec(`
    CREATE TABLE IF NOT EXISTS notificacao (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      cliente_id INTEGER,
      tipo TEXT DEFAULT 'geral',
      titulo TEXT NOT NULL,
      mensagem TEXT NOT NULL,
      link TEXT,
      lida INTEGER NOT NULL DEFAULT 0,
      criado_em TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (cliente_id) REFERENCES cliente(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_notificacao_cliente ON notificacao(cliente_id);
    CREATE INDEX IF NOT EXISTS idx_notificacao_lida ON notificacao(lida);
  `);
  
  // TABELA: Cancelamento/Devolução (alinhado com conteudoController pós-venda)
  coreDb.exec(`
    CREATE TABLE IF NOT EXISTS cancelamento_devolucao (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      pedido_id INTEGER NOT NULL,
      tipo TEXT NOT NULL CHECK(tipo IN ('cancelamento', 'devolucao', 'troca')),
      motivo TEXT,
      status_reembolso TEXT DEFAULT 'pendente',
      valor_reembolso REAL,
      processado_por_usuario_id INTEGER,
      criado_em TEXT NOT NULL DEFAULT (datetime('now')),
      atualizado_em TEXT,
      FOREIGN KEY (pedido_id) REFERENCES pedido(id)
    );
    CREATE INDEX IF NOT EXISTS idx_cancelamento_pedido ON cancelamento_devolucao(pedido_id);
    CREATE INDEX IF NOT EXISTS idx_cancelamento_status ON cancelamento_devolucao(status_reembolso);
  `);
  
  // TABELA: Reclamações (alinhado com conteudoController)
  coreDb.exec(`
    CREATE TABLE IF NOT EXISTS reclamacao (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      cliente_id INTEGER NOT NULL,
      pedido_id INTEGER,
      descricao TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'aberta',
      resposta TEXT,
      criado_em TEXT NOT NULL DEFAULT (datetime('now')),
      atualizado_em TEXT,
      FOREIGN KEY (cliente_id) REFERENCES cliente(id),
      FOREIGN KEY (pedido_id) REFERENCES pedido(id)
    );
    CREATE INDEX IF NOT EXISTS idx_reclamacao_cliente ON reclamacao(cliente_id);
    CREATE INDEX IF NOT EXISTS idx_reclamacao_status ON reclamacao(status);
  `);
  
  // TABELA: Mídia das reclamações (alinhado com conteudoController)
  coreDb.exec(`
    CREATE TABLE IF NOT EXISTS reclamacao_midia (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      reclamacao_id INTEGER NOT NULL,
      tipo TEXT NOT NULL,
      caminho TEXT NOT NULL,
      mime TEXT,
      size_bytes INTEGER,
      criado_em TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (reclamacao_id) REFERENCES reclamacao(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_midia_reclamacao ON reclamacao_midia(reclamacao_id);
  `);
  
  // TABELA: Tema/Configurações visuais (alinhado com conteudoController)
  coreDb.exec(`
    CREATE TABLE IF NOT EXISTS tema (
      id INTEGER PRIMARY KEY CHECK(id = 1),
      cor_primaria TEXT NOT NULL DEFAULT '#4a86e8',
      cor_secundaria TEXT NOT NULL DEFAULT '#357abd',
      cor_destaque TEXT,
      logo_path TEXT,
      favicon_path TEXT,
      atualizado_em TEXT NOT NULL DEFAULT (datetime('now'))
    );
    INSERT OR IGNORE INTO tema (id, cor_primaria, cor_secundaria) VALUES (1, '#4a86e8', '#357abd');
  `);
  
  // TABELA: Sessões de Caixa (alinhado com caixaController e financeiroController)
  coreDb.exec(`
    CREATE TABLE IF NOT EXISTS caixa_sessao (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      filial_id INTEGER NOT NULL,
      usuario_abertura_id INTEGER,
      usuario_fechamento_id INTEGER,
      valor_abertura REAL NOT NULL DEFAULT 0,
      valor_fechamento_declarado REAL,
      total_entradas REAL,
      total_saidas REAL,
      saldo_calculado REAL,
      diferenca REAL,
      status TEXT NOT NULL DEFAULT 'aberto' CHECK(status IN ('aberto', 'pendente_aprovacao', 'aprovado', 'fechado')),
      aberto_em TEXT NOT NULL DEFAULT (datetime('now')),
      fechado_em TEXT,
      observacoes_abertura TEXT,
      observacoes_fechamento TEXT,
      usuario_aprovacao_id INTEGER,
      aprovado_em TEXT,
      observacoes_aprovacao TEXT,
      FOREIGN KEY (filial_id) REFERENCES filial(id)
    );
    CREATE INDEX IF NOT EXISTS idx_caixa_sessao_filial ON caixa_sessao(filial_id);
    CREATE INDEX IF NOT EXISTS idx_caixa_sessao_status ON caixa_sessao(status);
  `);
  
  // TABELA: Lançamentos de Caixa (alinhado com caixaController)
  coreDb.exec(`
    CREATE TABLE IF NOT EXISTS caixa_lancamento (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      sessao_id INTEGER,
      filial_id INTEGER,
      pedido_id INTEGER,
      produto_variante_id INTEGER,
      tipo TEXT NOT NULL CHECK(tipo IN ('entrada', 'saida')),
      categoria TEXT,
      descricao TEXT NOT NULL,
      valor REAL NOT NULL,
      forma_pagamento TEXT,
      parcelas INTEGER,
      cliente_id INTEGER,
      usuario_vendedor_id INTEGER,
      origem TEXT,
      criado_em TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (sessao_id) REFERENCES caixa_sessao(id) ON DELETE CASCADE,
      FOREIGN KEY (filial_id) REFERENCES filial(id),
      FOREIGN KEY (pedido_id) REFERENCES pedido(id),
      FOREIGN KEY (produto_variante_id) REFERENCES produto_variante(id),
      FOREIGN KEY (cliente_id) REFERENCES cliente(id)
    );
    CREATE INDEX IF NOT EXISTS idx_lancamento_sessao ON caixa_lancamento(sessao_id);
    CREATE INDEX IF NOT EXISTS idx_lancamento_filial ON caixa_lancamento(filial_id);
    CREATE INDEX IF NOT EXISTS idx_lancamento_tipo ON caixa_lancamento(tipo);
  `);
  
  // TABELA: Contas a Pagar (alinhado com financeiroController)
  coreDb.exec(`
    CREATE TABLE IF NOT EXISTS financeiro_conta_pagar (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      filial_id INTEGER,
      fornecedor_id INTEGER,
      descricao TEXT NOT NULL,
      valor REAL NOT NULL,
      data_vencimento TEXT NOT NULL,
      data_pagamento TEXT,
      valor_pago REAL,
      status TEXT NOT NULL DEFAULT 'pendente' CHECK(status IN ('pendente', 'pago', 'atrasado', 'cancelado')),
      forma_pagamento TEXT,
      numero_documento TEXT,
      observacoes TEXT,
      criado_por_usuario_id INTEGER,
      pago_por_usuario_id INTEGER,
      criado_em TEXT NOT NULL DEFAULT (datetime('now')),
      atualizado_em TEXT,
      FOREIGN KEY (filial_id) REFERENCES filial(id),
      FOREIGN KEY (fornecedor_id) REFERENCES fornecedor(id)
    );
    CREATE INDEX IF NOT EXISTS idx_fin_conta_pagar_status ON financeiro_conta_pagar(status);
    CREATE INDEX IF NOT EXISTS idx_fin_conta_pagar_vencimento ON financeiro_conta_pagar(data_vencimento);
    CREATE INDEX IF NOT EXISTS idx_fin_conta_pagar_filial ON financeiro_conta_pagar(filial_id);
  `);
  
  // TABELA: Contas a Receber (alinhado com financeiroController)
  coreDb.exec(`
    CREATE TABLE IF NOT EXISTS financeiro_conta_receber (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      filial_id INTEGER,
      cliente_id INTEGER,
      descricao TEXT NOT NULL,
      valor REAL NOT NULL,
      data_vencimento TEXT NOT NULL,
      data_recebimento TEXT,
      valor_recebido REAL,
      status TEXT NOT NULL DEFAULT 'pendente' CHECK(status IN ('pendente', 'recebido', 'atrasado', 'cancelado')),
      forma_pagamento TEXT,
      numero_documento TEXT,
      observacoes TEXT,
      criado_por_usuario_id INTEGER,
      recebido_por_usuario_id INTEGER,
      criado_em TEXT NOT NULL DEFAULT (datetime('now')),
      atualizado_em TEXT,
      FOREIGN KEY (filial_id) REFERENCES filial(id),
      FOREIGN KEY (cliente_id) REFERENCES cliente(id)
    );
    CREATE INDEX IF NOT EXISTS idx_fin_conta_receber_status ON financeiro_conta_receber(status);
    CREATE INDEX IF NOT EXISTS idx_fin_conta_receber_vencimento ON financeiro_conta_receber(data_vencimento);
    CREATE INDEX IF NOT EXISTS idx_fin_conta_receber_filial ON financeiro_conta_receber(filial_id);
  `);
  
  // TABELA: Fechamento Financeiro (alinhado com financeiroController)
  coreDb.exec(`
    CREATE TABLE IF NOT EXISTS financeiro_fechamento (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      data_inicio TEXT NOT NULL,
      data_fim TEXT NOT NULL,
      filiais_json TEXT,
      total_receitas REAL NOT NULL DEFAULT 0,
      total_despesas REAL NOT NULL DEFAULT 0,
      resultado REAL NOT NULL DEFAULT 0,
      resumo_json TEXT,
      status TEXT NOT NULL DEFAULT 'gerado' CHECK(status IN ('gerado', 'aprovado', 'cancelado')),
      observacoes TEXT,
      criado_por_usuario_id INTEGER,
      criado_em TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_fechamento_periodo ON financeiro_fechamento(data_inicio, data_fim);
    CREATE INDEX IF NOT EXISTS idx_fechamento_status ON financeiro_fechamento(status);
  `);
  
  // Inserir filial padrão
  const insertFilial = coreDb.prepare('INSERT OR IGNORE INTO filial (nome, tipo) VALUES (?, ?)');
  insertFilial.run('Principal', 'loja');
  
  console.log('✅ CORE.DB criado com TODAS as tabelas');
  coreDb.close();
  
  // ============================================
  // 2. AUTH.DB - Autenticação e segurança
  // ============================================
  console.log('📦 Criando AUTH.DB (Autenticação e segurança)...');
  const authDb = new Database(authPath);
  
  authDb.pragma('journal_mode = WAL');
  authDb.pragma('foreign_keys = ON');
  authDb.pragma('synchronous = NORMAL');
  
  // TABELA: Grupos de acesso
  authDb.exec(`
    CREATE TABLE IF NOT EXISTS grupo_acesso (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      nome TEXT UNIQUE NOT NULL,
      descricao TEXT,
      criado_em TEXT NOT NULL DEFAULT (datetime('now'))
    );
  `);
  
  // TABELA: Permissões
  authDb.exec(`
    CREATE TABLE IF NOT EXISTS permissao (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      codigo TEXT UNIQUE NOT NULL,
      nome TEXT NOT NULL,
      modulo TEXT NOT NULL,
      criado_em TEXT NOT NULL DEFAULT (datetime('now'))
    );
  `);
  
  // TABELA: Relação grupo-permissão
  authDb.exec(`
    CREATE TABLE IF NOT EXISTS grupo_permissao (
      grupo_id INTEGER NOT NULL,
      permissao_id INTEGER NOT NULL,
      PRIMARY KEY (grupo_id, permissao_id),
      FOREIGN KEY (grupo_id) REFERENCES grupo_acesso(id) ON DELETE CASCADE,
      FOREIGN KEY (permissao_id) REFERENCES permissao(id) ON DELETE CASCADE
    );
  `);
  
  // TABELA: Usuários do sistema (com campo telefone adicionado na v3)
  authDb.exec(`
    CREATE TABLE IF NOT EXISTS usuario_sistema (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      nome_completo TEXT NOT NULL,
      login TEXT UNIQUE NOT NULL,
      senha_hash TEXT NOT NULL,
      email TEXT,
      telefone TEXT,
      filial_id INTEGER,
      grupo_acesso_id INTEGER,
      ativo INTEGER NOT NULL DEFAULT 1,
      ultimo_login TEXT,
      criado_em TEXT NOT NULL DEFAULT (datetime('now')),
      atualizado_em TEXT,
      FOREIGN KEY (grupo_acesso_id) REFERENCES grupo_acesso(id)
    );
    CREATE INDEX IF NOT EXISTS idx_usuario_login ON usuario_sistema(login);
    CREATE INDEX IF NOT EXISTS idx_usuario_email ON usuario_sistema(email);
  `);
  
  // TABELA: URLs autorizadas (CORS)
  authDb.exec(`
    CREATE TABLE IF NOT EXISTS urls_autorizadas (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      url TEXT UNIQUE NOT NULL,
      descricao TEXT,
      criado_em TEXT NOT NULL DEFAULT (datetime('now'))
    );
  `);
  
  // TABELA: Recuperação de senha (clientes)
  authDb.exec(`
    CREATE TABLE IF NOT EXISTS recuperacao_senha (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      cliente_id INTEGER NOT NULL,
      codigo_hash TEXT NOT NULL,
      expira_em TEXT NOT NULL,
      usado_em TEXT,
      criado_em TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_recuperacao_cliente ON recuperacao_senha(cliente_id);
    CREATE INDEX IF NOT EXISTS idx_recuperacao_codigo ON recuperacao_senha(codigo_hash);
    CREATE INDEX IF NOT EXISTS idx_recuperacao_expira ON recuperacao_senha(expira_em);
  `);

  // TABELA: Recuperação de senha de usuários do sistema (funcionários)
  authDb.exec(`
    CREATE TABLE IF NOT EXISTS recuperacao_senha_usuario (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      usuario_id INTEGER NOT NULL,
      codigo_hash TEXT NOT NULL,
      expira_em TEXT NOT NULL,
      usado_em TEXT,
      criado_em TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (usuario_id) REFERENCES usuario_sistema(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_recuperacao_usuario ON recuperacao_senha_usuario(usuario_id);
    CREATE INDEX IF NOT EXISTS idx_recuperacao_usuario_codigo ON recuperacao_senha_usuario(codigo_hash);
    CREATE INDEX IF NOT EXISTS idx_recuperacao_usuario_expira ON recuperacao_senha_usuario(expira_em);
  `);
  
  // TABELA: Tokens de API
  authDb.exec(`
    CREATE TABLE IF NOT EXISTS api_token (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      token TEXT UNIQUE NOT NULL,
      url_origem TEXT NOT NULL,
      ativo INTEGER NOT NULL DEFAULT 1,
      ultimo_uso TEXT,
      criado_em TEXT NOT NULL DEFAULT (datetime('now')),
      expira_em TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_token ON api_token(token);
  `);

  // TABELA: Tokens de Integração
  authDb.exec(`
    CREATE TABLE IF NOT EXISTS integracao_token (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      token_hash TEXT NOT NULL,
      expira_em TEXT NOT NULL,
      revogado INTEGER NOT NULL DEFAULT 0,
      criado_em TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_integracao_token_hash ON integracao_token(token_hash);
    CREATE INDEX IF NOT EXISTS idx_integracao_token_expira ON integracao_token(expira_em);
  `);

  // TABELA: Configuração de Webhook (v3)
  authDb.exec(`
    CREATE TABLE IF NOT EXISTS webhook_config (
      id INTEGER PRIMARY KEY CHECK(id = 1),
      url TEXT NOT NULL,
      secret TEXT,
      ativo INTEGER NOT NULL DEFAULT 1,
      criado_em TEXT NOT NULL DEFAULT (datetime('now')),
      atualizado_em TEXT
    );
  `);

  // TABELA: Logs de Webhook (v3)
  authDb.exec(`
    CREATE TABLE IF NOT EXISTS webhook_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      event_type TEXT NOT NULL,
      status TEXT NOT NULL,
      erro TEXT,
      criado_em TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_webhook_log_event ON webhook_log(event_type);
    CREATE INDEX IF NOT EXISTS idx_webhook_log_status ON webhook_log(status);
    CREATE INDEX IF NOT EXISTS idx_webhook_log_data ON webhook_log(criado_em);
  `);

  // TABELA: Autenticação de Dispositivos (v3)
  authDb.exec(`
    CREATE TABLE IF NOT EXISTS dispositivo_autenticacao (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      dispositivo_id TEXT NOT NULL,
      usuario_id INTEGER NOT NULL,
      ip TEXT,
      user_agent TEXT,
      status TEXT NOT NULL DEFAULT 'pendente' CHECK(status IN ('pendente', 'aprovado', 'rejeitado', 'revogado')),
      token_hash TEXT,
      aprovado_por TEXT,
      aprovado_em TEXT,
      ultimo_uso TEXT,
      criado_em TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (usuario_id) REFERENCES usuario_sistema(id)
    );
    CREATE INDEX IF NOT EXISTS idx_dispositivo_id ON dispositivo_autenticacao(dispositivo_id);
    CREATE INDEX IF NOT EXISTS idx_dispositivo_usuario ON dispositivo_autenticacao(usuario_id);
    CREATE INDEX IF NOT EXISTS idx_dispositivo_status ON dispositivo_autenticacao(status);
    CREATE INDEX IF NOT EXISTS idx_dispositivo_token ON dispositivo_autenticacao(token_hash);
  `);

  // TABELA: Inscrições de Push
  authDb.exec(`
    CREATE TABLE IF NOT EXISTS push_subscription (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      endpoint TEXT UNIQUE NOT NULL,
      expirationTime TEXT,
      p256dh TEXT,
      auth TEXT,
      criado_em TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_push_endpoint ON push_subscription(endpoint);
  `);
  
  // Inserir dados iniciais
  const insertGrupo = authDb.prepare('INSERT OR IGNORE INTO grupo_acesso (nome, descricao) VALUES (?, ?)');
  insertGrupo.run('Admin', 'Administrador total do sistema');
  
  const adminSenhaHash = bcrypt.hashSync('admin123', 10);
  const insertAdmin = authDb.prepare(`
    INSERT OR IGNORE INTO usuario_sistema (nome_completo, login, senha_hash, email, filial_id, grupo_acesso_id)
    VALUES (?, ?, ?, ?, ?, ?)
  `);
  insertAdmin.run('Administrador', 'admin', adminSenhaHash, null, 1, 1);
  
  console.log('✅ AUTH.DB criado com TODAS as tabelas');
  authDb.close();
  
  // ============================================
  // 3. AUDIT.DB - Auditoria e logs
  // ============================================
  console.log('📦 Criando AUDIT.DB (Auditoria e logs)...');
  const auditDb = new Database(auditPath);
  
  auditDb.pragma('journal_mode = WAL');
  auditDb.pragma('synchronous = NORMAL');
  
  // TABELA: Logs de auditoria
  auditDb.exec(`
    CREATE TABLE IF NOT EXISTS audit_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      entidade TEXT NOT NULL,
      entidade_id INTEGER NOT NULL,
      acao TEXT NOT NULL CHECK(acao IN ('create', 'update', 'delete', 'login', 'logout', 'status_change')),
      antes_json TEXT,
      depois_json TEXT,
      usuario_id INTEGER,
      usuario_tipo TEXT,
      ip TEXT,
      user_agent TEXT,
      criado_em TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_audit_entidade ON audit_log(entidade, entidade_id);
    CREATE INDEX IF NOT EXISTS idx_audit_usuario ON audit_log(usuario_id, usuario_tipo);
    CREATE INDEX IF NOT EXISTS idx_audit_data ON audit_log(criado_em);
  `);
  
  console.log('✅ AUDIT.DB criado com TODAS as tabelas');
  auditDb.close();
  
  console.log('\n╔════════════════════════════════════════════════════════════╗');
  console.log('║   ✅ BANCO DE DADOS INICIALIZADO COM SUCESSO!              ║');
  console.log('║                                                            ║');
  console.log('║   📊 Resumo:                                               ║');
  console.log('║   • CORE.DB: 25+ tabelas criadas                          ║');
  console.log('║   • AUTH.DB: 11 tabelas criadas (incl. webhook/dispositivo)║');
  console.log('║   • AUDIT.DB: 1 tabela criada                             ║');
  console.log('║                                                            ║');
  console.log('║   🔐 Usuário admin criado:                                 ║');
  console.log('║   • Login: admin                                           ║');
  console.log('║   • Senha: admin123                                        ║');
  console.log('╚════════════════════════════════════════════════════════════╝\n');
  
} catch (err) {
  console.error('\n❌ ERRO NA INICIALIZAÇÃO:', err.message);
  console.error(err);
  process.exit(1);
}
