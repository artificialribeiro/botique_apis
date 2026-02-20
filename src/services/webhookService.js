/**
 * BOUTIQUE DINIZ API - Serviço de Webhook
 * Desenvolvido por Estúdio Atlas
 *
 * Responsável por disparar eventos para serviços externos.
 * Todos os eventos relevantes do sistema (recuperação de senha, atualização
 * de pedido, compra, atualização de dados do cliente, autenticação de
 * dispositivo, etc.) são enviados para a URL de webhook configurada.
 *
 * Cada evento inclui:
 *   - tipo do evento (event_type)
 *   - dados do evento (data)
 *   - email e/ou telefone do destinatário quando aplicável
 *   - timestamp
 *
 * A URL do webhook é configurada via variável de ambiente WEBHOOK_URL
 * ou pela tabela webhook_config no banco auth.db.
 */

const logger = require('../utils/logger');

// ============================================
// TIPOS DE EVENTOS
// ============================================
const WEBHOOK_EVENTS = {
  // Clientes
  CLIENTE_RECUPERACAO_SENHA: 'cliente.recuperacao_senha',
  CLIENTE_DADOS_ATUALIZADOS: 'cliente.dados_atualizados',
  CLIENTE_CADASTRO: 'cliente.cadastro',

  // Pedidos
  PEDIDO_CRIADO: 'pedido.criado',
  PEDIDO_STATUS_ATUALIZADO: 'pedido.status_atualizado',
  PEDIDO_PAGAMENTO_CONFIRMADO: 'pedido.pagamento_confirmado',
  PEDIDO_ENVIADO: 'pedido.enviado',
  PEDIDO_ENTREGUE: 'pedido.entregue',
  PEDIDO_CANCELADO: 'pedido.cancelado',

  // Funcionários
  FUNCIONARIO_RECUPERACAO_SENHA: 'funcionario.recuperacao_senha',
  FUNCIONARIO_DADOS_ATUALIZADOS: 'funcionario.dados_atualizados',

  // Dispositivos
  DISPOSITIVO_AUTENTICACAO_SOLICITADA: 'dispositivo.autenticacao_solicitada',
  DISPOSITIVO_AUTENTICACAO_APROVADA: 'dispositivo.autenticacao_aprovada',
  DISPOSITIVO_AUTENTICACAO_REJEITADA: 'dispositivo.autenticacao_rejeitada',

  // Caixa
  CAIXA_ABERTO: 'caixa.aberto',
  CAIXA_FECHADO: 'caixa.fechado',
  CAIXA_APROVADO: 'caixa.aprovado',

  // Estoque
  ESTOQUE_BAIXO: 'estoque.alerta_baixo',

  // Pós-venda
  POSVENDA_SOLICITACAO: 'posvenda.solicitacao',
  RECLAMACAO_CRIADA: 'reclamacao.criada'
};

// ============================================
// FILA DE EVENTOS (em memória, com retry)
// ============================================
const eventQueue = [];
let isProcessing = false;
const MAX_RETRIES = 3;
const RETRY_DELAY_MS = 5000;

/**
 * Obtém a configuração do webhook (URL e secret)
 */
function getWebhookConfig() {
  try {
    // Prioridade 1: Variável de ambiente
    const envUrl = process.env.WEBHOOK_URL;
    const envSecret = process.env.WEBHOOK_SECRET || '';

    if (envUrl) {
      return { url: envUrl, secret: envSecret, ativo: true };
    }

    // Prioridade 2: Banco de dados
    const db = require('../config/database');
    const authDb = db.getAuth();
    const config = authDb.prepare('SELECT * FROM webhook_config WHERE id = 1').get();

    if (config && config.ativo) {
      return { url: config.url, secret: config.secret || '', ativo: true };
    }

    return { url: null, secret: '', ativo: false };
  } catch (err) {
    // Se a tabela não existir ainda, retorna inativo
    return { url: null, secret: '', ativo: false };
  }
}

/**
 * Dispara um evento de webhook
 * @param {string} eventType - Tipo do evento (usar constantes WEBHOOK_EVENTS)
 * @param {object} data - Dados do evento
 * @param {object} destinatario - { email, telefone, nome } do destinatário (opcional)
 */
async function dispararEvento(eventType, data, destinatario = {}) {
  const config = getWebhookConfig();

  if (!config.ativo || !config.url) {
    logger.debug('Webhook não configurado ou inativo, evento ignorado', { eventType });
    return;
  }

  const payload = {
    event_type: eventType,
    timestamp: new Date().toISOString(),
    destinatario: {
      email: destinatario.email || null,
      telefone: destinatario.telefone || null,
      nome: destinatario.nome || null
    },
    data: data
  };

  eventQueue.push({
    payload,
    url: config.url,
    secret: config.secret,
    retries: 0
  });

  // Processar fila de forma assíncrona
  if (!isProcessing) {
    processQueue();
  }
}

/**
 * Processa a fila de eventos pendentes
 */
async function processQueue() {
  if (isProcessing || eventQueue.length === 0) return;
  isProcessing = true;

  while (eventQueue.length > 0) {
    const event = eventQueue.shift();

    try {
      await enviarWebhook(event.url, event.payload, event.secret);
      logWebhookEnvio(event.payload.event_type, 'sucesso', null);
      logger.info('Webhook enviado com sucesso', {
        eventType: event.payload.event_type,
        url: event.url
      });
    } catch (error) {
      event.retries++;
      if (event.retries < MAX_RETRIES) {
        logger.warn('Webhook falhou, reagendando tentativa', {
          eventType: event.payload.event_type,
          tentativa: event.retries,
          erro: error.message
        });
        // Reagendar com delay
        setTimeout(() => {
          eventQueue.push(event);
          if (!isProcessing) processQueue();
        }, RETRY_DELAY_MS * event.retries);
      } else {
        logger.error('Webhook falhou após todas as tentativas', {
          eventType: event.payload.event_type,
          erro: error.message
        });
        logWebhookEnvio(event.payload.event_type, 'falha', error.message);
      }
    }
  }

  isProcessing = false;
}

/**
 * Envia o webhook via HTTP POST
 */
async function enviarWebhook(url, payload, secret) {
  const crypto = require('crypto');
  const payloadStr = JSON.stringify(payload);

  const headers = {
    'Content-Type': 'application/json',
    'X-Webhook-Event': payload.event_type,
    'X-Webhook-Timestamp': payload.timestamp,
    'User-Agent': 'BoutiqueDiniz-Webhook/1.0'
  };

  // Assinar payload com HMAC-SHA256 se secret configurado
  if (secret) {
    const signature = crypto
      .createHmac('sha256', secret)
      .update(payloadStr)
      .digest('hex');
    headers['X-Webhook-Signature'] = `sha256=${signature}`;
  }

  // Usar fetch nativo (Node 18+) ou http/https
  if (typeof fetch === 'function') {
    const response = await fetch(url, {
      method: 'POST',
      headers,
      body: payloadStr,
      signal: AbortSignal.timeout(10000)
    });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }
    return response;
  } else {
    // Fallback para http/https nativo
    return new Promise((resolve, reject) => {
      const urlObj = new URL(url);
      const lib = urlObj.protocol === 'https:' ? require('https') : require('http');

      const req = lib.request(urlObj, {
        method: 'POST',
        headers: {
          ...headers,
          'Content-Length': Buffer.byteLength(payloadStr)
        },
        timeout: 10000
      }, (res) => {
        let body = '';
        res.on('data', chunk => body += chunk);
        res.on('end', () => {
          if (res.statusCode >= 200 && res.statusCode < 300) {
            resolve({ status: res.statusCode, body });
          } else {
            reject(new Error(`HTTP ${res.statusCode}: ${body}`));
          }
        });
      });

      req.on('error', reject);
      req.on('timeout', () => {
        req.destroy();
        reject(new Error('Timeout'));
      });
      req.write(payloadStr);
      req.end();
    });
  }
}

/**
 * Registra o envio do webhook no banco de dados para auditoria
 */
function logWebhookEnvio(eventType, status, erro) {
  try {
    const db = require('../config/database');
    const authDb = db.getAuth();
    authDb.prepare(`
      INSERT INTO webhook_log (event_type, status, erro, criado_em)
      VALUES (?, ?, ?, datetime('now'))
    `).run(eventType, status, erro);
  } catch (err) {
    // Silencioso — não queremos que falha de log quebre o sistema
    logger.debug('Falha ao registrar log de webhook', { erro: err.message });
  }
}

// ============================================
// HELPERS PARA EVENTOS ESPECÍFICOS
// ============================================

/**
 * Evento: Cliente solicitou recuperação de senha
 */
function eventoRecuperacaoSenhaCliente(cliente, codigoRecuperacao) {
  dispararEvento(WEBHOOK_EVENTS.CLIENTE_RECUPERACAO_SENHA, {
    cliente_id: cliente.id,
    nome: cliente.nome_completo,
    codigo_recuperacao: codigoRecuperacao
  }, {
    email: cliente.email,
    telefone: cliente.celular,
    nome: cliente.nome_completo
  });
}

/**
 * Evento: Funcionário solicitou recuperação de senha
 */
function eventoRecuperacaoSenhaFuncionario(funcionario, codigoRecuperacao) {
  dispararEvento(WEBHOOK_EVENTS.FUNCIONARIO_RECUPERACAO_SENHA, {
    funcionario_id: funcionario.id,
    nome: funcionario.nome_completo,
    login: funcionario.login,
    codigo_recuperacao: codigoRecuperacao
  }, {
    email: funcionario.email,
    telefone: funcionario.telefone,
    nome: funcionario.nome_completo
  });
}

/**
 * Evento: Pedido criado / atualizado / pago / enviado
 */
function eventoPedido(eventType, pedido, cliente) {
  dispararEvento(eventType, {
    pedido_id: pedido.id,
    status_pedido: pedido.status_pedido,
    status_pagamento: pedido.status_pagamento,
    total: pedido.total,
    codigo_rastreio: pedido.codigo_rastreio || null
  }, {
    email: cliente.email,
    telefone: cliente.celular,
    nome: cliente.nome_completo
  });
}

/**
 * Evento: Dados do cliente atualizados
 */
function eventoClienteAtualizado(cliente) {
  dispararEvento(WEBHOOK_EVENTS.CLIENTE_DADOS_ATUALIZADOS, {
    cliente_id: cliente.id,
    nome: cliente.nome_completo,
    campos_atualizados: true
  }, {
    email: cliente.email,
    telefone: cliente.celular,
    nome: cliente.nome_completo
  });
}

/**
 * Evento: Solicitação de autenticação de dispositivo
 */
function eventoDispositivoAutenticacao(solicitacao, funcionario) {
  dispararEvento(WEBHOOK_EVENTS.DISPOSITIVO_AUTENTICACAO_SOLICITADA, {
    solicitacao_id: solicitacao.id,
    dispositivo_id: solicitacao.dispositivo_id,
    ip: solicitacao.ip,
    user_agent: solicitacao.user_agent,
    funcionario_id: funcionario.id,
    funcionario_nome: funcionario.nome_completo,
    funcionario_login: funcionario.login
  }, {
    email: funcionario.email,
    telefone: funcionario.telefone,
    nome: funcionario.nome_completo
  });
}

module.exports = {
  WEBHOOK_EVENTS,
  dispararEvento,
  eventoRecuperacaoSenhaCliente,
  eventoRecuperacaoSenhaFuncionario,
  eventoPedido,
  eventoClienteAtualizado,
  eventoDispositivoAutenticacao,
  getWebhookConfig
};
