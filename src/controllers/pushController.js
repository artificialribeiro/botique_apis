/**
 * BOUTIQUE DINIZ API - Controller de Notificações Web Push
 *
 * Este controlador gerencia as inscrições e o envio de notificações Web
 * Push para clientes que habilitaram o PWA. As rotas estão protegidas pelo
 * middleware `authenticate`, portanto exigem chave da API e token de
 * integração. As chaves VAPID devem ser definidas nas variáveis de
 * ambiente VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY e VAPID_SUBJECT.
 */

const db = require('../config/database');
const webpush = require('web-push');
const { success, created, notFound, unauthorized } = require('../utils/response');
const logger = require('../utils/logger');

// Configurar VAPID assim que o módulo for carregado. Se as chaves não
// estiverem definidas, o envio de notificações não funcionará, mas as
// rotas de inscrição ainda podem operar normalmente.
try {
  const vapidPublicKey = process.env.VAPID_PUBLIC_KEY;
  const vapidPrivateKey = process.env.VAPID_PRIVATE_KEY;
  const vapidSubject = process.env.VAPID_SUBJECT || 'mailto:noreply@example.com';
  if (vapidPublicKey && vapidPrivateKey) {
    webpush.setVapidDetails(vapidSubject, vapidPublicKey, vapidPrivateKey);
  }
} catch (err) {
  // Ignorar erros na configuração inicial
  logger.warn('Falha ao configurar VAPID para WebPush', err);
}

/**
 * GET /api/push/vapid-public-key
 * Retorna a chave pública VAPID para que o cliente consiga registrar
 * inscrições de push. Não requer autorização adicional além de
 * authenticate.
 */
function getVapidPublicKey(req, res) {
  const vapidPublicKey = process.env.VAPID_PUBLIC_KEY;
  return success(res, { publicKey: vapidPublicKey || null }, 'Chave pública VAPID');
}

/**
 * POST /api/push/subscribe
 * Registra uma nova inscrição de push. Espera receber no corpo da
 * requisição um objeto `subscription` conforme definido na API Web Push.
 */
function subscribe(req, res) {
  try {
    const { subscription } = req.body;
    if (!subscription || !subscription.endpoint) {
      return unauthorized(res, 'Inscrição inválida');
    }
    const { endpoint, expirationTime, keys } = subscription;
    const p256dh = keys && keys.p256dh;
    const auth = keys && keys.auth;
    const authDb = db.getAuth();
    // Inserir ou atualizar inscrição
    authDb.prepare(
      `INSERT INTO push_subscription (endpoint, expirationTime, p256dh, auth)
       VALUES (?, ?, ?, ?)
       ON CONFLICT(endpoint) DO UPDATE SET
         expirationTime = excluded.expirationTime,
         p256dh = excluded.p256dh,
         auth = excluded.auth,
         criado_em = datetime('now')`
    ).run(endpoint, expirationTime || null, p256dh || null, auth || null);
    logger.info('Inscrição de push registrada', { endpoint });
    return created(res, null, 'Inscrição registrada com sucesso');
  } catch (error) {
    logger.error('Erro ao registrar inscrição de push:', error);
    throw error;
  }
}

/**
 * POST /api/push/unsubscribe
 * Remove uma inscrição de push a partir do endpoint informado no corpo
 * da requisição.
 */
function unsubscribe(req, res) {
  try {
    const { endpoint } = req.body;
    if (!endpoint) {
      return unauthorized(res, 'Endpoint não fornecido');
    }
    const authDb = db.getAuth();
    const info = authDb.prepare(
      `DELETE FROM push_subscription WHERE endpoint = ?`
    ).run(endpoint);
    if (info.changes === 0) {
      return notFound(res, 'Inscrição não encontrada');
    }
    logger.info('Inscrição de push removida', { endpoint });
    return success(res, null, 'Inscrição removida');
  } catch (error) {
    logger.error('Erro ao remover inscrição de push:', error);
    throw error;
  }
}

/**
 * POST /api/push/send
 * Envia uma notificação de push para todas as inscrições registradas.
 * Espera receber no corpo da requisição um objeto com `titulo`, `mensagem`
 * e opcionalmente `url`. O envio é assíncrono, e falhas de entrega
 * removem inscrições inválidas da base de dados.
 */
async function send(req, res) {
  try {
    const { titulo, mensagem, url } = req.body;
    if (!titulo || !mensagem) {
      return unauthorized(res, 'Título ou mensagem não fornecidos');
    }
    const payload = JSON.stringify({ titulo, mensagem, url });
    const authDb = db.getAuth();
    const subscriptions = authDb.prepare(
      `SELECT endpoint, expirationTime, p256dh, auth FROM push_subscription`
    ).all();
    let enviados = 0;
    for (const sub of subscriptions) {
      const subscription = {
        endpoint: sub.endpoint,
        expirationTime: sub.expirationTime || undefined,
        keys: { p256dh: sub.p256dh, auth: sub.auth }
      };
      try {
        await webpush.sendNotification(subscription, payload);
        enviados++;
      } catch (error) {
        logger.warn('Falha ao enviar notificação, removendo inscrição', { endpoint: sub.endpoint, error: error.message });
        // Inscrição inválida, remover da base
        authDb.prepare(`DELETE FROM push_subscription WHERE endpoint = ?`).run(sub.endpoint);
      }
    }
    return success(res, { enviados }, `Notificações enviadas para ${enviados} inscrição(ões)`);
  } catch (error) {
    logger.error('Erro ao enviar notificações de push:', error);
    throw error;
  }
}

module.exports = {
  getVapidPublicKey,
  subscribe,
  unsubscribe,
  send
};