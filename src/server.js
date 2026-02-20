/**
 * BOUTIQUE DINIZ API - Servidor Principal
 * Desenvolvido por Estúdio Atlas
 * 
 * Sistema de gestão completo para Boutique Diniz
 * Inclui: Clientes, Produtos, Estoque, Pedidos, Caixa, Backup e mais
 *
 * CORREÇÃO v4 — CORS e segurança para hospedagem em plataformas externas:
 *   - CORS aceita TODAS as origens (resolve bloqueio do Chrome em iframes)
 *   - Helmet configurado para permitir embedding em qualquer plataforma
 *   - Cadastro de URLs autorizadas protegido por chave de segurança
 *   - Headers X-Frame-Options removidos para permitir iframe
 */

require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cron = require('node-cron');
const path = require('path');

const config = require('./config');
const logger = require('./utils/logger');
const routes = require('./routes');
const { errorHandler, notFoundHandler } = require('./middlewares/errorHandler');
const sistemaController = require('./controllers/sistemaController');
const backupController = require('./controllers/backupController');

// Inicializar Express
const app = express();

// Trust proxy — necessário para express-rate-limit funcionar corretamente
// atrás de proxies reversos (Railway, Render, Nginx, etc.)
app.set('trust proxy', 1);

// ============================================
// MIDDLEWARES DE SEGURANÇA
// ============================================

// Helmet - Headers de segurança (configurado para permitir iframe/embedding)
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false,
  crossOriginOpenerPolicy: false,
  crossOriginResourcePolicy: false,
  frameguard: false,              // Permite ser carregado em iframe de qualquer origem
  xFrameOptions: false            // Remove X-Frame-Options para não bloquear iframe
}));

// ============================================
// CORS - ACEITA TODAS AS ORIGENS
// ============================================

// Quando o sistema está hospedado dentro de outro programa/plataforma,
// o Chrome bloqueia requisições cross-origin. Para resolver isso,
// aceitamos TODAS as origens. A segurança é feita via API Key + Token.
app.use(cors({
  origin: true,                   // Aceita QUALQUER origem
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'],
  allowedHeaders: [
    'Content-Type',
    'X-API-KEY',
    'X-API-TOKEN',
    'X-User-Id',
    'X-User-Type',
    'X-Admin-Key',
    'Authorization',
    'Accept',
    'Origin',
    'Access-Control-Request-Method',
    'Access-Control-Request-Headers'
  ],
  credentials: true,
  maxAge: 86400,
  preflightContinue: false,
  optionsSuccessStatus: 200
}));

// Middleware adicional para garantir headers CORS em TODAS as respostas
// (fallback para casos onde o middleware cors() não cobre)
app.use((req, res, next) => {
  const origin = req.headers.origin;

  // Sempre refletir a origem da requisição (ou * se não houver)
  if (origin) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  } else {
    res.setHeader('Access-Control-Allow-Origin', '*');
  }

  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-API-KEY, X-API-TOKEN, X-User-Id, X-User-Type, X-Admin-Key, Authorization, Accept, Origin');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Max-Age', '86400');
  res.setHeader('Access-Control-Expose-Headers', 'Content-Length, X-JSON-Response-Size');

  // Remover headers que bloqueiam iframe
  res.removeHeader('X-Frame-Options');
  res.removeHeader('Cross-Origin-Opener-Policy');
  res.removeHeader('Cross-Origin-Resource-Policy');
  res.removeHeader('Cross-Origin-Embedder-Policy');

  // Responder a preflight requests imediatamente
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }

  next();
});

// ============================================
// RATE LIMITING
// ============================================

const limiter = rateLimit({
  windowMs: config.rateLimit.windowMs,
  max: config.rateLimit.maxRequests,
  message: {
    success: false,
    message: 'Muitas requisicoes. Tente novamente mais tarde.',
    error: { code: 'RATE_LIMIT_EXCEEDED' }
  },
  standardHeaders: true,
  legacyHeaders: false,
  // Validar proxy corretamente
  validate: { trustProxy: false, xForwardedForHeader: false },
  skip: (req) => {
    // Não aplicar rate limit em health check, admin login e admin URLs
    return req.path === '/api/health' || 
           req.path === '/api/admin/login' ||
           req.path.startsWith('/api/admin/');
  }
});
app.use('/api/', limiter);

// ============================================
// MIDDLEWARES DE PARSING
// ============================================

app.use(express.json({ limit: config.performance.maxBodySize }));
app.use(express.urlencoded({ extended: true, limit: config.performance.maxBodySize }));

// ============================================
// TIMEOUT PARA UPLOADS LONGOS
// ============================================

app.use((req, res, next) => {
  // Aumentar timeout para uploads (60 segundos)
  req.setTimeout(60000);
  res.setTimeout(60000);

  // Adicionar handler de timeout
  req.on('timeout', () => {
    logger.error('Timeout na requisição: ' + req.method + ' ' + req.path);
    if (!res.headersSent) {
      res.status(408).json({
        success: false,
        message: 'Requisicao expirou. Tente novamente.',
        error: { code: 'REQUEST_TIMEOUT' }
      });
    }
  });

  res.on('timeout', () => {
    logger.error('Timeout na resposta: ' + req.method + ' ' + req.path);
  });

  next();
});

// ============================================
// ARQUIVOS ESTÁTICOS (UPLOADS)
// ============================================

app.use('/uploads', express.static(path.join(config.upload.path)));

// ============================================
// LOGGING DE REQUISIÇÕES
// ============================================

app.use((req, res, next) => {
  const start = Date.now();

  res.on('finish', () => {
    const duration = Date.now() - start;
    logger.http(req.method + ' ' + req.originalUrl + ' ' + res.statusCode + ' ' + duration + 'ms', {
      method: req.method,
      url: req.originalUrl,
      status: res.statusCode,
      duration,
      ip: req.ip
    });
  });

  next();
});

// ============================================
// ROTAS
// ============================================

// Rota raiz
app.get('/', (req, res) => {
  res.json({
    success: true,
    message: config.brand.name + ' API',
    version: config.api.version,
    developer: config.brand.developer,
    website: config.brand.website,
    documentation: '/docs',
    health: '/api/health'
  });
});

// Rotas da API
app.use('/api', routes);

// ============================================
// TRATAMENTO DE ERROS
// ============================================

app.use(notFoundHandler);
app.use(errorHandler);

// ============================================
// TAREFAS AGENDADAS (CRON)
// ============================================

// Backup automático (padrão: 3h da manhã)
cron.schedule(config.backup.cronSchedule, () => {
  logger.info('Executando backup automático agendado...');
  backupController.backupAutomatico();
});

// Limpeza de tokens expirados (a cada hora)
cron.schedule('0 * * * *', () => {
  logger.info('Limpando tokens expirados...');
  sistemaController.limparTokensExpirados();
});

// Limpeza de backups antigos (diariamente às 4h)
cron.schedule('0 4 * * *', () => {
  logger.info('Limpando backups antigos...');
  backupController.limparBackupsAntigos();
});

// ============================================
// INICIALIZAÇÃO DO SERVIDOR
// ============================================

const server = app.listen(config.server.port, config.server.host, () => {
  console.log('');
  console.log('╔════════════════════════════════════════════════════════════╗');
  console.log('║                  ' + config.brand.name.padEnd(45) + '║');
  console.log('║                 Desenvolvido por ' + config.brand.developer.padEnd(23) + '║');
  console.log('╠════════════════════════════════════════════════════════════╣');
  console.log('║  Status: ✅ Online                                         ║');
  console.log('║  Ambiente: ' + config.env.padEnd(43) + '║');
  console.log('║  Porta: ' + config.server.port.toString().padEnd(46) + '║');
  console.log('║  URL: http://' + config.server.host + ':' + config.server.port + ''.padEnd(47) + '║');
  console.log('╠════════════════════════════════════════════════════════════╣');
  console.log('║  Endpoints:                                                ║');
  console.log('║  • Health: GET /api/health                                 ║');
  console.log('║  • Token:  POST /api/token                                 ║');
  console.log('║  • Admin:  GET /api/admin                                  ║');
  console.log('║  • Docs:   Ver documentação                                ║');
  console.log('╠════════════════════════════════════════════════════════════╣');
  console.log('║  Segurança:                                                ║');
  console.log('║  • CORS: Todas as origens aceitas (segurança via API Key)  ║');
  console.log('║  • URLs: Cadastro protegido por chave de segurança         ║');
  console.log('║  • Iframe: Permitido em qualquer plataforma                ║');
  console.log('╠════════════════════════════════════════════════════════════╣');
  console.log('║  Tarefas agendadas:                                        ║');
  console.log('║  • Backup automático: ' + config.backup.cronSchedule.padEnd(32) + '║');
  console.log('║  • Limpeza de tokens: a cada hora                          ║');
  console.log('║  • Limpeza de backups: diariamente às 4h (backups > 7 dias) ║');
  console.log('║  • Notificações: Email e Google Apps Script                ║');
  console.log('╚════════════════════════════════════════════════════════════╝');
  console.log('');

  logger.info('Servidor ' + config.brand.name + ' iniciado em ' + config.server.host + ':' + config.server.port);
  logger.info('Desenvolvido por ' + config.brand.developer);
  logger.info('CORS: Todas as origens aceitas');
});

// ============================================
// GRACEFUL SHUTDOWN
// ============================================

const gracefulShutdown = (signal) => {
  logger.info('Recebido sinal ' + signal + '. Encerrando ' + config.brand.name + '...');

  server.close(() => {
    logger.info('Servidor HTTP encerrado');

    // Fechar conexões com banco de dados
    const db = require('./config/database');
    db.closeAll();

    logger.info('Conexoes com banco de dados encerradas');
    process.exit(0);
  });

  // Forçar encerramento após 10 segundos
  setTimeout(() => {
    logger.error('Encerramento forcado apos timeout');
    process.exit(1);
  }, 10000);
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Tratamento de erros não capturados
process.on('uncaughtException', (error) => {
  logger.error('Erro nao capturado em ' + config.brand.name + ':', error);
  gracefulShutdown('uncaughtException');
});

process.on('unhandledRejection', (reason, promise) => {
  logger.error('Promise rejeitada nao tratada:', { reason, promise });
});

module.exports = app;
