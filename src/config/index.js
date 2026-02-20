/**
 * BOUTIQUE DINIZ API - Configurações Centralizadas
 * Desenvolvido por Estúdio Atlas
 */

require('dotenv').config();
const path = require('path');

const config = {
  // Ambiente
  env: process.env.NODE_ENV || 'development',
  isProduction: process.env.NODE_ENV === 'production',
  
  // Servidor
  server: {
    port: parseInt(process.env.PORT, 10) || 1535,
    host: process.env.HOST || '0.0.0.0'
  },
  
  // Segurança
  security: {
    apiKey: process.env.API_KEY || '1526',
    tokenSecret: process.env.TOKEN_SECRET || 'default_secret_change_in_production',
    tokenExpirationSeconds: parseInt(process.env.TOKEN_EXPIRATION_SECONDS, 10) || 900,
    encryptionKey: process.env.ENCRYPTION_KEY || 'default_encryption_key_32chars!!'
  },
  
  // Banco de dados
  database: {
    corePath: path.resolve(process.cwd(), process.env.DB_CORE_PATH || './data/core.db'),
    authPath: path.resolve(process.cwd(), process.env.DB_AUTH_PATH || './data/auth.db'),
    auditPath: path.resolve(process.cwd(), process.env.DB_AUDIT_PATH || './data/audit.db')
  },
  
  // Uploads
  upload: {
    maxSizeMB: parseInt(process.env.UPLOAD_MAX_SIZE_MB, 10) || 50,
    path: path.resolve(process.cwd(), process.env.UPLOAD_PATH || './data/uploads'),
    // Tipos MIME permitidos. Algumas variações (como image/jpg ou image/x-png) não são
    // retornadas pelas bibliotecas de detecção de MIME, mas são aceitas em
    // navegadores antigos. Para maior compatibilidade, adicionamos aliases.
    allowedMimeTypes: {
      images: [
        'image/jpeg', 'image/png', 'image/webp', 'image/gif',
        'image/jpg',       // alias comum para image/jpeg
        'image/x-png',     // alias para image/png
        'image/pjpeg',     // alias para image/jpeg em alguns navegadores
        'image/pjpg'       // alias adicional para image/jpeg
      ],
      videos: ['video/mp4', 'video/webm']
    },
    maxFileSizeBytes: (parseInt(process.env.UPLOAD_MAX_SIZE_MB, 10) || 50) * 1024 * 1024
  },
  
  // Backup
  backup: {
    path: path.resolve(process.cwd(), process.env.BACKUP_PATH || './data/backups'),
    retentionDays: parseInt(process.env.BACKUP_RETENTION_DAYS, 10) || 30,
    cronSchedule: process.env.BACKUP_CRON_SCHEDULE || '0 3 * * *'
  },
  
  // E-mail
  email: {
    host: process.env.SMTP_HOST || 'smtp.gmail.com',
    port: parseInt(process.env.SMTP_PORT, 10) || 587,
    secure: process.env.SMTP_SECURE === 'true',
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
    from: process.env.EMAIL_FROM || 'Boutique Diniz <noreply@boutiquediniz.com>'
  },
  
  // SMTP (alias para compatibilidade com notificacaoService)
  smtp: {
    host: process.env.SMTP_HOST || 'smtp.gmail.com',
    port: parseInt(process.env.SMTP_PORT, 10) || 587,
    secure: process.env.SMTP_SECURE === 'true',
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
    from: process.env.EMAIL_FROM || 'Boutique Diniz <noreply@boutiquediniz.com>'
  },
  
  // Google Apps Script
  googleAppsScript: {
    // URL padrão do Google Apps Script para envio de notificações por email.
    // Esta URL foi fornecida pelo cliente e corresponde à nova API de email.
    url: process.env.GOOGLE_APPS_SCRIPT_URL || 'https://script.google.com/macros/s/AKfycbzZUPie9IgAcFcQd2qzjZYFdPNXuWnyToAtHe1y4Zfp8jA9sMqifG9WGc19qXurZy5Cew/exec'
  },
  
  // Rate Limiting (otimizado para dados em massa)
  rateLimit: {
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS, 10) || 900000,
    maxRequests: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS, 10) || 500
  },
  
  // Logs
  logs: {
    level: process.env.LOG_LEVEL || 'info',
    path: path.resolve(process.cwd(), process.env.LOG_PATH || './logs')
  },
  
  // API
  api: {
    baseUrl: process.env.API_BASE_URL || 'http://localhost:1535',
    version: '1.0.0'
  },
  
  // Paginação padrão
  pagination: {
    defaultPageSize: 20,
    maxPageSize: 100
  },
  
  // Otimizações para dados em massa
  performance: {
    maxBodySize: process.env.MAX_BODY_SIZE || '50mb',
    maxQuerySize: parseInt(process.env.MAX_QUERY_SIZE, 10) || 10000,
    connectionPoolSize: parseInt(process.env.CONNECTION_POOL_SIZE, 10) || 20
  },
  
  // Branding - Atlas Soluções
  brand: {
    name: process.env.BRAND_NAME || 'Boutique Diniz',
    developer: process.env.BRAND_DEVELOPER || 'Atlas Soluções',
    year: process.env.BRAND_YEAR || '2026',
    website: process.env.BRAND_WEBSITE || 'https://www.atlassolutions.com.br'
  }
};

module.exports = config;
