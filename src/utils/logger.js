/**
 * BOUTIQUE DINIZ API - Sistema de Logs
 * Desenvolvido por Estúdio Atlas
 */

const winston = require('winston');
const path = require('path');
const fs = require('fs');

// Configuração via variáveis de ambiente (carregada antes do config para evitar dependência circular)
require('dotenv').config();

const logPath = path.resolve(process.cwd(), process.env.LOG_PATH || './logs');
const logLevel = process.env.LOG_LEVEL || 'info';

// Garantir que o diretório de logs existe
if (!fs.existsSync(logPath)) {
  fs.mkdirSync(logPath, { recursive: true });
}

// Formato personalizado
const customFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.errors({ stack: true }),
  winston.format.printf(({ level, message, timestamp, stack, ...meta }) => {
    let log = `${timestamp} [${level.toUpperCase()}]: ${message}`;
    if (Object.keys(meta).length > 0) {
      log += ` ${JSON.stringify(meta)}`;
    }
    if (stack) {
      log += `\n${stack}`;
    }
    return log;
  })
);

// Formato JSON para arquivos
const jsonFormat = winston.format.combine(
  winston.format.timestamp(),
  winston.format.errors({ stack: true }),
  winston.format.json()
);

// Criar logger
const logger = winston.createLogger({
  level: logLevel,
  defaultMeta: { service: 'boutique-diniz-api' },
  transports: [
    // Console (desenvolvimento)
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        customFormat
      )
    }),
    // Arquivo de logs gerais
    new winston.transports.File({
      filename: path.join(logPath, 'combined.log'),
      format: jsonFormat,
      maxsize: 10 * 1024 * 1024, // 10MB
      maxFiles: 5
    }),
    // Arquivo de erros
    new winston.transports.File({
      filename: path.join(logPath, 'error.log'),
      level: 'error',
      format: jsonFormat,
      maxsize: 10 * 1024 * 1024,
      maxFiles: 5
    }),
    // Arquivo de acessos
    new winston.transports.File({
      filename: path.join(logPath, 'access.log'),
      level: 'http',
      format: jsonFormat,
      maxsize: 10 * 1024 * 1024,
      maxFiles: 5
    })
  ]
});

// Stream para Morgan (logs de requisições HTTP)
logger.stream = {
  write: (message) => {
    logger.http(message.trim());
  }
};

module.exports = logger;
