/**
 * BOUTIQUE DINIZ API - Utilitários de Criptografia
 * Desenvolvido por Estúdio Atlas
 */

const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const config = require('../config');

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16;
const AUTH_TAG_LENGTH = 16;
const SALT_ROUNDS = 10;

/**
 * Criptografa texto usando AES-256-GCM
 */
function encrypt(text) {
  if (!text) return null;
  
  const iv = crypto.randomBytes(IV_LENGTH);
  const key = Buffer.from(config.security.encryptionKey.padEnd(32, '0').slice(0, 32));
  
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  const authTag = cipher.getAuthTag();
  
  // Formato: iv:authTag:encrypted
  return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted}`;
}

/**
 * Descriptografa texto
 */
function decrypt(encryptedText) {
  if (!encryptedText) return null;
  
  try {
    const parts = encryptedText.split(':');
    if (parts.length !== 3) return null;
    
    const iv = Buffer.from(parts[0], 'hex');
    const authTag = Buffer.from(parts[1], 'hex');
    const encrypted = parts[2];
    
    const key = Buffer.from(config.security.encryptionKey.padEnd(32, '0').slice(0, 32));
    
    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
    decipher.setAuthTag(authTag);
    
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  } catch (error) {
    return null;
  }
}

/**
 * Gera hash SHA-256
 */
function sha256(text) {
  return crypto.createHash('sha256').update(text).digest('hex');
}

/**
 * Gera hash de senha com bcrypt
 */
async function hashPassword(password) {
  return bcrypt.hash(password, SALT_ROUNDS);
}

/**
 * Verifica senha com bcrypt
 */
async function verifyPassword(password, hash) {
  return bcrypt.compare(password, hash);
}

/**
 * Gera hash de senha síncrono
 */
function hashPasswordSync(password) {
  return bcrypt.hashSync(password, SALT_ROUNDS);
}

/**
 * Verifica senha síncrono
 */
function verifyPasswordSync(password, hash) {
  return bcrypt.compareSync(password, hash);
}

/**
 * Gera token aleatório
 */
function generateToken(length = 32) {
  return crypto.randomBytes(length).toString('hex');
}

/**
 * Gera código de recuperação (6 números + 4 letras)
 */
function generateRecoveryCode() {
  const numbers = Math.floor(100000 + Math.random() * 900000).toString();
  const letters = crypto.randomBytes(2).toString('hex').toUpperCase().slice(0, 4);
  return numbers + letters;
}

/**
 * Normaliza CPF (remove pontuação)
 */
function normalizeCpf(cpf) {
  return cpf.replace(/\D/g, '');
}

/**
 * Valida CPF
 */
function validateCpf(cpf) {
  cpf = normalizeCpf(cpf);
  
  if (cpf.length !== 11) return false;
  if (/^(\d)\1+$/.test(cpf)) return false;
  
  let sum = 0;
  for (let i = 0; i < 9; i++) {
    sum += parseInt(cpf.charAt(i)) * (10 - i);
  }
  let digit = 11 - (sum % 11);
  if (digit >= 10) digit = 0;
  if (digit !== parseInt(cpf.charAt(9))) return false;
  
  sum = 0;
  for (let i = 0; i < 10; i++) {
    sum += parseInt(cpf.charAt(i)) * (11 - i);
  }
  digit = 11 - (sum % 11);
  if (digit >= 10) digit = 0;
  if (digit !== parseInt(cpf.charAt(10))) return false;
  
  return true;
}

module.exports = {
  encrypt,
  decrypt,
  sha256,
  hashPassword,
  verifyPassword,
  hashPasswordSync,
  verifyPasswordSync,
  generateToken,
  generateRecoveryCode,
  normalizeCpf,
  validateCpf
};
