/**
 * BOUTIQUE DINIZ API - Controller de Backup e Restauração
 * Desenvolvido por Estúdio Atlas
 */

const db = require('../config/database');
const config = require('../config');
const { success, validationError, internalError } = require('../utils/response');
const logger = require('../utils/logger');
const archiver = require('archiver');
const unzipper = require('unzipper');
const fs = require('fs');
const path = require('path');

/**
 * POST /api/backup
 * Cria backup completo do sistema
 */
async function criarBackup(req, res) {
  try {
    // Fechar conexões para garantir integridade
    db.closeAll();
    
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    const backupFileName = `backup_${timestamp}.zip`;
    const backupPath = path.join(config.backup.path, backupFileName);
    
    // Garantir que o diretório existe
    if (!fs.existsSync(config.backup.path)) {
      fs.mkdirSync(config.backup.path, { recursive: true });
    }
    
    // Criar arquivo ZIP
    const output = fs.createWriteStream(backupPath);
    const archive = archiver('zip', { zlib: { level: 9 } });
    
    return new Promise((resolve, reject) => {
      output.on('close', () => {
        const sizeBytes = archive.pointer();
        const sizeMB = (sizeBytes / (1024 * 1024)).toFixed(2);
        
        logger.info('Backup criado com sucesso', { arquivo: backupFileName, tamanho: `${sizeMB} MB` });
        
        resolve(success(res, {
          arquivo: backupFileName,
          tamanho_bytes: sizeBytes,
          tamanho_mb: sizeMB,
          criado_em: new Date().toISOString()
        }, 'Backup criado com sucesso'));
      });
      
      output.on('error', (err) => {
        logger.error('Erro ao criar backup:', err);
        reject(internalError(res, 'Erro ao criar backup'));
      });
      
      archive.on('error', (err) => {
        logger.error('Erro no archiver:', err);
        reject(internalError(res, 'Erro ao compactar backup'));
      });
      
      archive.pipe(output);
      
      // Adicionar bancos de dados
      const dataDir = path.resolve(process.cwd(), './data');
      
      if (fs.existsSync(path.join(dataDir, 'core.db'))) {
        archive.file(path.join(dataDir, 'core.db'), { name: 'data/core.db' });
      }
      if (fs.existsSync(path.join(dataDir, 'auth.db'))) {
        archive.file(path.join(dataDir, 'auth.db'), { name: 'data/auth.db' });
      }
      if (fs.existsSync(path.join(dataDir, 'audit.db'))) {
        archive.file(path.join(dataDir, 'audit.db'), { name: 'data/audit.db' });
      }
      
      // Adicionar uploads
      const uploadsDir = path.join(dataDir, 'uploads');
      if (fs.existsSync(uploadsDir)) {
        archive.directory(uploadsDir, 'data/uploads');
      }
      
      // Adicionar .env (se existir)
      const envPath = path.resolve(process.cwd(), '.env');
      if (fs.existsSync(envPath)) {
        archive.file(envPath, { name: '.env' });
      }
      
      archive.finalize();
    });
  } catch (error) {
    logger.error('Erro ao criar backup:', error);
    throw error;
  }
}

/**
 * POST /api/restore
 * Restaura backup
 */
async function restaurarBackup(req, res) {
  try {
    if (!req.file) {
      return validationError(res, [{ field: 'arquivo', issue: 'Arquivo de backup é obrigatório' }]);
    }
    
    const backupFile = req.file.path;
    
    // Verificar se é um arquivo ZIP válido
    if (!req.file.originalname.endsWith('.zip')) {
      fs.unlinkSync(backupFile);
      return validationError(res, [{ field: 'arquivo', issue: 'Arquivo deve ser um ZIP' }]);
    }
    
    // Fechar conexões
    db.closeAll();
    
    // Criar backup do estado atual antes de restaurar
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    const preRestoreBackup = `pre_restore_${timestamp}.zip`;
    const preRestorePath = path.join(config.backup.path, preRestoreBackup);
    
    // Criar backup de segurança
    const preBackupArchive = archiver('zip', { zlib: { level: 9 } });
    const preBackupOutput = fs.createWriteStream(preRestorePath);
    
    await new Promise((resolve, reject) => {
      preBackupOutput.on('close', resolve);
      preBackupOutput.on('error', reject);
      preBackupArchive.pipe(preBackupOutput);
      
      const dataDir = path.resolve(process.cwd(), './data');
      if (fs.existsSync(path.join(dataDir, 'core.db'))) {
        preBackupArchive.file(path.join(dataDir, 'core.db'), { name: 'data/core.db' });
      }
      if (fs.existsSync(path.join(dataDir, 'auth.db'))) {
        preBackupArchive.file(path.join(dataDir, 'auth.db'), { name: 'data/auth.db' });
      }
      if (fs.existsSync(path.join(dataDir, 'audit.db'))) {
        preBackupArchive.file(path.join(dataDir, 'audit.db'), { name: 'data/audit.db' });
      }
      
      preBackupArchive.finalize();
    });
    
    logger.info('Backup de segurança criado', { arquivo: preRestoreBackup });
    
    // Extrair backup
    const extractPath = path.resolve(process.cwd());
    
    await new Promise((resolve, reject) => {
      fs.createReadStream(backupFile)
        .pipe(unzipper.Extract({ path: extractPath }))
        .on('close', resolve)
        .on('error', reject);
    });
    
    // Remover arquivo temporário
    fs.unlinkSync(backupFile);
    
    logger.info('Backup restaurado com sucesso', { arquivo: req.file.originalname });
    
    return success(res, {
      restaurado: req.file.originalname,
      backup_seguranca: preRestoreBackup,
      restaurado_em: new Date().toISOString()
    }, 'Backup restaurado com sucesso. Reinicie o servidor para aplicar as alterações.');
  } catch (error) {
    logger.error('Erro ao restaurar backup:', error);
    throw error;
  }
}

/**
 * GET /api/backups
 * Lista backups disponíveis
 */
function listarBackups(req, res) {
  try {
    if (!fs.existsSync(config.backup.path)) {
      return success(res, []);
    }
    
    const files = fs.readdirSync(config.backup.path)
      .filter(f => f.endsWith('.zip'))
      .map(f => {
        const filePath = path.join(config.backup.path, f);
        const stats = fs.statSync(filePath);
        return {
          arquivo: f,
          tamanho_bytes: stats.size,
          tamanho_mb: (stats.size / (1024 * 1024)).toFixed(2),
          criado_em: stats.birthtime.toISOString()
        };
      })
      .sort((a, b) => new Date(b.criado_em) - new Date(a.criado_em));
    
    return success(res, files);
  } catch (error) {
    logger.error('Erro ao listar backups:', error);
    throw error;
  }
}

/**
 * DELETE /api/backups/:arquivo
 * Remove backup
 */
function removerBackup(req, res) {
  try {
    const { arquivo } = req.params;
    const filePath = path.join(config.backup.path, arquivo);
    
    if (!fs.existsSync(filePath)) {
      return validationError(res, [{ field: 'arquivo', issue: 'Backup não encontrado' }]);
    }
    
    fs.unlinkSync(filePath);
    
    logger.info('Backup removido', { arquivo });
    
    return success(res, null, 'Backup removido com sucesso');
  } catch (error) {
    logger.error('Erro ao remover backup:', error);
    throw error;
  }
}

/**
 * Limpa backups antigos (chamado pelo cron)
 */
function limparBackupsAntigos() {
  try {
    if (!fs.existsSync(config.backup.path)) return;
    
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - config.backup.retentionDays);
    
    const files = fs.readdirSync(config.backup.path)
      .filter(f => f.endsWith('.zip'));
    
    let removidos = 0;
    
    files.forEach(f => {
      const filePath = path.join(config.backup.path, f);
      const stats = fs.statSync(filePath);
      
      if (stats.birthtime < cutoffDate) {
        fs.unlinkSync(filePath);
        removidos++;
        logger.info('Backup antigo removido', { arquivo: f });
      }
    });
    
    if (removidos > 0) {
      logger.info(`${removidos} backup(s) antigo(s) removido(s)`);
    }
  } catch (error) {
    logger.error('Erro ao limpar backups antigos:', error);
  }
}

/**
 * Executa backup automático (chamado pelo cron)
 */
async function backupAutomatico() {
  try {
    logger.info('Iniciando backup automático...');
    
    // Fechar conexões
    db.closeAll();
    
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    const backupFileName = `auto_backup_${timestamp}.zip`;
    const backupPath = path.join(config.backup.path, backupFileName);
    
    if (!fs.existsSync(config.backup.path)) {
      fs.mkdirSync(config.backup.path, { recursive: true });
    }
    
    const output = fs.createWriteStream(backupPath);
    const archive = archiver('zip', { zlib: { level: 9 } });
    
    await new Promise((resolve, reject) => {
      output.on('close', resolve);
      output.on('error', reject);
      archive.pipe(output);
      
      const dataDir = path.resolve(process.cwd(), './data');
      
      if (fs.existsSync(path.join(dataDir, 'core.db'))) {
        archive.file(path.join(dataDir, 'core.db'), { name: 'data/core.db' });
      }
      if (fs.existsSync(path.join(dataDir, 'auth.db'))) {
        archive.file(path.join(dataDir, 'auth.db'), { name: 'data/auth.db' });
      }
      if (fs.existsSync(path.join(dataDir, 'audit.db'))) {
        archive.file(path.join(dataDir, 'audit.db'), { name: 'data/audit.db' });
      }
      
      const uploadsDir = path.join(dataDir, 'uploads');
      if (fs.existsSync(uploadsDir)) {
        archive.directory(uploadsDir, 'data/uploads');
      }
      
      archive.finalize();
    });
    
    const stats = fs.statSync(backupPath);
    logger.info('Backup automático concluído', { 
      arquivo: backupFileName, 
      tamanho: `${(stats.size / (1024 * 1024)).toFixed(2)} MB` 
    });
    
    // Limpar backups antigos
    limparBackupsAntigos();
  } catch (error) {
    logger.error('Erro no backup automático:', error);
  }
}

module.exports = {
  criarBackup,
  restaurarBackup,
  listarBackups,
  removerBackup,
  limparBackupsAntigos,
  backupAutomatico
};
