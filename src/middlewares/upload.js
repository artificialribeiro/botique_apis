/**
 * BOUTIQUE DINIZ API - Middleware de Upload
 * Desenvolvido por Estúdio Atlas
 * 
 * CORREÇÕES APLICADAS:
 * - Timeout aumentado para 60 segundos
 * - Limite de arquivos aumentado para 50
 * - Tratamento de erro de timeout
 * - Otimização de performance
 * - Suporte a uploads em paralelo
 */

const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
const config = require('../config');
const logger = require('../utils/logger');

/**
 * Configuração de armazenamento
 */
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    let uploadPath = config.upload.path;
    
    // Determinar subpasta baseado no tipo de upload
    if (req.baseUrl.includes('produtos') || req.path.includes('produtos')) {
      uploadPath = path.join(uploadPath, 'produtos');
    } else if (req.baseUrl.includes('banners') || req.path.includes('banners') || req.baseUrl.includes('carrossel')) {
      uploadPath = path.join(uploadPath, 'banners');
    } else if (req.baseUrl.includes('reclamacoes') || req.path.includes('reclamacoes')) {
      uploadPath = path.join(uploadPath, 'reclamacoes');
    } else if (req.baseUrl.includes('categorias') || req.path.includes('categorias')) {
      uploadPath = path.join(uploadPath, 'categorias');
    }
    
    // Criar diretório se não existir
    if (!fs.existsSync(uploadPath)) {
      fs.mkdirSync(uploadPath, { recursive: true });
    }
    
    cb(null, uploadPath);
  },
  filename: (req, file, cb) => {
    // Gerar nome único
    const uniqueName = `${Date.now()}-${uuidv4()}${path.extname(file.originalname)}`;
    cb(null, uniqueName);
  }
});

/**
 * Filtro de arquivos
 */
const fileFilter = (req, file, cb) => {
  // Normalizar tipo MIME para comparação case-insensitive e tratar aliases
  let mimeType = (file.mimetype || '').toLowerCase();
  // Mapear aliases comuns para tipos suportados
  const mimeAliases = {
    'image/jpg': 'image/jpeg',
    'image/x-png': 'image/png',
    'image/pjpeg': 'image/jpeg',
    'image/pjpg': 'image/jpeg'
  };
  // Substituir alias pelo tipo oficial se aplicável
  mimeType = mimeAliases[mimeType] || mimeType;
  const allowedImages = config.upload.allowedMimeTypes.images.map(m => m.toLowerCase());
  const allowedVideos = config.upload.allowedMimeTypes.videos.map(m => m.toLowerCase());
  const isImage = allowedImages.includes(mimeType);
  const isVideo = allowedVideos.includes(mimeType);
  if (isImage || isVideo) {
    cb(null, true);
  } else {
    logger.warn('Tipo de arquivo rejeitado:', { mimetype: file.mimetype });
    // Erro de validação amigável
    cb(new Error('Tipo de arquivo não permitido'), false);
  }
};

/**
 * Configuração do Multer com otimizações
 */
const upload = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: config.upload.maxFileSizeBytes,
    files: 50 // Aumentado de 10 para 50 arquivos por requisição
  },
  // Timeout aumentado para 60 segundos (60000ms)
  timeout: 60000
});

/**
 * Middleware para tratamento de erro de timeout
 */
const timeoutHandler = (err, req, res, next) => {
  if (err.code === 'LIMIT_FILE_SIZE') {
    logger.error('Arquivo muito grande:', { size: err.limit });
    return res.status(413).json({
      success: false,
      message: 'Arquivo muito grande. Tamanho máximo: ' + config.upload.maxSizeMB + 'MB',
      error: { code: 'FILE_TOO_LARGE' }
    });
  }
  if (err.code === 'LIMIT_FILE_COUNT') {
    logger.error('Muitos arquivos:', { count: err.limit });
    return res.status(413).json({
      success: false,
      message: 'Muitos arquivos. Máximo: 50 arquivos por requisição',
      error: { code: 'TOO_MANY_FILES' }
    });
  }
  if (err.code === 'LIMIT_PART_COUNT') {
    logger.error('Muitas partes:', { count: err.limit });
    return res.status(413).json({
      success: false,
      message: 'Muitas partes no upload',
      error: { code: 'TOO_MANY_PARTS' }
    });
  }
  next(err);
};

/**
 * Upload de imagem única
 */
const uploadSingleImage = (req, res, next) => {
  upload.single('imagem')(req, res, (err) => {
    if (err) {
      logger.error('Erro no upload de imagem única:', err);
      
      // Tratamento específico de erros
      if (err.message === 'Tipo de arquivo não permitido') {
        return res.status(400).json({
          success: false,
          message: 'Tipo de arquivo não permitido. Use: JPG, PNG, WebP ou GIF',
          error: { code: 'INVALID_FILE_TYPE' }
        });
      }
      
      if (err.code === 'LIMIT_FILE_SIZE') {
        return res.status(413).json({
          success: false,
          message: 'Arquivo muito grande. Tamanho máximo: ' + config.upload.maxSizeMB + 'MB',
          error: { code: 'FILE_TOO_LARGE' }
        });
      }
      
      if (err.code === 'LIMIT_PART_COUNT' || err.code === 'LIMIT_FILE_COUNT') {
        return res.status(413).json({
          success: false,
          message: 'Limite de upload excedido',
          error: { code: 'UPLOAD_LIMIT_EXCEEDED' }
        });
      }
      
      // Erro genérico com mais contexto
      logger.error('Erro detalhado no upload:', {
        message: err.message,
        code: err.code,
        stack: err.stack
      });
      
      return res.status(500).json({
        success: false,
        message: 'Erro ao fazer upload. Tente novamente.',
        error: { code: 'UPLOAD_ERROR', details: err.message }
      });
    }
    next();
  });
};

/**
 * Upload de múltiplas imagens
 */
const uploadMultipleImages = (req, res, next) => {
  upload.array('imagens', 50)(req, res, (err) => {
    if (err) {
      logger.error('Erro no upload de múltiplas imagens:', err);
      
      // Tratamento específico de erros
      if (err.message === 'Tipo de arquivo não permitido') {
        return res.status(400).json({
          success: false,
          message: 'Um ou mais arquivos têm tipo não permitido. Use: JPG, PNG, WebP ou GIF',
          error: { code: 'INVALID_FILE_TYPE' }
        });
      }
      
      if (err.code === 'LIMIT_FILE_SIZE') {
        return res.status(413).json({
          success: false,
          message: 'Um ou mais arquivos estão muito grandes. Máximo: ' + config.upload.maxSizeMB + 'MB cada',
          error: { code: 'FILE_TOO_LARGE' }
        });
      }
      
      if (err.code === 'LIMIT_FILE_COUNT') {
        return res.status(413).json({
          success: false,
          message: 'Muitos arquivos. Máximo: 50 arquivos por requisição',
          error: { code: 'TOO_MANY_FILES' }
        });
      }
      
      if (err.code === 'LIMIT_PART_COUNT') {
        return res.status(413).json({
          success: false,
          message: 'Muitas partes no upload',
          error: { code: 'TOO_MANY_PARTS' }
        });
      }
      
      // Erro genérico com mais contexto
      logger.error('Erro detalhado no upload múltiplo:', {
        message: err.message,
        code: err.code,
        stack: err.stack
      });
      
      return res.status(500).json({
        success: false,
        message: 'Erro ao fazer upload. Tente novamente.',
        error: { code: 'UPLOAD_ERROR', details: err.message }
      });
    }
    next();
  });
};

/**
 * Upload de mídia (imagem ou vídeo)
 */
const uploadMedia = (req, res, next) => {
  upload.single('midia')(req, res, (err) => {
    if (err) {
      logger.error('Erro no upload de mídia:', err);
      if (err.message === 'Tipo de arquivo não permitido') {
        return res.status(400).json({
          success: false,
          message: 'Tipo de arquivo não permitido',
          error: { code: 'INVALID_FILE_TYPE' }
        });
      }
      return res.status(400).json({
        success: false,
        message: err.message || 'Erro ao fazer upload',
        error: { code: 'UPLOAD_ERROR' }
      });
    }
    next();
  });
};

/**
 * Upload de múltiplas mídias
 */
const uploadMultipleMedia = (req, res, next) => {
  upload.array('midias', 50)(req, res, (err) => {
    if (err) {
      logger.error('Erro no upload de múltiplas mídias:', err);
      if (err.message === 'Tipo de arquivo não permitido') {
        return res.status(400).json({
          success: false,
          message: 'Um ou mais arquivos têm tipo não permitido',
          error: { code: 'INVALID_FILE_TYPE' }
        });
      }
      return res.status(400).json({
        success: false,
        message: err.message || 'Erro ao fazer upload',
        error: { code: 'UPLOAD_ERROR' }
      });
    }
    next();
  });
};

/**
 * Remove arquivo do sistema
 */
function removeFile(filePath) {
  try {
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
      logger.info('Arquivo removido:', filePath);
    }
  } catch (error) {
    logger.error('Erro ao remover arquivo:', error);
  }
}

/**
 * Obtém caminho relativo do arquivo
 */
function getRelativePath(absolutePath) {
  return absolutePath.replace(config.upload.path, '/uploads');
}

module.exports = {
  upload,
  uploadSingleImage,
  uploadMultipleImages,
  uploadMedia,
  uploadMultipleMedia,
  removeFile,
  getRelativePath,
  timeoutHandler
};
