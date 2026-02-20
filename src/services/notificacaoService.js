/**
 * BOUTIQUE DINIZ API - Serviço de Notificações
 * Desenvolvido por Estúdio Atlas
 * 
 * Serviço de notificações por email integrado com Google Apps Script
 * Suporta: Login, Recuperação de Senha, Atualizações de Pedidos, Promoções
 */

const nodemailer = require('nodemailer');
const axios = require('axios');
const config = require('../config');
const logger = require('../utils/logger');

/**
 * Configuração do transporte de email
 */
let transporter = null;

function initializeTransporter() {
  if (transporter) return transporter;

  // Captura configurações de SMTP do arquivo .env/config.
  // Algumas instalações podem não definir usuário e senha SMTP.
  // Neste caso, criamos um transport sem autenticação para evitar falhas.
  const { host, port, secure, user, pass } = config.smtp;
  const transportOptions = { host, port, secure };

  // Adiciona autenticação apenas se usuário e senha forem fornecidos.
  if (user && pass) {
    transportOptions.auth = { user, pass };
  }

  transporter = nodemailer.createTransport(transportOptions);

  return transporter;
}

/**
 * Envia notificação via Google Apps Script
 * URL: https://script.google.com/macros/s/AKfycbxmWQYuR6oxsj7fD1yeUQ0UIdw8_nC_GrAF-ZxKuy5kxSFsJvsBXbW-N8kvT8Q2MGCk/exec
 */
async function enviarViaGoogleAppsScript(email, dados) {
  try {
    // Permite configurar a URL via arquivo .env. Se não definido, utiliza
    // a URL padrão fornecida pelo Estúdio Atlas. Esta abordagem evita
    // acoplamento rígido e permite que o administrador atualize o script
    // sem recompilar a aplicação.
    const GOOGLE_APPS_SCRIPT_URL = config.googleAppsScript?.url ||
      'https://script.google.com/macros/s/AKfycbxmWQYuR6oxsj7fD1yeUQ0UIdw8_nC_GrAF-ZxKuy5kxSFsJvsBXbW-N8kvT8Q2MGCk/exec';
    
    const params = new URLSearchParams({
      email: email,
      dados: JSON.stringify({
        ...dados,
        marca: 'Boutique Diniz',
        origem: 'Atlas Soluções',
        timestamp: new Date().toLocaleString('pt-BR')
      })
    });
    
    const response = await axios.get(`${GOOGLE_APPS_SCRIPT_URL}?${params.toString()}`, {
      timeout: 10000
    });
    
    if (response.data.status === 'success') {
      logger.info('Notificação enviada via Google Apps Script', { email, tipo: dados.tipo });
      return { sucesso: true, resposta: response.data };
    } else {
      logger.warn('Erro ao enviar notificação via Google Apps Script', { email, erro: response.data.mensagem });
      return { sucesso: false, erro: response.data.mensagem };
    }
  } catch (error) {
    logger.error('Erro ao enviar notificação via Google Apps Script', { email, erro: error.message });
    return { sucesso: false, erro: error.message };
  }
}

/**
 * Envia notificação de login
 */
async function notificarLogin(cliente) {
  try {
    if (!cliente.email) {
      logger.warn('Email do cliente não configurado para notificação de login', { clienteId: cliente.id });
      return;
    }
    
    const dados = {
      tipo: 'login',
      assunto: '🔐 Acesso à sua conta - Boutique Diniz',
      nome: cliente.nome_completo,
      cpf: cliente.cpf,
      timestamp: new Date().toLocaleString('pt-BR'),
      ip: cliente.ip || 'N/A',
      navegador: cliente.navegador || 'N/A'
    };
    
    // Enviar via Google Apps Script
    await enviarViaGoogleAppsScript(cliente.email, dados);
    
    // Também enviar via email direto (fallback)
    await enviarEmailLogin(cliente, dados);
    
    logger.info('Notificação de login enviada', { clienteId: cliente.id, email: cliente.email });
  } catch (error) {
    logger.error('Erro ao notificar login', { clienteId: cliente.id, erro: error.message });
  }
}

/**
 * Envia notificação de boas-vindas (NOVO)
 */
async function notificarBoasVindas(cliente) {
  try {
    if (!cliente.email) {
      logger.warn('Email do cliente não configurado para boas-vindas', { clienteId: cliente.id });
      return;
    }
    
    const dados = {
      tipo: 'boas_vindas',
      assunto: '🎉 Bem-vindo(a) à Boutique Diniz!',
      nome: cliente.nome_completo,
      cpf: cliente.cpf,
      timestamp: new Date().toLocaleString('pt-BR')
    };
    
    // Enviar via Google Apps Script
    await enviarViaGoogleAppsScript(cliente.email, dados);
    
    // Também enviar via email direto (fallback)
    await enviarEmailBoasVindas(cliente);
    
    logger.info('Email de boas-vindas enviado', { clienteId: cliente.id, email: cliente.email });
  } catch (error) {
    logger.error('Erro ao enviar boas-vindas', { clienteId: cliente.id, erro: error.message });
  }
}

/**
 * Envia notificação de senha redefinida (NOVO)
 */
async function notificarSenhaRedefinida(cliente) {
  try {
    if (!cliente.email) {
      logger.warn('Email do cliente não configurado para senha redefinida', { clienteId: cliente.id });
      return;
    }
    
    const dados = {
      tipo: 'senha_redefinida',
      assunto: '✅ Senha redefinida com sucesso - Boutique Diniz',
      nome: cliente.nome_completo,
      timestamp: new Date().toLocaleString('pt-BR'),
      ip: cliente.ip || 'N/A',
      navegador: cliente.navegador || 'N/A'
    };
    
    // Enviar via Google Apps Script
    await enviarViaGoogleAppsScript(cliente.email, dados);
    
    // Também enviar via email direto (fallback)
    await enviarEmailSenhaRedefinida(cliente);
    
    logger.info('Email de senha redefinida enviado', { clienteId: cliente.id, email: cliente.email });
  } catch (error) {
    logger.error('Erro ao enviar notificação de senha redefinida', { clienteId: cliente.id, erro: error.message });
  }
}

/**
 * Envia notificação de recuperação de senha
 */
async function notificarRecuperacaoSenha(cliente, codigo) {
  try {
    if (!cliente.email) {
      logger.warn('Email do cliente não configurado para notificação de recuperação de senha', { clienteId: cliente.id });
      return;
    }
    
    const dados = {
      tipo: 'recuperacao_senha',
      assunto: '🔑 Código de recuperação de senha - Boutique Diniz',
      nome: cliente.nome_completo,
      cpf: cliente.cpf,
      codigo: codigo,
      validade: '30 minutos',
      timestamp: new Date().toLocaleString('pt-BR')
    };
    
    // Enviar via Google Apps Script
    await enviarViaGoogleAppsScript(cliente.email, dados);
    
    // Também enviar via email direto (fallback)
    await enviarEmailRecuperacaoSenha(cliente, codigo);
    
    logger.info('Notificação de recuperação de senha enviada', { clienteId: cliente.id, email: cliente.email });
  } catch (error) {
    logger.error('Erro ao notificar recuperação de senha', { clienteId: cliente.id, erro: error.message });
  }
}

/**
 * Envia notificação de atualização de pedido
 */
async function notificarAtualizacaoPedido(cliente, pedido, statusAnterior, statusNovo) {
  try {
    if (!cliente.email) {
      logger.warn('Email do cliente não configurado para notificação de pedido', { clienteId: cliente.id });
      return;
    }
    
    const statusMensagens = {
      'pendente': 'Seu pedido está pendente de confirmação',
      'confirmado': 'Seu pedido foi confirmado! 🎉',
      'processando': 'Seu pedido está sendo processado',
      'enviado': 'Seu pedido foi enviado! 📦',
      'entregue': 'Seu pedido foi entregue! ✅',
      'cancelado': 'Seu pedido foi cancelado',
      'devolvido': 'Seu pedido foi devolvido'
    };
    
    const dados = {
      tipo: 'atualizacao_pedido',
      assunto: `📦 Atualização do seu pedido #${pedido.numero_pedido}`,
      nome: cliente.nome_completo,
      numeroPedido: pedido.numero_pedido,
      statusAnterior: statusAnterior,
      statusNovo: statusNovo,
      mensagem: statusMensagens[statusNovo] || 'Seu pedido foi atualizado',
      dataAtualizacao: new Date().toLocaleString('pt-BR'),
      rastreio: pedido.rastreio || 'Não disponível',
      valor: pedido.valor_total
    };
    
    // Enviar via Google Apps Script
    await enviarViaGoogleAppsScript(cliente.email, dados);
    
    // Também enviar via email direto (fallback)
    await enviarEmailAtualizacaoPedido(cliente, pedido, statusNovo);
    
    logger.info('Notificação de atualização de pedido enviada', { clienteId: cliente.id, pedidoId: pedido.id });
  } catch (error) {
    logger.error('Erro ao notificar atualização de pedido', { clienteId: cliente.id, erro: error.message });
  }
}

/**
 * Envia notificação de promoção/desconto
 */
async function notificarPromocao(cliente, promocao) {
  try {
    if (!cliente.email) {
      logger.warn('Email do cliente não configurado para notificação de promoção', { clienteId: cliente.id });
      return;
    }
    
    const dados = {
      tipo: 'promocao',
      assunto: `🎉 Promoção especial para você! ${promocao.titulo}`,
      nome: cliente.nome_completo,
      titulo: promocao.titulo,
      descricao: promocao.descricao,
      desconto: promocao.desconto,
      codigoCupom: promocao.codigo_cupom,
      dataInicio: promocao.data_inicio,
      dataFim: promocao.data_fim,
      timestamp: new Date().toLocaleString('pt-BR')
    };
    
    // Enviar via Google Apps Script
    await enviarViaGoogleAppsScript(cliente.email, dados);
    
    // Também enviar via email direto (fallback)
    await enviarEmailPromocao(cliente, promocao);
    
    logger.info('Notificação de promoção enviada', { clienteId: cliente.id, promocaoId: promocao.id });
  } catch (error) {
    logger.error('Erro ao notificar promoção', { clienteId: cliente.id, erro: error.message });
  }
}

/**
 * Envia notificação de atualização de dados cadastrais
 */
async function notificarAtualizacaoDados(cliente, dadosAlterados) {
  try {
    if (!cliente.email) {
      logger.warn('Email do cliente não configurado para notificação de dados', { clienteId: cliente.id });
      return;
    }
    
    const dados = {
      tipo: 'atualizacao_dados',
      assunto: '📝 Seus dados cadastrais foram atualizados',
      nome: cliente.nome_completo,
      dadosAlterados: dadosAlterados,
      timestamp: new Date().toLocaleString('pt-BR')
    };
    
    // Enviar via Google Apps Script
    await enviarViaGoogleAppsScript(cliente.email, dados);
    
    // Também enviar via email direto (fallback)
    await enviarEmailAtualizacaoDados(cliente, dadosAlterados);
    
    logger.info('Notificação de atualização de dados enviada', { clienteId: cliente.id });
  } catch (error) {
    logger.error('Erro ao notificar atualização de dados', { clienteId: cliente.id, erro: error.message });
  }
}

/**
 * Envia email de login (fallback)
 */
async function enviarEmailLogin(cliente, dados) {
  try {
    const transporter = initializeTransporter();
    
    const htmlContent = `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <style>
          body { font-family: Arial, sans-serif; background-color: #f5f5f5; }
          .container { max-width: 600px; margin: 0 auto; background-color: white; padding: 20px; border-radius: 8px; }
          .header { text-align: center; border-bottom: 2px solid #4a86e8; padding-bottom: 20px; }
          .logo { font-size: 24px; font-weight: bold; color: #4a86e8; }
          .content { padding: 20px 0; }
          .info { background-color: #f0f4ff; padding: 15px; border-radius: 4px; margin: 10px 0; }
          .footer { text-align: center; color: #666; font-size: 12px; border-top: 1px solid #ddd; padding-top: 20px; margin-top: 20px; }
          .brand { color: #4a86e8; font-weight: bold; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <div class="logo">🛍️ Boutique Diniz</div>
            <p>Notificação de Acesso</p>
          </div>
          
          <div class="content">
            <h2>Olá, ${dados.nome}!</h2>
            <p>Detectamos um acesso à sua conta.</p>
            
            <div class="info">
              <p><strong>Data/Hora:</strong> ${dados.timestamp}</p>
              <p><strong>IP:</strong> ${dados.ip}</p>
              <p><strong>Navegador:</strong> ${dados.navegador}</p>
            </div>
            
            <p>Se você não realizou este acesso, altere sua senha imediatamente.</p>
          </div>
          
          <div class="footer">
            <p>Desenvolvido por <span class="brand">Atlas Soluções</span></p>
            <p>© 2026 Boutique Diniz. Todos os direitos reservados.</p>
          </div>
        </div>
      </body>
      </html>
    `;
    
    await transporter.sendMail({
      from: config.smtp.from,
      to: cliente.email,
      subject: dados.assunto,
      html: htmlContent
    });
    
    logger.info('Email de login enviado', { clienteId: cliente.id });
  } catch (error) {
    logger.error('Erro ao enviar email de login', { clienteId: cliente.id, erro: error.message });
  }
}

/**
 * Envia email de recuperação de senha (fallback)
 */
async function enviarEmailRecuperacaoSenha(cliente, codigo) {
  try {
    const transporter = initializeTransporter();
    
    const htmlContent = `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <style>
          body { font-family: Arial, sans-serif; background-color: #f5f5f5; }
          .container { max-width: 600px; margin: 0 auto; background-color: white; padding: 20px; border-radius: 8px; }
          .header { text-align: center; border-bottom: 2px solid #4a86e8; padding-bottom: 20px; }
          .logo { font-size: 24px; font-weight: bold; color: #4a86e8; }
          .content { padding: 20px 0; }
          .code-box { background-color: #f0f4ff; padding: 20px; border-radius: 4px; text-align: center; margin: 20px 0; }
          .code { font-size: 32px; font-weight: bold; color: #4a86e8; letter-spacing: 2px; }
          .footer { text-align: center; color: #666; font-size: 12px; border-top: 1px solid #ddd; padding-top: 20px; margin-top: 20px; }
          .brand { color: #4a86e8; font-weight: bold; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <div class="logo">🛍️ Boutique Diniz</div>
            <p>Recuperação de Senha</p>
          </div>
          
          <div class="content">
            <h2>Olá, ${cliente.nome_completo}!</h2>
            <p>Recebemos uma solicitação para recuperar sua senha. Use o código abaixo:</p>
            
            <div class="code-box">
              <div class="code">${codigo}</div>
              <p>Válido por 30 minutos</p>
            </div>
            
            <p>Se você não solicitou esta recuperação, ignore este email.</p>
          </div>
          
          <div class="footer">
            <p>Desenvolvido por <span class="brand">Atlas Soluções</span></p>
            <p>© 2026 Boutique Diniz. Todos os direitos reservados.</p>
          </div>
        </div>
      </body>
      </html>
    `;
    
    await transporter.sendMail({
      from: config.smtp.from,
      to: cliente.email,
      subject: '🔑 Código de recuperação de senha - Boutique Diniz',
      html: htmlContent
    });
    
    logger.info('Email de recuperação de senha enviado', { clienteId: cliente.id });
  } catch (error) {
    logger.error('Erro ao enviar email de recuperação de senha', { clienteId: cliente.id, erro: error.message });
  }
}

/**
 * Envia email de atualização de pedido (fallback)
 */
async function enviarEmailAtualizacaoPedido(cliente, pedido, statusNovo) {
  try {
    const transporter = initializeTransporter();
    
    const statusEmojis = {
      'pendente': '⏳',
      'confirmado': '✅',
      'processando': '⚙️',
      'enviado': '📦',
      'entregue': '🎉',
      'cancelado': '❌',
      'devolvido': '↩️'
    };
    
    const htmlContent = `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <style>
          body { font-family: Arial, sans-serif; background-color: #f5f5f5; }
          .container { max-width: 600px; margin: 0 auto; background-color: white; padding: 20px; border-radius: 8px; }
          .header { text-align: center; border-bottom: 2px solid #4a86e8; padding-bottom: 20px; }
          .logo { font-size: 24px; font-weight: bold; color: #4a86e8; }
          .content { padding: 20px 0; }
          .status-box { background-color: #f0f4ff; padding: 20px; border-radius: 4px; margin: 20px 0; }
          .status { font-size: 24px; font-weight: bold; color: #4a86e8; }
          .info-table { width: 100%; border-collapse: collapse; margin: 20px 0; }
          .info-table td { padding: 10px; border-bottom: 1px solid #ddd; }
          .info-table .label { font-weight: bold; width: 30%; }
          .footer { text-align: center; color: #666; font-size: 12px; border-top: 1px solid #ddd; padding-top: 20px; margin-top: 20px; }
          .brand { color: #4a86e8; font-weight: bold; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <div class="logo">🛍️ Boutique Diniz</div>
            <p>Atualização do Pedido</p>
          </div>
          
          <div class="content">
            <h2>Olá, ${cliente.nome_completo}!</h2>
            <p>Seu pedido foi atualizado!</p>
            
            <div class="status-box">
              <div class="status">${statusEmojis[statusNovo] || '📦'} ${statusNovo.toUpperCase()}</div>
            </div>
            
            <table class="info-table">
              <tr>
                <td class="label">Número do Pedido:</td>
                <td>#${pedido.numero_pedido}</td>
              </tr>
              <tr>
                <td class="label">Valor:</td>
                <td>R$ ${parseFloat(pedido.valor_total).toFixed(2)}</td>
              </tr>
              <tr>
                <td class="label">Rastreio:</td>
                <td>${pedido.rastreio || 'Não disponível'}</td>
              </tr>
            </table>
          </div>
          
          <div class="footer">
            <p>Desenvolvido por <span class="brand">Atlas Soluções</span></p>
            <p>© 2026 Boutique Diniz. Todos os direitos reservados.</p>
          </div>
        </div>
      </body>
      </html>
    `;
    
    await transporter.sendMail({
      from: config.smtp.from,
      to: cliente.email,
      subject: `📦 Atualização do seu pedido #${pedido.numero_pedido}`,
      html: htmlContent
    });
    
    logger.info('Email de atualização de pedido enviado', { clienteId: cliente.id });
  } catch (error) {
    logger.error('Erro ao enviar email de atualização de pedido', { clienteId: cliente.id, erro: error.message });
  }
}

/**
 * Envia email de promoção (fallback)
 */
async function enviarEmailPromocao(cliente, promocao) {
  try {
    const transporter = initializeTransporter();
    
    const htmlContent = `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <style>
          body { font-family: Arial, sans-serif; background-color: #f5f5f5; }
          .container { max-width: 600px; margin: 0 auto; background-color: white; padding: 20px; border-radius: 8px; }
          .header { text-align: center; border-bottom: 2px solid #4a86e8; padding-bottom: 20px; }
          .logo { font-size: 24px; font-weight: bold; color: #4a86e8; }
          .content { padding: 20px 0; }
          .promo-box { background: linear-gradient(135deg, #4a86e8, #357abd); color: white; padding: 30px; border-radius: 8px; text-align: center; margin: 20px 0; }
          .promo-title { font-size: 28px; font-weight: bold; margin-bottom: 10px; }
          .promo-desc { font-size: 16px; margin-bottom: 20px; }
          .coupon { background-color: white; color: #4a86e8; padding: 15px; border-radius: 4px; font-weight: bold; font-size: 18px; letter-spacing: 2px; }
          .footer { text-align: center; color: #666; font-size: 12px; border-top: 1px solid #ddd; padding-top: 20px; margin-top: 20px; }
          .brand { color: #4a86e8; font-weight: bold; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <div class="logo">🛍️ Boutique Diniz</div>
            <p>Promoção Especial</p>
          </div>
          
          <div class="content">
            <h2>Olá, ${cliente.nome_completo}!</h2>
            <p>Temos uma promoção especial para você!</p>
            
            <div class="promo-box">
              <div class="promo-title">🎉 ${promocao.titulo}</div>
              <div class="promo-desc">${promocao.descricao}</div>
              <div class="promo-desc"><strong>${promocao.desconto}</strong> de desconto</div>
              <div class="coupon">${promocao.codigo_cupom}</div>
            </div>
            
            <p><strong>Válido até:</strong> ${new Date(promocao.data_fim).toLocaleDateString('pt-BR')}</p>
          </div>
          
          <div class="footer">
            <p>Desenvolvido por <span class="brand">Atlas Soluções</span></p>
            <p>© 2026 Boutique Diniz. Todos os direitos reservados.</p>
          </div>
        </div>
      </body>
      </html>
    `;
    
    await transporter.sendMail({
      from: config.smtp.from,
      to: cliente.email,
      subject: `🎉 Promoção especial para você! ${promocao.titulo}`,
      html: htmlContent
    });
    
    logger.info('Email de promoção enviado', { clienteId: cliente.id });
  } catch (error) {
    logger.error('Erro ao enviar email de promoção', { clienteId: cliente.id, erro: error.message });
  }
}

/**
 * Envia email de atualização de dados (fallback)
 */
async function enviarEmailAtualizacaoDados(cliente, dadosAlterados) {
  try {
    const transporter = initializeTransporter();
    
    const dadosFormatados = Object.entries(dadosAlterados)
      .map(([chave, valor]) => `<tr><td class="label">${chave}:</td><td>${valor}</td></tr>`)
      .join('');
    
    const htmlContent = `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <style>
          body { font-family: Arial, sans-serif; background-color: #f5f5f5; }
          .container { max-width: 600px; margin: 0 auto; background-color: white; padding: 20px; border-radius: 8px; }
          .header { text-align: center; border-bottom: 2px solid #4a86e8; padding-bottom: 20px; }
          .logo { font-size: 24px; font-weight: bold; color: #4a86e8; }
          .content { padding: 20px 0; }
          .info-table { width: 100%; border-collapse: collapse; margin: 20px 0; }
          .info-table td { padding: 10px; border-bottom: 1px solid #ddd; }
          .info-table .label { font-weight: bold; width: 30%; }
          .footer { text-align: center; color: #666; font-size: 12px; border-top: 1px solid #ddd; padding-top: 20px; margin-top: 20px; }
          .brand { color: #4a86e8; font-weight: bold; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <div class="logo">🛍️ Boutique Diniz</div>
            <p>Atualização de Dados</p>
          </div>
          
          <div class="content">
            <h2>Olá, ${cliente.nome_completo}!</h2>
            <p>Seus dados cadastrais foram atualizados:</p>
            
            <table class="info-table">
              ${dadosFormatados}
            </table>
            
            <p>Se você não realizou esta alteração, entre em contato conosco imediatamente.</p>
          </div>
          
          <div class="footer">
            <p>Desenvolvido por <span class="brand">Atlas Soluções</span></p>
            <p>© 2026 Boutique Diniz. Todos os direitos reservados.</p>
          </div>
        </div>
      </body>
      </html>
    `;
    
    await transporter.sendMail({
      from: config.smtp.from,
      to: cliente.email,
      subject: '📝 Seus dados cadastrais foram atualizados',
      html: htmlContent
    });
    
    logger.info('Email de atualização de dados enviado', { clienteId: cliente.id });
  } catch (error) {
    logger.error('Erro ao enviar email de atualização de dados', { clienteId: cliente.id, erro: error.message });
  }
}

/**
 * Envia email de boas-vindas (NOVO - fallback)
 */
async function enviarEmailBoasVindas(cliente) {
  try {
    const transporter = initializeTransporter();
    
    const htmlContent = `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <style>
          body { font-family: Arial, sans-serif; background-color: #f5f5f5; margin: 0; padding: 0; }
          .container { max-width: 600px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 8px; }
          .header { text-align: center; border-bottom: 3px solid #4a86e8; padding-bottom: 20px; margin-bottom: 30px; }
          .logo { font-size: 32px; font-weight: bold; color: #4a86e8; margin-bottom: 10px; }
          .subtitle { font-size: 18px; color: #666; }
          .content { padding: 20px 0; line-height: 1.6; color: #333; }
          .welcome-box { background: linear-gradient(135deg, #4a86e8, #357abd); color: white; padding: 30px; border-radius: 8px; text-align: center; margin: 30px 0; }
          .welcome-title { font-size: 28px; font-weight: bold; margin-bottom: 15px; }
          .welcome-text { font-size: 16px; line-height: 1.8; }
          .features { margin: 30px 0; }
          .feature { display: block; margin-bottom: 20px; padding: 15px; background-color: #f8f9fa; border-radius: 6px; }
          .feature-icon { font-size: 24px; margin-right: 15px; }
          .feature-title { font-weight: bold; color: #4a86e8; margin-bottom: 5px; }
          .footer { text-align: center; color: #666; font-size: 12px; border-top: 1px solid #ddd; padding-top: 20px; margin-top: 30px; }
          .brand { color: #4a86e8; font-weight: bold; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <div class="logo">🛍️ Boutique Diniz</div>
            <div class="subtitle">Moda e Elegância</div>
          </div>
          
          <div class="content">
            <div class="welcome-box">
              <div class="welcome-title">🎉 Bem-vindo(a)!</div>
              <div class="welcome-text">
                Olá ${cliente.nome_completo},<br>
                Estamos muito felizes em ter você conosco!<br>
                Sua conta foi criada com sucesso.
              </div>
            </div>
            
            <h3 style="color: #4a86e8;">O que você pode fazer agora:</h3>
            
            <div class="features">
              <div class="feature">
                <span class="feature-icon">🛍️</span>
                <div class="feature-title">Explore nosso catálogo</div>
                <div>Descubra as últimas tendências da moda e peças exclusivas.</div>
              </div>
              
              <div class="feature">
                <span class="feature-icon">❤️</span>
                <div class="feature-title">Crie sua lista de favoritos</div>
                <div>Salve os produtos que você mais gosta.</div>
              </div>
              
              <div class="feature">
                <span class="feature-icon">🎁</span>
                <div class="feature-title">Aproveite ofertas exclusivas</div>
                <div>Fique por dentro de promoções especiais.</div>
              </div>
              
              <div class="feature">
                <span class="feature-icon">📦</span>
                <div class="feature-title">Acompanhe seus pedidos</div>
                <div>Receba atualizações em tempo real.</div>
              </div>
            </div>
            
            <p style="text-align: center; margin-top: 30px;">
              <strong>Seus dados de acesso:</strong><br>
              CPF: ${cliente.cpf}
            </p>
          </div>
          
          <div class="footer">
            <p><strong>Boutique Diniz</strong> - Moda e Elegância</p>
            <p>Desenvolvido por <span class="brand">Atlas Soluções</span></p>
            <p>© 2026 Boutique Diniz. Todos os direitos reservados.</p>
          </div>
        </div>
      </body>
      </html>
    `;
    
    await transporter.sendMail({
      from: config.smtp.from,
      to: cliente.email,
      subject: '🎉 Bem-vindo(a) à Boutique Diniz!',
      html: htmlContent
    });
    
    logger.info('Email de boas-vindas enviado', { clienteId: cliente.id });
  } catch (error) {
    logger.error('Erro ao enviar email de boas-vindas', { clienteId: cliente.id, erro: error.message });
  }
}

/**
 * Envia email de senha redefinida (NOVO - fallback)
 */
async function enviarEmailSenhaRedefinida(cliente) {
  try {
    const transporter = initializeTransporter();
    
    const htmlContent = `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <style>
          body { font-family: Arial, sans-serif; background-color: #f5f5f5; margin: 0; padding: 0; }
          .container { max-width: 600px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 8px; }
          .header { text-align: center; border-bottom: 3px solid #28a745; padding-bottom: 20px; margin-bottom: 30px; }
          .logo { font-size: 32px; font-weight: bold; color: #4a86e8; margin-bottom: 10px; }
          .content { padding: 20px 0; line-height: 1.6; color: #333; }
          .success-box { background: linear-gradient(135deg, #28a745, #20c997); color: white; padding: 30px; border-radius: 8px; text-align: center; margin: 30px 0; }
          .success-icon { font-size: 48px; margin-bottom: 15px; }
          .success-title { font-size: 24px; font-weight: bold; margin-bottom: 10px; }
          .success-text { font-size: 16px; }
          .info-box { background-color: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 20px 0; border-radius: 4px; }
          .info-title { font-weight: bold; color: #856404; margin-bottom: 5px; }
          .info-text { color: #856404; font-size: 14px; }
          .security-tips { margin: 30px 0; padding: 20px; background-color: #f8f9fa; border-radius: 8px; }
          .security-tips h4 { color: #4a86e8; margin-top: 0; }
          .security-tips ul { padding-left: 20px; }
          .security-tips li { margin-bottom: 10px; color: #666; }
          .details-table { width: 100%; border-collapse: collapse; margin: 20px 0; }
          .details-table td { padding: 10px; border-bottom: 1px solid #ddd; }
          .details-table .label { font-weight: bold; width: 30%; }
          .footer { text-align: center; color: #666; font-size: 12px; border-top: 1px solid #ddd; padding-top: 20px; margin-top: 30px; }
          .brand { color: #4a86e8; font-weight: bold; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <div class="logo">🛍️ Boutique Diniz</div>
          </div>
          
          <div class="content">
            <div class="success-box">
              <div class="success-icon">✅</div>
              <div class="success-title">Senha Redefinida com Sucesso!</div>
              <div class="success-text">Sua senha foi alterada com segurança</div>
            </div>
            
            <h2>Olá, ${cliente.nome_completo}!</h2>
            <p>Sua senha foi redefinida com sucesso. Agora você já pode fazer login com sua nova senha.</p>
            
            <div class="info-box">
              <div class="info-title">⚠️ Não foi você?</div>
              <div class="info-text">
                Se você não solicitou esta alteração, entre em contato conosco imediatamente.
              </div>
            </div>
            
            <h3>Detalhes da alteração:</h3>
            <table class="details-table">
              <tr>
                <td class="label">Data e Hora:</td>
                <td>${new Date().toLocaleString('pt-BR')}</td>
              </tr>
              <tr>
                <td class="label">IP:</td>
                <td>${cliente.ip || 'N/A'}</td>
              </tr>
              <tr>
                <td class="label">Navegador:</td>
                <td>${cliente.navegador || 'N/A'}</td>
              </tr>
            </table>
            
            <div class="security-tips">
              <h4>🔐 Dicas de Segurança</h4>
              <ul>
                <li>Nunca compartilhe sua senha com ninguém</li>
                <li>Use uma senha forte com letras, números e símbolos</li>
                <li>Não use a mesma senha em diferentes sites</li>
                <li>Altere sua senha regularmente</li>
                <li>Desconfie de e-mails suspeitos solicitando seus dados</li>
              </ul>
            </div>
          </div>
          
          <div class="footer">
            <p><strong>Boutique Diniz</strong> - Moda e Elegância</p>
            <p>Desenvolvido por <span class="brand">Atlas Soluções</span></p>
            <p>© 2026 Boutique Diniz. Todos os direitos reservados.</p>
          </div>
        </div>
      </body>
      </html>
    `;
    
    await transporter.sendMail({
      from: config.smtp.from,
      to: cliente.email,
      subject: '✅ Senha redefinida com sucesso - Boutique Diniz',
      html: htmlContent
    });
    
    logger.info('Email de senha redefinida enviado', { clienteId: cliente.id });
  } catch (error) {
    logger.error('Erro ao enviar email de senha redefinida', { clienteId: cliente.id, erro: error.message });
  }
}

module.exports = {
  notificarLogin,
  notificarBoasVindas,
  notificarSenhaRedefinida,
  notificarRecuperacaoSenha,
  notificarAtualizacaoPedido,
  notificarPromocao,
  notificarAtualizacaoDados,
  enviarViaGoogleAppsScript
};
