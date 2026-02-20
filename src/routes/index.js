/**
 * BOUTIQUE DINIZ API - Rotas Principais
 * Desenvolvido por Estúdio Atlas
 */

const express = require('express');
const router = express.Router();

// Middlewares
const { verifyApiKey, authenticate } = require('../middlewares/auth');
const { uploadSingleImage, uploadMultipleImages, uploadMultipleMedia } = require('../middlewares/upload');

// Controllers
const sistemaController = require('../controllers/sistemaController');
const clienteController = require('../controllers/clienteController');
const enderecoController = require('../controllers/enderecoController');
const produtoController = require('../controllers/produtoController');
const varianteController = require('../controllers/varianteController');
const estoqueController = require('../controllers/estoqueController');
const carrinhoController = require('../controllers/carrinhoController');
const pedidoController = require('../controllers/pedidoController');
const caixaController = require('../controllers/caixaController');
const conteudoController = require('../controllers/conteudoController');
const backupController = require('../controllers/backupController');
const adminController = require('../controllers/adminController');
const pushController = require('../controllers/pushController');

// Novos controladores (Filiais e Cartões Presente)
const filialController = require('../controllers/filialController');
const cartaoPresenteController = require('../controllers/cartaoPresenteController');

// Controlador de categorias
const categoriaController = require('../controllers/categoriaController');

// Usuários do sistema (funcionários)
const usuarioController = require('../controllers/usuarioController');
const grupoController = require('../controllers/grupoController');

// Novos controladores v3
const webhookController = require('../controllers/webhookController');
const dispositivoController = require('../controllers/dispositivoController');

// Validators
const { paginationValidator, validateId } = require('../validators/common');

// ============================================
// ROTAS ADMINISTRATIVAS (Segurança)
// ============================================
router.get('/admin', adminController.getAdminPage);
router.post('/admin/login', adminController.login);
router.get('/admin/urls', adminController.listarUrls);
router.post('/admin/urls', adminController.adicionarUrl);
router.delete('/admin/urls/:id', adminController.removerUrl);

// Recuperação de senha de funcionários (via admin)
router.post('/admin/funcionarios/recuperar-senha', adminController.solicitarRecuperacaoSenha);
router.post('/admin/funcionarios/redefinir-senha', adminController.redefinirSenha);

// ============================================
// ROTAS PÚBLICAS (sem autenticação)
// ============================================

// Health check
router.get('/health', sistemaController.health);

// Token de integração (requer apenas API Key)
router.post('/token', verifyApiKey, sistemaController.gerarToken);
router.post('/token/revoke', authenticate, sistemaController.revogarToken);

// ============================================
// ROTAS DE CLIENTES
// ============================================

// Login e recuperação de senha (requer API Key + Token)
router.post('/clientes/login', authenticate, clienteController.login);
router.post('/clientes/recuperar-senha', authenticate, clienteController.recuperarSenha);
router.post('/clientes/redefinir-senha', authenticate, clienteController.redefinirSenha);

// CRUD Clientes
router.post('/clientes', authenticate, clienteController.criar);
router.get('/clientes', authenticate, paginationValidator, clienteController.listar);
router.get('/clientes/:id', authenticate, validateId, clienteController.buscar);
router.put('/clientes/:id', authenticate, validateId, clienteController.atualizar);
router.delete('/clientes/:id', authenticate, validateId, clienteController.remover);

// Endereços
router.post('/clientes/:id/enderecos', authenticate, validateId, enderecoController.criar);
router.get('/clientes/:id/enderecos', authenticate, validateId, enderecoController.listar);
router.put('/enderecos/:id', authenticate, validateId, enderecoController.atualizar);
router.delete('/enderecos/:id', authenticate, validateId, enderecoController.remover);

// ============================================
// ROTAS DE PRODUTOS
// ============================================

router.post('/produtos', authenticate, produtoController.criar);
router.get('/produtos', authenticate, paginationValidator, produtoController.listar);
router.get('/produtos/:id', authenticate, validateId, produtoController.buscar);
router.put('/produtos/:id', authenticate, validateId, produtoController.atualizar);
router.patch('/produtos/:id/status', authenticate, validateId, produtoController.atualizarStatus);
router.post('/produtos/:id/imagens', authenticate, validateId, uploadMultipleImages, produtoController.uploadImagens);
router.delete('/produtos/:id/imagens/:imagemId', authenticate, produtoController.removerImagem);

// Variantes
router.post('/produtos/:id/variantes', authenticate, validateId, varianteController.criar);
router.get('/produtos/:id/variantes', authenticate, validateId, varianteController.listar);
router.put('/variantes/:id', authenticate, validateId, varianteController.atualizar);
router.delete('/variantes/:id', authenticate, validateId, varianteController.remover);

// ============================================
// ROTAS DE CATEGORIAS DE PRODUTOS
// ============================================

// Cadastro de categoria (nome, logo, imagem, ativo). Requer autenticação e pode receber arquivos via multipart.
router.post(
  '/categorias',
  authenticate,
  require('../middlewares/upload').upload.fields([
    { name: 'logo', maxCount: 1 },
    { name: 'imagem', maxCount: 1 }
  ]),
  categoriaController.criar
);

// Listagem de categorias com paginação
router.get('/categorias', authenticate, paginationValidator, categoriaController.listar);

// Busca de categoria específica
router.get('/categorias/:id', authenticate, validateId, categoriaController.buscar);

// Atualização de categoria (permite alterar nome, ativo, logo e imagem)
router.put(
  '/categorias/:id',
  authenticate,
  validateId,
  require('../middlewares/upload').upload.fields([
    { name: 'logo', maxCount: 1 },
    { name: 'imagem', maxCount: 1 }
  ]),
  categoriaController.atualizar
);

// ============================================
// ROTAS DE ESTOQUE
// ============================================

router.post('/estoque/movimentos', authenticate, estoqueController.criarMovimento);
router.get('/estoque/movimentos', authenticate, paginationValidator, estoqueController.listarMovimentos);
router.get('/estoque/alertas', authenticate, estoqueController.listarAlertas);
router.get('/estoque/resumo', authenticate, estoqueController.resumo);

// ============================================
// ROTAS DE CARRINHO
// ============================================

router.post('/carrinho', authenticate, carrinhoController.adicionar);
router.get('/carrinho/:cliente_id', authenticate, carrinhoController.listar);
router.put('/carrinho/:item_id', authenticate, carrinhoController.atualizar);
router.delete('/carrinho/:item_id', authenticate, carrinhoController.remover);
router.post('/carrinho/:cliente_id/limpar', authenticate, carrinhoController.limpar);

// ============================================
// ROTAS DE PEDIDOS
// ============================================

router.post('/pedidos', authenticate, pedidoController.criar);
router.get('/pedidos', authenticate, paginationValidator, pedidoController.listar);
router.get('/pedidos/:id', authenticate, validateId, pedidoController.buscar);
router.patch('/pedidos/:id/status-pedido', authenticate, validateId, pedidoController.atualizarStatusPedido);
router.patch('/pedidos/:id/status-pagamento', authenticate, validateId, pedidoController.atualizarStatusPagamento);
router.patch('/pedidos/:id/rastreio', authenticate, validateId, pedidoController.atualizarRastreio);

// ============================================
// ROTAS DE CAIXA
// ============================================

router.post('/caixa/lancamentos', authenticate, caixaController.criar);
router.get('/caixa/lancamentos', authenticate, paginationValidator, caixaController.listar);
router.put('/caixa/lancamentos/:id', authenticate, validateId, caixaController.atualizar);
router.delete('/caixa/lancamentos/:id', authenticate, validateId, caixaController.remover);
router.get('/caixa/resumo', authenticate, caixaController.resumo);

// ============================================
// ROTAS DE BANNERS
// ============================================

router.post('/banners', authenticate, uploadSingleImage, conteudoController.criarBanner);
router.get('/banners', authenticate, conteudoController.listarBanners);
router.put('/banners/:id', authenticate, validateId, uploadSingleImage, conteudoController.atualizarBanner);
router.delete('/banners/:id', authenticate, validateId, conteudoController.removerBanner);

// ============================================
// ROTAS DE CARROSSEL
// ============================================

const carrosselController = require('../controllers/carrosselController');

router.post('/carrossel', authenticate, uploadSingleImage, carrosselController.criar);
router.get('/carrossel', authenticate, paginationValidator, carrosselController.listar);
router.get('/carrossel/ativo/listar', carrosselController.listarAtivos); // Rota pública para frontend
router.get('/carrossel/:id', authenticate, validateId, carrosselController.buscar);
router.put('/carrossel/:id', authenticate, validateId, uploadSingleImage, carrosselController.atualizar);
router.delete('/carrossel/:id', authenticate, validateId, carrosselController.remover);
router.patch('/carrossel/reordenar', authenticate, carrosselController.reordenar);

// ============================================
// ROTAS DE CUPONS
// ============================================

router.post('/cupons', authenticate, conteudoController.criarCupom);
router.get('/cupons', authenticate, paginationValidator, conteudoController.listarCupons);
router.post('/cupons/validar', authenticate, conteudoController.validarCupom);

// ============================================
// ROTAS DE NOTIFICAÇÕES
// ============================================

router.post('/notificacoes', authenticate, conteudoController.criarNotificacao);
router.get('/notificacoes', authenticate, paginationValidator, conteudoController.listarNotificacoes);
router.put('/notificacoes/:id', authenticate, validateId, conteudoController.marcarLida);

// ============================================
// ROTAS DE PÓS-VENDA
// ============================================

router.post('/posvenda', authenticate, conteudoController.criarPosVenda);
router.get('/posvenda', authenticate, paginationValidator, conteudoController.listarPosVenda);
router.patch('/posvenda/:id/status-reembolso', authenticate, validateId, conteudoController.atualizarStatusReembolso);

// ============================================
// ROTAS DE RECLAMAÇÕES
// ============================================

router.post('/reclamacoes', authenticate, conteudoController.criarReclamacao);
router.post('/reclamacoes/:id/midia', authenticate, validateId, uploadMultipleMedia, conteudoController.uploadMidiaReclamacao);
router.get('/reclamacoes', authenticate, paginationValidator, conteudoController.listarReclamacoes);
router.put('/reclamacoes/:id', authenticate, validateId, conteudoController.atualizarReclamacao);

// ============================================
// ROTAS DE TEMA
// ============================================

router.get('/tema', authenticate, conteudoController.getTema);
router.put('/tema', authenticate, conteudoController.atualizarTema);

// ============================================
// ROTAS DE BACKUP
// ============================================

const multer = require('multer');
const backupUpload = multer({ dest: '/tmp/backups/' });

router.post('/backup', authenticate, backupController.criarBackup);
router.post('/restore', authenticate, backupUpload.single('arquivo'), backupController.restaurarBackup);
router.get('/backups', authenticate, backupController.listarBackups);
router.delete('/backups/:arquivo', authenticate, backupController.removerBackup);

// ============================================
// ROTAS DE FILIAIS (Unidades)
// ============================================

router.post('/filiais', authenticate, filialController.criar);
router.get('/filiais', authenticate, paginationValidator, filialController.listar);
router.get('/filiais/:id', authenticate, validateId, filialController.buscar);
router.put('/filiais/:id', authenticate, validateId, filialController.atualizar);
router.delete('/filiais/:id', authenticate, validateId, filialController.remover);

// ============================================
// ROTAS DE CARTÕES PRESENTE
// ============================================

router.post('/cartoes', authenticate, cartaoPresenteController.criar);
router.get('/cartoes', authenticate, paginationValidator, cartaoPresenteController.listar);
router.get('/cartoes/numero/:numero', authenticate, cartaoPresenteController.buscarPorNumero);
router.delete('/cartoes/:id', authenticate, validateId, cartaoPresenteController.remover);
router.post('/cartoes/resgatar', authenticate, cartaoPresenteController.resgatar);


// ============================================
// ROTAS DE CAIXA — SESSÕES (abertura e fechamento formal)
// ============================================

router.post('/caixa/abrir',           authenticate, caixaController.abrirCaixa);
router.post('/caixa/:sessaoId/fechar', authenticate, caixaController.fecharCaixa);
router.get('/caixa/sessoes',           authenticate, paginationValidator, caixaController.listarSessoes);
router.get('/caixa/sessoes/:id',       authenticate, validateId, caixaController.buscarSessao);

// ============================================
// ROTAS DE USUÁRIOS DO SISTEMA (FUNCIONÁRIOS)
// ============================================

// Login de funcionário (requer API Key + Token de integração)
router.post('/usuarios/login', authenticate, usuarioController.login);

// Listar usuários (com paginação opcional)
router.get('/usuarios', authenticate, paginationValidator, usuarioController.listar);

// Criar novo usuário
router.post('/usuarios', authenticate, usuarioController.criar);

// Atualizar dados de usuário existente
router.put('/usuarios/:id', authenticate, validateId, usuarioController.atualizar);

// Alterar grupo de acesso principal de usuário
router.put('/usuarios/:id/grupos', authenticate, validateId, usuarioController.atualizarGrupo);

// Listar grupos de acesso
router.get('/grupos', authenticate, usuarioController.listarGrupos);

// Recuperação de senha e redefinição para usuários do sistema
router.post('/usuarios/recuperar-senha', authenticate, usuarioController.recuperarSenha);
router.post('/usuarios/redefinir-senha', authenticate, usuarioController.redefinirSenha);
// Gerenciamento de grupos de acesso
router.get('/grupos/:id', authenticate, validateId, grupoController.buscar);
router.post('/grupos', authenticate, grupoController.criar);
router.put('/grupos/:id', authenticate, validateId, grupoController.atualizar);
router.delete('/grupos/:id', authenticate, validateId, grupoController.remover);

// ============================================
// ROTAS DE NOTIFICAÇÕES (PUSH WEB)
// ============================================

// Retorna a chave pública VAPID para o frontend registrar a inscrição
router.get('/push/vapid-public-key', authenticate, pushController.getVapidPublicKey);

// Registra uma inscrição de push (Web Push)
router.post('/push/subscribe', authenticate, pushController.subscribe);

// Remove uma inscrição de push
router.post('/push/unsubscribe', authenticate, pushController.unsubscribe);

// Envia uma notificação para todas as inscrições (admin)
router.post('/push/send', authenticate, pushController.send);

// ============================================
// ROTAS FINANCEIRO
// ============================================

const financeiroController = require('../controllers/financeiroController');

// Dashboard e caixas pendentes
router.get('/financeiro/dashboard',                   authenticate, financeiroController.dashboard);
router.get('/financeiro/caixas-pendentes',            authenticate, paginationValidator, financeiroController.listarCaixasPendentes);
router.get('/financeiro/caixas/:sessaoId',            authenticate, financeiroController.revisarCaixa);
router.post('/financeiro/caixas/:sessaoId/aprovar',   authenticate, financeiroController.aprovarCaixa);
router.post('/financeiro/caixas/:sessaoId/rejeitar',  authenticate, financeiroController.rejeitarCaixa);

// Contas a pagar
router.post('/financeiro/contas-pagar',               authenticate, financeiroController.criarContaPagar);
router.get('/financeiro/contas-pagar',                authenticate, paginationValidator, financeiroController.listarContasPagar);
router.put('/financeiro/contas-pagar/:id',            authenticate, validateId, financeiroController.atualizarContaPagar);
router.patch('/financeiro/contas-pagar/:id/baixar',   authenticate, validateId, financeiroController.baixarContaPagar);

// Contas a receber
router.post('/financeiro/contas-receber',             authenticate, financeiroController.criarContaReceber);
router.get('/financeiro/contas-receber',              authenticate, paginationValidator, financeiroController.listarContasReceber);
router.patch('/financeiro/contas-receber/:id/baixar', authenticate, validateId, financeiroController.baixarContaReceber);

// Fechamento financeiro consolidado
router.post('/financeiro/fechamento',                 authenticate, financeiroController.gerarFechamento);
router.get('/financeiro/fechamentos',                 authenticate, paginationValidator, financeiroController.listarFechamentos);
router.get('/financeiro/fechamentos/:id',             authenticate, validateId, financeiroController.buscarFechamento);

// ============================================
// ROTAS DE WEBHOOK
// ============================================

router.get('/webhook/config',                authenticate, webhookController.getConfig);
router.put('/webhook/config',                authenticate, webhookController.updateConfig);
router.post('/webhook/testar',               authenticate, webhookController.testar);
router.get('/webhook/logs',                  authenticate, paginationValidator, webhookController.listarLogs);

// Callback de dispositivo (recebe resposta do serviço externo)
// Este endpoint pode ser chamado sem autenticação padrão (usa secret do webhook)
router.post('/webhook/callback/dispositivo', webhookController.callbackDispositivo);

// ============================================
// ROTAS DE AUTENTICAÇÃO DE DISPOSITIVOS
// ============================================

router.post('/dispositivos/solicitar',             authenticate, dispositivoController.solicitar);
router.get('/dispositivos/status/:solicitacaoId',  authenticate, dispositivoController.consultarStatus);
router.get('/dispositivos/validar',                dispositivoController.validarToken); // Não requer auth padrão, usa token próprio
router.delete('/dispositivos/:id/revogar',         authenticate, dispositivoController.revogar);
router.get('/dispositivos',                        authenticate, paginationValidator, dispositivoController.listar);

module.exports = router;

