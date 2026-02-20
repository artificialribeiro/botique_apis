#!/bin/bash
# ============================================
# BOUTIQUE DINIZ API - Script de Instalação
# Desenvolvido por Estúdio Atlas
# ============================================

set -e

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║        BOUTIQUE DINIZ API - Instalação Automatizada        ║"
echo "║                 Desenvolvido por Estúdio Atlas             ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Função para exibir mensagens
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Verificar se está rodando como root
if [ "$EUID" -eq 0 ]; then
    log_warn "Não é recomendado executar como root. Continuando mesmo assim..."
fi

# Verificar Node.js
log_info "Verificando Node.js..."
if ! command -v node &> /dev/null; then
    log_error "Node.js não encontrado. Por favor, instale o Node.js 18+ primeiro."
    exit 1
fi

NODE_VERSION=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
if [ "$NODE_VERSION" -lt 18 ]; then
    log_error "Node.js versão 18+ é necessária. Versão atual: $(node -v)"
    exit 1
fi
log_info "Node.js $(node -v) ✓"

# Verificar npm
log_info "Verificando npm..."
if ! command -v npm &> /dev/null; then
    log_error "npm não encontrado."
    exit 1
fi
log_info "npm $(npm -v) ✓"

# Instalar dependências
log_info "Instalando dependências..."
npm install --production

# Criar arquivo .env se não existir
if [ ! -f .env ]; then
    log_info "Criando arquivo .env a partir do template..."
    cp .env.example .env
    
    # Gerar chaves seguras
    TOKEN_SECRET=$(openssl rand -hex 32)
    ENCRYPTION_KEY=$(openssl rand -hex 16)
    
    # Substituir valores no .env
    sed -i "s/sua_chave_secreta_muito_forte_aqui_minimo_32_caracteres/$TOKEN_SECRET/" .env
    sed -i "s/chave_de_32_caracteres_exatos_!!/$ENCRYPTION_KEY/" .env
    
    log_info "Arquivo .env criado com chaves seguras"
    log_warn "IMPORTANTE: Edite o arquivo .env e configure as credenciais de e-mail!"
else
    log_info "Arquivo .env já existe, mantendo configurações atuais"
fi

# Criar diretórios necessários
log_info "Criando estrutura de diretórios..."
mkdir -p data/uploads/produtos
mkdir -p data/uploads/banners
mkdir -p data/uploads/reclamacoes
mkdir -p data/backups
mkdir -p logs

# Definir permissões
chmod -R 755 data
chmod -R 755 logs

# Inicializar banco de dados
log_info "Inicializando banco de dados..."
node scripts/init-database.js

# Verificar PM2
log_info "Verificando PM2..."
if ! command -v pm2 &> /dev/null; then
    log_info "Instalando PM2 globalmente..."
    npm install -g pm2
fi
log_info "PM2 $(pm2 -v) ✓"

# Configurar PM2 para iniciar no boot
log_info "Configurando PM2 para iniciar no boot do sistema..."
pm2 startup systemd -u $USER --hp $HOME 2>/dev/null || true

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║            ✅ INSTALAÇÃO CONCLUÍDA COM SUCESSO!            ║"
echo "╠════════════════════════════════════════════════════════════╣"
echo "║                                                            ║"
echo "║  Próximos passos:                                          ║"
echo "║                                                            ║"
echo "║  1. Edite o arquivo .env com suas configurações            ║"
echo "║     (especialmente credenciais de e-mail)                  ║"
echo "║                                                            ║"
echo "║  2. Inicie o servidor:                                     ║"
echo "║     npm run pm2:start                                      ║"
echo "║                                                            ║"
echo "║  3. Verifique o status:                                    ║"
echo "║     npm run pm2:status                                     ║"
echo "║                                                            ║"
echo "║  4. Salve a configuração do PM2:                           ║"
echo "║     pm2 save                                               ║"
echo "║                                                            ║"
echo "║  Credenciais padrão do admin:                              ║"
echo "║  • Login: admin                                            ║"
echo "║  • Senha: admin123                                         ║"
echo "║  ⚠️  ALTERE A SENHA APÓS O PRIMEIRO LOGIN!                 ║"
echo "║                                                            ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
