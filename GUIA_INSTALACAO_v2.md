# 🚀 Guia de Instalação - Boutique Diniz API v2

**Versão:** 2.0.0  
**Data:** 16 de Fevereiro de 2026  
**Desenvolvido por:** Atlas Soluções

---

## 📋 Índice

1. [Pré-requisitos](#pré-requisitos)
2. [Instalação Rápida](#instalação-rápida)
3. [Configuração](#configuração)
4. [Inicialização do Banco de Dados](#inicialização-do-banco-de-dados)
5. [Migração de Banco Existente](#migração-de-banco-existente)
6. [Iniciar o Servidor](#iniciar-o-servidor)
7. [Verificação de Saúde](#verificação-de-saúde)
8. [Troubleshooting](#troubleshooting)

---

## 🔧 Pré-requisitos

### Sistema Operacional
- Windows 10+
- macOS 10.15+
- Linux (Ubuntu 18.04+, Debian 10+)

### Software Necessário

| Software | Versão | Download |
|----------|--------|----------|
| Node.js | 18.0.0+ | https://nodejs.org |
| npm | 8.0.0+ | Incluído com Node.js |
| Git | 2.30.0+ | https://git-scm.com |

### Verificar Instalação

```bash
node --version    # v18.0.0 ou superior
npm --version     # 8.0.0 ou superior
git --version     # 2.30.0 ou superior
```

---

## ⚡ Instalação Rápida

### 1. Clonar ou Extrair o Projeto

```bash
# Se tiver arquivo ZIP
unzip botiquedinizv9_corrigido.zip
cd botiquedinizv8

# Ou clonar do repositório
git clone <seu-repositorio>
cd botiquedinizv8
```

### 2. Instalar Dependências

```bash
npm install
```

**Tempo esperado:** 2-5 minutos (depende da velocidade da conexão)

### 3. Configurar Variáveis de Ambiente

```bash
# Copiar arquivo de exemplo
cp .env.example .env

# Editar arquivo .env com suas configurações
nano .env  # ou use seu editor favorito
```

### 4. Inicializar Banco de Dados

```bash
# Novo banco de dados
node scripts/init-database.js

# Ou migrar banco existente
node scripts/add-carrossel-table.js
```

### 5. Iniciar Servidor

```bash
npm start
```

Você deve ver:

```
╔════════════════════════════════════════════════════════════╗
║                  Boutique Diniz API                        ║
║                 Desenvolvido por Atlas Soluções            ║
╠════════════════════════════════════════════════════════════╣
║  Status: ✅ Online                                         ║
║  Ambiente: production                                      ║
║  Porta: 1535                                               ║
║  URL: http://0.0.0.0:1535                                  ║
╚════════════════════════════════════════════════════════════╝
```

---

## ⚙️ Configuração

### Arquivo .env

Edite o arquivo `.env` com suas configurações:

```env
# ============================================
# AMBIENTE
# ============================================
NODE_ENV=production

# ============================================
# SERVIDOR
# ============================================
PORT=1535
HOST=0.0.0.0

# ============================================
# SEGURANÇA
# ============================================
API_KEY=1526  # Alterar em produção!
TOKEN_SECRET=SuaChaveSecretaAqui  # Alterar em produção!
ENCRYPTION_KEY=SuaChaveEncriptacaoAqui  # 32 caracteres

# ============================================
# EMAIL (SMTP)
# ============================================
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=seu_email@gmail.com
SMTP_PASS=sua_senha_de_app
EMAIL_FROM=Boutique Diniz <noreply@boutiquediniz.com>

# ============================================
# GOOGLE APPS SCRIPT
# ============================================
GOOGLE_APPS_SCRIPT_URL=https://script.google.com/macros/s/...

# ============================================
# UPLOADS
# ============================================
UPLOAD_MAX_SIZE_MB=50
UPLOAD_PATH=./data/uploads

# ============================================
# BACKUP
# ============================================
BACKUP_PATH=./data/backups
BACKUP_RETENTION_DAYS=7
BACKUP_CRON_SCHEDULE=0 3 */4 * *

# ============================================
# RATE LIMITING
# ============================================
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=500

# ============================================
# LOGS
# ============================================
LOG_LEVEL=info
LOG_PATH=./logs
```

### Configurações Importantes

#### 1. Segurança em Produção

```env
# Gerar chaves seguras
API_KEY=seu_codigo_aleatorio_aqui
TOKEN_SECRET=gerar_com_openssl_rand_-_hex_32
ENCRYPTION_KEY=gerar_com_openssl_rand_-_hex_32
```

#### 2. Email (Gmail)

```env
# 1. Ativar "Acesso a apps menos seguros" em:
# https://myaccount.google.com/lesssecureapps

# 2. Gerar "Senha de app" em:
# https://myaccount.google.com/apppasswords

SMTP_USER=seu_email@gmail.com
SMTP_PASS=sua_senha_de_app_gerada
```

#### 3. Email (Outro SMTP)

```env
# Exemplo: SendGrid
SMTP_HOST=smtp.sendgrid.net
SMTP_PORT=587
SMTP_USER=apikey
SMTP_PASS=SG.sua_chave_sendgrid
```

---

## 📊 Inicialização do Banco de Dados

### Novo Banco de Dados

```bash
node scripts/init-database.js
```

Este script:
- ✅ Cria arquivo `core.db` (dados principais)
- ✅ Cria arquivo `auth.db` (autenticação)
- ✅ Cria arquivo `audit.db` (auditoria)
- ✅ Cria todas as tabelas necessárias
- ✅ Cria índices para performance
- ✅ Configura constraints de integridade

**Saída esperada:**

```
╔════════════════════════════════════════════════════════════╗
║     BOUTIQUE DINIZ API - Inicialização do Banco de Dados   ║
║          Compatible: Windows/Linux/Mac (better-sqlite3)    ║
╚════════════════════════════════════════════════════════════╝

📦 Criando CORE.DB (Dados principais)...
✅ CORE.DB criado com sucesso
📦 Criando AUTH.DB (Autenticação)...
✅ AUTH.DB criado com sucesso
📦 Criando AUDIT.DB (Auditoria)...
✅ AUDIT.DB criado com sucesso

✅ Banco de dados inicializado com sucesso!
```

### Banco de Dados Existente

Se você já tem um banco de dados e quer adicionar a tabela de carrossel:

```bash
node scripts/add-carrossel-table.js
```

Este script:
- ✅ Verifica se tabela já existe
- ✅ Cria tabela se não existir
- ✅ Cria índices para performance
- ✅ Não afeta dados existentes

---

## 🔄 Migração de Banco Existente

### Passo a Passo

#### 1. Fazer Backup

```bash
node scripts/backup.js
```

Backup será salvo em `./data/backups/`

#### 2. Adicionar Tabela de Carrossel

```bash
node scripts/add-carrossel-table.js
```

#### 3. Verificar Integridade

```bash
# Conectar ao banco e verificar
sqlite3 ./data/core.db "SELECT name FROM sqlite_master WHERE type='table';"
```

Você deve ver a tabela `carrossel` na lista.

#### 4. Testar API

```bash
curl http://localhost:1535/api/health
```

---

## 🚀 Iniciar o Servidor

### Modo Produção

```bash
npm start
```

### Modo Desenvolvimento

```bash
npm run dev
```

(Requer `nodemon` instalado)

### Usando PM2 (Recomendado para Produção)

```bash
# Instalar PM2 globalmente
npm install -g pm2

# Iniciar com PM2
npm run pm2:start

# Ver status
npm run pm2:status

# Ver logs
npm run pm2:logs

# Parar
npm run pm2:stop

# Reiniciar
npm run pm2:restart
```

---

## ✅ Verificação de Saúde

### 1. Health Check

```bash
curl http://localhost:1535/api/health
```

**Resposta esperada:**

```json
{
  "success": true,
  "message": "Sistema operacional",
  "status": "online",
  "timestamp": "2026-02-16T18:30:00Z"
}
```

### 2. Rota Raiz

```bash
curl http://localhost:1535/
```

**Resposta esperada:**

```json
{
  "success": true,
  "message": "Boutique Diniz API",
  "version": "1.0.0",
  "developer": "Atlas Soluções",
  "website": "https://www.atlassolutions.com.br",
  "documentation": "/docs",
  "health": "/api/health"
}
```

### 3. Gerar Token

```bash
curl -X POST http://localhost:1535/api/token \
  -H "X-API-KEY: 1526" \
  -H "Content-Type: application/json"
```

---

## 🐛 Troubleshooting

### Problema: "Port 1535 is already in use"

**Solução:**

```bash
# Encontrar processo usando a porta
lsof -i :1535  # macOS/Linux
netstat -ano | findstr :1535  # Windows

# Matar processo
kill -9 <PID>  # macOS/Linux
taskkill /PID <PID> /F  # Windows

# Ou mudar porta no .env
PORT=3000
```

### Problema: "Cannot find module 'better-sqlite3'"

**Solução:**

```bash
# Reinstalar dependências
rm -rf node_modules package-lock.json
npm install

# Ou instalar especificamente
npm install better-sqlite3
```

### Problema: "EACCES: permission denied"

**Solução:**

```bash
# Dar permissão de escrita
chmod -R 755 ./data
chmod -R 755 ./logs

# Ou usar sudo (não recomendado)
sudo npm start
```

### Problema: "Database is locked"

**Solução:**

```bash
# Fechar todas as conexões
pkill -f "node src/server.js"

# Aguardar 5 segundos
sleep 5

# Reiniciar
npm start
```

### Problema: "Upload timeout"

**Solução:**

```env
# Aumentar timeout em .env (se necessário)
# Já está em 60 segundos por padrão

# Verificar tamanho máximo
UPLOAD_MAX_SIZE_MB=50

# Verificar conexão de rede
# Testar com arquivo menor
```

### Problema: "Cannot GET /api/carrossel"

**Solução:**

```bash
# Verificar se tabela foi criada
node scripts/add-carrossel-table.js

# Reiniciar servidor
npm start

# Testar novamente
curl http://localhost:1535/api/carrossel \
  -H "X-API-KEY: 1526" \
  -H "X-API-TOKEN: seu_token"
```

---

## 📝 Logs

### Localização

```
./logs/
├── combined.log      # Todos os logs
├── error.log         # Apenas erros
└── app.log           # Logs da aplicação
```

### Ver Logs em Tempo Real

```bash
# Todos os logs
tail -f ./logs/combined.log

# Apenas erros
tail -f ./logs/error.log

# Últimas 100 linhas
tail -100 ./logs/combined.log
```

### Limpar Logs

```bash
# Limpar arquivo
> ./logs/combined.log

# Ou deletar
rm ./logs/*.log
```

---

## 🔐 Segurança

### Checklist de Produção

- ✅ Alterar `API_KEY` no `.env`
- ✅ Alterar `TOKEN_SECRET` no `.env`
- ✅ Alterar `ENCRYPTION_KEY` no `.env`
- ✅ Configurar SMTP com credenciais reais
- ✅ Usar HTTPS em produção
- ✅ Configurar firewall
- ✅ Fazer backup regular
- ✅ Monitorar logs
- ✅ Atualizar dependências regularmente
- ✅ Usar variáveis de ambiente seguras

### Gerar Chaves Seguras

```bash
# Linux/macOS
openssl rand -hex 32  # Para TOKEN_SECRET
openssl rand -hex 16  # Para ENCRYPTION_KEY

# Windows (PowerShell)
[System.Convert]::ToHexString([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
```

---

## 📦 Deployment

### Heroku

```bash
# 1. Criar app
heroku create seu-app-name

# 2. Configurar variáveis
heroku config:set API_KEY=sua_chave
heroku config:set TOKEN_SECRET=sua_chave_secreta

# 3. Deploy
git push heroku main
```

### AWS EC2

```bash
# 1. SSH na instância
ssh -i seu-key.pem ec2-user@seu-ip

# 2. Instalar Node.js
curl -fsSL https://rpm.nodesource.com/setup_18.x | sudo bash -
sudo yum install -y nodejs

# 3. Clonar projeto
git clone seu-repositorio
cd botiquedinizv8

# 4. Instalar e iniciar
npm install
npm start
```

### Docker

```dockerfile
FROM node:18-alpine

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .

EXPOSE 1535

CMD ["npm", "start"]
```

```bash
# Build
docker build -t boutique-diniz .

# Run
docker run -p 1535:1535 boutique-diniz
```

---

## 📞 Suporte

### Documentação
- [README.md](./README.md) - Visão geral
- [SETUP.md](./SETUP.md) - Configuração detalhada
- [CORRECOES_v2_UPLOAD.md](./CORRECOES_v2_UPLOAD.md) - Correções implementadas
- [docs/API_DOCUMENTATION.md](./docs/API_DOCUMENTATION.md) - Documentação da API

### Contato
**Atlas Soluções**  
Website: https://www.atlassolutions.com.br  
Email: suporte@atlassolutions.com.br

---

## ✨ Próximos Passos

1. ✅ Instalar dependências
2. ✅ Configurar `.env`
3. ✅ Inicializar banco de dados
4. ✅ Iniciar servidor
5. ✅ Testar endpoints
6. ✅ Configurar backup automático
7. ✅ Monitorar logs
8. ✅ Deploy em produção

---

**Desenvolvido com ❤️ por Atlas Soluções**  
© 2026 Boutique Diniz - Todos os direitos reservados
