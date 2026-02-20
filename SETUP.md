# 🚀 Guia de Setup - Boutique Diniz API

**Desenvolvido por:** Atlas Soluções  
**Versão:** 1.0.0  
**Data:** Fevereiro 2026

---

## 📋 Pré-requisitos

- **Node.js:** v18.0.0 ou superior
- **npm:** v9.0.0 ou superior
- **Git:** Para controle de versão
- **Conta Gmail:** Para envio de emails (opcional, pode usar outro SMTP)

---

## 🔧 Instalação Rápida

### 1. Clonar o Repositório

```bash
git clone <seu-repositorio>
cd boutique-diniz-sistema
```

### 2. Instalar Dependências

```bash
npm install
```

### 3. Configurar Variáveis de Ambiente

Copie o arquivo `.env.example` para `.env`:

```bash
cp .env.example .env
```

Edite o arquivo `.env` com suas configurações:

```env
# Servidor
PORT=1535
HOST=0.0.0.0
NODE_ENV=production

# Banco de Dados
DB_CORE_PATH=./data/core.db
DB_AUTH_PATH=./data/auth.db
DB_AUDIT_PATH=./data/audit.db

# E-mail (Gmail)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=seu_email@gmail.com
SMTP_PASS=sua_senha_de_app
EMAIL_FROM=Boutique Diniz <noreply@boutiquediniz.com>

# Google Apps Script
GOOGLE_APPS_SCRIPT_URL=https://script.google.com/macros/s/AKfycbxmWQYuR6oxsj7fD1yeUQ0UIdw8_nC_GrAF-ZxKuy5kxSFsJvsBXbW-N8kvT8Q2MGCk/exec

# Branding
BRAND_NAME=Boutique Diniz
BRAND_DEVELOPER=Atlas Soluções
BRAND_YEAR=2026
BRAND_WEBSITE=https://www.atlassolutions.com.br
```

### 4. Inicializar Banco de Dados

```bash
npm run init-db
```

### 5. Iniciar o Servidor

**Desenvolvimento:**
```bash
npm run dev
```

**Produção:**
```bash
npm start
```

---

## 📧 Configuração de Email

### Gmail (Recomendado)

1. Acesse sua conta Google: https://myaccount.google.com
2. Vá para "Segurança" no menu lateral
3. Ative "Autenticação de dois fatores"
4. Gere uma "Senha de app" em https://myaccount.google.com/apppasswords
5. Use a senha gerada no arquivo `.env`

### Outro Servidor SMTP

Se usar outro servidor SMTP, altere as configurações:

```env
SMTP_HOST=seu_servidor.com
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=seu_usuario
SMTP_PASS=sua_senha
```

---

## 🗄️ Banco de Dados

### Estrutura

O sistema utiliza 3 bancos de dados SQLite:

- **core.db** - Dados principais (clientes, produtos, pedidos)
- **auth.db** - Autenticação e recuperação de senha
- **audit.db** - Auditoria e logs

### Inicialização

```bash
npm run init-db
```

### Backup

```bash
npm run backup
```

### Restauração

```bash
npm run restore
```

---

## 🔐 Segurança

### Chaves Secretas

Altere as chaves padrão no `.env`:

```env
API_KEY=1526
TOKEN_SECRET=BoutiqueDiniz2026SecretKey_EstudioAtlas_!@#$%
ENCRYPTION_KEY=BoutiqueDiniz2026Encrypt32Ch!!
```

### HTTPS em Produção

Configure um proxy reverso (Nginx, Apache) com SSL/TLS:

```nginx
server {
    listen 443 ssl;
    server_name api.boutiquediniz.com;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    location / {
        proxy_pass http://localhost:1535;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### Rate Limiting

O sistema está configurado com rate limiting:

```env
RATE_LIMIT_WINDOW_MS=900000  # 15 minutos
RATE_LIMIT_MAX_REQUESTS=500  # 500 requisições
```

---

## 📊 Monitoramento

### Logs

Os logs são salvos em `./logs/`:

```bash
# Ver logs em tempo real
tail -f logs/combined.log

# Ver apenas erros
tail -f logs/error.log
```

### Health Check

```bash
curl http://localhost:1535/api/health
```

### Status do PM2

```bash
npm run pm2:status
npm run pm2:logs
```

---

## 🚀 Deployment

### Com PM2

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

### Com Docker

Crie um `Dockerfile`:

```dockerfile
FROM node:18-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY . .

EXPOSE 1535

CMD ["npm", "start"]
```

Build e execute:

```bash
docker build -t boutique-diniz-api .
docker run -p 1535:1535 --env-file .env boutique-diniz-api
```

### Com Systemd (Linux)

Crie `/etc/systemd/system/boutique-diniz.service`:

```ini
[Unit]
Description=Boutique Diniz API
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/home/www-data/boutique-diniz-sistema
ExecStart=/usr/bin/npm start
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Ative o serviço:

```bash
sudo systemctl daemon-reload
sudo systemctl enable boutique-diniz
sudo systemctl start boutique-diniz
sudo systemctl status boutique-diniz
```

---

## 🧪 Testes

### Testar Endpoints

```bash
# Health check
curl http://localhost:1535/api/health

# Gerar token
curl -X POST http://localhost:1535/api/token \
  -H "Content-Type: application/json" \
  -H "X-API-KEY: 1526" \
  -d '{"usuario": "admin"}'

# Login de cliente
curl -X POST http://localhost:1535/api/clientes/login \
  -H "Content-Type: application/json" \
  -H "X-API-TOKEN: seu_token" \
  -d '{"cpf": "123.456.789-00", "senha": "senha123"}'
```

### Testar Notificações

```bash
# Recuperação de senha
curl -X POST http://localhost:1535/api/clientes/recuperar-senha \
  -H "Content-Type: application/json" \
  -H "X-API-TOKEN: seu_token" \
  -d '{"cpf": "123.456.789-00"}'
```

---

## 📈 Otimizações para Dados em Massa

O sistema está otimizado para lidar com grandes volumes de dados:

### Configurações Aplicadas

```env
# Tamanho máximo de upload
UPLOAD_MAX_SIZE_MB=50

# Limite de requisições aumentado
RATE_LIMIT_MAX_REQUESTS=500

# Pool de conexões
CONNECTION_POOL_SIZE=20

# Tamanho máximo de corpo
MAX_BODY_SIZE=50mb
```

### Índices do Banco de Dados

Os índices estão criados automaticamente:

```sql
CREATE INDEX idx_cliente_cpf ON cliente(cpf);
CREATE INDEX idx_cliente_email ON cliente(email);
CREATE INDEX idx_pedido_cliente ON pedido(cliente_id);
CREATE INDEX idx_pedido_status ON pedido(status_pedido);
```

### Paginação

Use paginação para listar dados:

```bash
curl "http://localhost:1535/api/clientes?page=1&pageSize=50"
```

---

## 🎯 Branding - Atlas Soluções

O sistema está configurado com branding da Atlas Soluções:

### Personalizações

```env
BRAND_NAME=Boutique Diniz
BRAND_DEVELOPER=Atlas Soluções
BRAND_YEAR=2026
BRAND_WEBSITE=https://www.atlassolutions.com.br
```

### Emails

Todos os emails incluem:
- Logo da Boutique Diniz
- Rodapé com "Desenvolvido por Atlas Soluções"
- Link para website

### Resposta da API

```json
{
  "success": true,
  "message": "Boutique Diniz API",
  "developer": "Atlas Soluções",
  "website": "https://www.atlassolutions.com.br"
}
```

---

## 🐛 Troubleshooting

### Porta 1535 já está em uso

```bash
# Encontrar processo usando a porta
lsof -i :1535

# Matar processo
kill -9 <PID>

# Ou usar outra porta no .env
PORT=1536
```

### Erro de conexão com banco de dados

```bash
# Verificar se a pasta data existe
mkdir -p data

# Reinicializar banco de dados
npm run init-db
```

### Email não está sendo enviado

1. Verifique credenciais SMTP
2. Verifique se a porta está correta
3. Verifique logs: `tail -f logs/error.log`
4. Teste conexão SMTP:

```bash
node -e "
const nodemailer = require('nodemailer');
const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 587,
  auth: {
    user: 'seu_email@gmail.com',
    pass: 'sua_senha'
  }
});
transporter.verify((err, success) => {
  if (err) console.log(err);
  else console.log('Conexão OK');
});
"
```

---

## 📞 Suporte

Para dúvidas ou problemas:

**Atlas Soluções**  
Website: https://www.atlassolutions.com.br  
Email: suporte@atlassolutions.com.br

---

## 📄 Licença

Propriedade exclusiva da Boutique Diniz.  
Desenvolvido por Atlas Soluções © 2026

---

**Última atualização:** 12 de Fevereiro de 2026
