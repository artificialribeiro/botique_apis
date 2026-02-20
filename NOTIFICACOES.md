# 📧 Sistema de Notificações - Boutique Diniz

**Desenvolvido por:** Atlas Soluções  
**Versão:** 1.0.0  
**Data:** Fevereiro 2026

---

## 📋 Visão Geral

O sistema de notificações integrado da Boutique Diniz oferece notificações automáticas por email para eventos importantes do sistema, incluindo:

- **🔐 Login:** Notificação de acesso à conta
- **🔑 Recuperação de Senha:** Código de recuperação com token (4 números + 3 letras)
- **📦 Atualizações de Pedidos:** Status de processamento, envio e entrega
- **🎉 Promoções e Descontos:** Ofertas especiais para clientes
- **📝 Atualização de Dados:** Alterações cadastrais
- **💳 Atualizações de Pagamento:** Status de pagamento dos pedidos

---

## 🔧 Configuração

### Variáveis de Ambiente

Adicione as seguintes variáveis ao arquivo `.env`:

```env
# Servidor
PORT=1535
HOST=0.0.0.0

# E-mail SMTP
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

### Configuração do Gmail

Para usar o Gmail como servidor SMTP:

1. Ative a autenticação de dois fatores na sua conta Google
2. Gere uma senha de app em: https://myaccount.google.com/apppasswords
3. Use essa senha no campo `SMTP_PASS`

---

## 📤 Tipos de Notificações

### 1. Notificação de Login

**Quando:** Quando um cliente faz login na plataforma  
**Dados Enviados:**
- Nome do cliente
- CPF
- Data/hora do acesso
- IP do cliente
- Navegador utilizado

**Exemplo de Email:**
```
Assunto: 🔐 Acesso à sua conta - Boutique Diniz

Olá, João Silva!

Detectamos um acesso à sua conta.

Data/Hora: 12/02/2026 10:30:45
IP: 192.168.1.100
Navegador: Chrome 120.0

Se você não realizou este acesso, altere sua senha imediatamente.
```

### 2. Recuperação de Senha

**Quando:** Quando um cliente solicita recuperação de senha  
**Dados Enviados:**
- Nome do cliente
- Código de recuperação (4 números + 3 letras)
- Validade do código (30 minutos)

**Exemplo de Email:**
```
Assunto: 🔑 Código de recuperação de senha - Boutique Diniz

Olá, João Silva!

Recebemos uma solicitação para recuperar sua senha. Use o código abaixo:

1234ABC

Válido por 30 minutos

Se você não solicitou esta recuperação, ignore este email.
```

### 3. Atualização de Pedido

**Quando:** Quando o status de um pedido é alterado  
**Dados Enviados:**
- Número do pedido
- Status anterior e novo
- Valor total
- Código de rastreio (se disponível)

**Exemplo de Email:**
```
Assunto: 📦 Atualização do seu pedido #PED-001234

Olá, João Silva!

Seu pedido foi atualizado!

✅ CONFIRMADO

Número do Pedido: #PED-001234
Valor: R$ 299,90
Rastreio: BR123456789BR
```

### 4. Promoção/Desconto

**Quando:** Quando uma promoção é criada ou atualizada  
**Dados Enviados:**
- Título da promoção
- Descrição
- Percentual/valor de desconto
- Código do cupom
- Data de início e fim

**Exemplo de Email:**
```
Assunto: 🎉 Promoção especial para você! Liquidação de Verão

Olá, João Silva!

Temos uma promoção especial para você!

LIQUIDAÇÃO DE VERÃO
Aproveite 50% de desconto em toda coleção de verão!

VERAO50

Válido até: 28/02/2026
```

### 5. Atualização de Dados Cadastrais

**Quando:** Quando dados do cliente são alterados  
**Dados Enviados:**
- Campos que foram alterados
- Novos valores

**Exemplo de Email:**
```
Assunto: 📝 Seus dados cadastrais foram atualizados

Olá, João Silva!

Seus dados cadastrais foram atualizados:

Email: joao@email.com
Telefone: (27) 99999-9999
Endereço: Rua Principal, 123

Se você não realizou esta alteração, entre em contato conosco imediatamente.
```

---

## 🔌 Integração com Google Apps Script

O sistema envia notificações para o Google Apps Script que registra os dados em uma planilha Google Sheets.

### URL da API Google Apps Script

```
https://script.google.com/macros/s/AKfycbxmWQYuR6oxsj7fD1yeUQ0UIdw8_nC_GrAF-ZxKuy5kxSFsJvsBXbW-N8kvT8Q2MGCk/exec
```

### Formato de Requisição

```
GET /exec?email=cliente@email.com&dados={"tipo":"login","nome":"João Silva",...}
```

### Resposta de Sucesso

```json
{
  "status": "success",
  "codigo": 200,
  "marca": "Boutique Diniz",
  "sistema": "Atlas Soluções",
  "dados": {
    "mensagem": "Dados recebidos com sucesso!",
    "email": "cliente@email.com",
    "marca": "Boutique Diniz",
    "timestamp": "12/02/2026 10:30:45"
  }
}
```

---

## 📡 Endpoints de Notificação

### Notificação de Login

```http
POST /api/clientes/login
Content-Type: application/json

{
  "cpf": "123.456.789-00",
  "senha": "sua_senha"
}
```

**Resposta:**
```json
{
  "success": true,
  "message": "Login realizado com sucesso",
  "data": {
    "id": 1,
    "nome_completo": "João Silva",
    "email": "joao@email.com",
    "cpf": "123.456.789-00"
  }
}
```

### Recuperação de Senha

```http
POST /api/clientes/recuperar-senha
Content-Type: application/json

{
  "cpf": "123.456.789-00"
}
```

**Resposta:**
```json
{
  "success": true,
  "message": "Código enviado para o e-mail cadastrado"
}
```

### Redefinição de Senha

```http
POST /api/clientes/redefinir-senha
Content-Type: application/json

{
  "cpf": "123.456.789-00",
  "codigo": "1234ABC",
  "nova_senha": "nova_senha_segura"
}
```

### Atualização de Status do Pedido

```http
PATCH /api/pedidos/:id/status-pedido
Content-Type: application/json
X-API-TOKEN: seu_token

{
  "status_pedido": "enviado"
}
```

**Statuses Disponíveis:**
- `pendente` - Pedido pendente de confirmação
- `confirmado` - Pedido confirmado
- `processando` - Pedido sendo processado
- `enviado` - Pedido enviado
- `entregue` - Pedido entregue
- `cancelado` - Pedido cancelado
- `devolvido` - Pedido devolvido

### Atualização de Status de Pagamento

```http
PATCH /api/pedidos/:id/status-pagamento
Content-Type: application/json
X-API-TOKEN: seu_token

{
  "status_pagamento": "confirmado"
}
```

**Statuses Disponíveis:**
- `pendente` - Pagamento pendente
- `confirmado` - Pagamento confirmado
- `falhou` - Pagamento falhou
- `reembolsado` - Pagamento reembolsado

---

## 🛡️ Segurança

### Validação de Email

- Todos os emails são validados antes de enviar
- Emails inválidos são registrados em logs

### Criptografia

- Dados sensíveis são criptografados em trânsito (HTTPS)
- Senhas são hasheadas com bcrypt

### Rate Limiting

- Limite de 500 requisições por 15 minutos
- Proteção contra abuso de API

### Auditoria

- Todas as notificações são registradas em logs
- Histórico de envios é mantido no banco de dados

---

## 📊 Banco de Dados

### Tabelas Relacionadas

#### `cliente`
```sql
CREATE TABLE cliente (
  id INTEGER PRIMARY KEY,
  nome_completo TEXT NOT NULL,
  cpf TEXT NOT NULL UNIQUE,
  email TEXT,
  celular TEXT,
  ativo BOOLEAN DEFAULT 1,
  criado_em DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

#### `pedido`
```sql
CREATE TABLE pedido (
  id INTEGER PRIMARY KEY,
  cliente_id INTEGER NOT NULL,
  numero_pedido TEXT UNIQUE,
  status_pedido TEXT DEFAULT 'pendente',
  status_pagamento TEXT DEFAULT 'pendente',
  valor_total DECIMAL(10,2),
  rastreio TEXT,
  criado_em DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (cliente_id) REFERENCES cliente(id)
);
```

#### `recuperacao_senha`
```sql
CREATE TABLE recuperacao_senha (
  id INTEGER PRIMARY KEY,
  cliente_id INTEGER NOT NULL,
  codigo_hash TEXT NOT NULL,
  expira_em DATETIME NOT NULL,
  usado_em DATETIME,
  criado_em DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (cliente_id) REFERENCES cliente(id)
);
```

---

## 🚀 Deployment

### Instalação de Dependências

```bash
npm install
```

### Inicialização do Banco de Dados

```bash
npm run init-db
```

### Iniciar o Servidor

```bash
# Desenvolvimento
npm run dev

# Produção
npm start
```

### Com PM2

```bash
npm run pm2:start
npm run pm2:logs
npm run pm2:stop
```

---

## 📝 Logs

Os logs são armazenados em `./logs/` com os seguintes níveis:

- `error` - Erros críticos
- `warn` - Avisos
- `info` - Informações gerais
- `http` - Requisições HTTP

### Exemplo de Log

```
[2026-02-12T10:30:45.123Z] INFO: Notificação de login enviada
{
  "clienteId": 1,
  "email": "joao@email.com",
  "timestamp": "2026-02-12T10:30:45.123Z"
}
```

---

## 🐛 Troubleshooting

### Email não está sendo enviado

1. Verifique as credenciais SMTP no `.env`
2. Verifique se a porta SMTP está correta (587 para Gmail)
3. Verifique os logs em `./logs/`

### Código de recuperação não chega

1. Verifique se o email do cliente está cadastrado
2. Verifique a pasta de spam
3. Verifique se o serviço SMTP está ativo

### Google Apps Script não recebe dados

1. Verifique a URL do Google Apps Script
2. Verifique se o Apps Script está publicado como Web App
3. Verifique os logs de execução do Apps Script

---

## 📞 Suporte

Para suporte técnico, entre em contato com:

**Atlas Soluções**  
Website: https://www.atlassolutions.com.br  
Email: suporte@atlassolutions.com.br

---

## 📄 Licença

Este sistema é propriedade exclusiva da Boutique Diniz.  
Desenvolvido por Atlas Soluções © 2026

---

**Última atualização:** 12 de Fevereiro de 2026
