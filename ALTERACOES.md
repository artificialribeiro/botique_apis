# 📝 Resumo de Alterações - Boutique Diniz API

**Última atualização:** 14 de Fevereiro de 2026  
**Desenvolvido por:** Atlas Soluções  
**Versão:** 1.0.1

---

## 🐛 CORREÇÃO CRÍTICA — v1.0.1 (14/02/2026)

### Bug: "CPF já existe" em banco vazio

**Causa raiz:** O arquivo `src/config/sqlite-compat.js` implementava uma camada de
compatibilidade que envolvia a biblioteca `sqlite3` (assíncrona, baseada em callbacks/Promises).
No entanto, **todos os controllers** foram escritos para `better-sqlite3` (síncrona), chamando
`.get()`, `.run()` e `.all()` como operações síncronas, sem `await`.

O resultado era que cada chamada ao banco retornava uma **Promise pendente** — que em JavaScript
é um objeto truthy — em vez de `null` ou `undefined`. Portanto, a verificação:

```js
const existente = coreDb.prepare('SELECT id FROM cliente WHERE cpf_hash = ?').get(cpfHash);
if (existente) { /* CPF já existe */ }
```

...era **sempre verdadeira**, independentemente do conteúdo do banco. O cadastro de qualquer
cliente era rejeitado com "CPF já cadastrado", mesmo com o banco completamente vazio.
O mesmo problema afetava todas as operações de leitura e escrita em todos os controllers.

**Solução:** Substituído o conteúdo de `sqlite-compat.js` para simplesmente re-exportar
`better-sqlite3`, que opera de forma 100% síncrona. A API pública é idêntica, portanto
**nenhum controller precisou ser alterado**. Atualizada a dependência no `package.json`
de `"sqlite3": "^5.1.7"` para `"better-sqlite3": "^9.4.3"`.

**Arquivos alterados:**
- `src/config/sqlite-compat.js` — Reescrito (correção do bug)
- `package.json` — Dependência atualizada de sqlite3 → better-sqlite3

---

### Melhoria: Configuração de Backup Automático

Ajustadas as configurações de backup conforme solicitado:

- **Frequência:** Backup geral a cada **4 dias** às 03h00 (era: diário)
  - Cron: `0 3 */4 * *`
- **Retenção:** Backups com mais de **7 dias** são excluídos automaticamente (era: 30 dias)

O processo de limpeza já existente (`limparBackupsAntigos`, executado diariamente às 04h)
usa automaticamente o valor de `BACKUP_RETENTION_DAYS`, portanto nenhuma alteração de código
foi necessária além da configuração.

**Arquivos alterados:**
- `.env` — `BACKUP_RETENTION_DAYS=7`, `BACKUP_CRON_SCHEDULE=0 3 */4 * *`
- `.env.example` — Mesmos valores, com comentários explicativos
- `src/server.js` — Mensagem de console atualizada

---



## 🎯 Objetivo

Implementar um sistema completo de notificações por email integrado com Google Apps Script, ajustar a porta do servidor para 1535, otimizar para dados em massa e adicionar branding da Atlas Soluções.

---

## ✅ Alterações Realizadas

### 1️⃣ Sistema de Notificações por Email

#### Novo Arquivo: `src/services/notificacaoService.js`

Serviço centralizado para gerenciar todas as notificações:

- **notificarLogin()** - Envia notificação quando cliente faz login
- **notificarRecuperacaoSenha()** - Envia código de recuperação (4 números + 3 letras)
- **notificarAtualizacaoPedido()** - Envia notificação de alteração de status do pedido
- **notificarPromocao()** - Envia notificação de promoções e descontos
- **notificarAtualizacaoDados()** - Envia notificação de alteração de dados cadastrais
- **enviarViaGoogleAppsScript()** - Integração com Google Apps Script

#### Características

✅ Integração com Google Apps Script  
✅ Fallback para email direto (SMTP)  
✅ Emails HTML formatados  
✅ Tratamento de erros robusto  
✅ Logging detalhado  
✅ Suporte a múltiplos tipos de notificação  

### 2️⃣ Integração com Controllers

#### Arquivo Modificado: `src/controllers/clienteController.js`

```javascript
// Login - Notificação automática
notificacaoService.notificarLogin({...})

// Recuperação de senha - Envia código
notificacaoService.notificarRecuperacaoSenha(cliente, codigo)
```

#### Arquivo Modificado: `src/controllers/pedidoController.js`

```javascript
// Atualização de status do pedido
notificacaoService.notificarAtualizacaoPedido(pedido, statusAnterior, statusNovo)

// Atualização de status de pagamento
notificacaoService.notificarAtualizacaoPedido(pedido, 'pagamento_' + statusAnterior, 'pagamento_' + statusNovo)
```

### 3️⃣ Configurações Atualizadas

#### Arquivo Modificado: `.env`

**Porta do Servidor:**
```env
PORT=1535  # Alterado de 3000 para 1535
```

**Google Apps Script:**
```env
GOOGLE_APPS_SCRIPT_URL=https://script.google.com/macros/s/AKfycbxmWQYuR6oxsj7fD1yeUQ0UIdw8_nC_GrAF-ZxKuy5kxSFsJvsBXbW-N8kvT8Q2MGCk/exec
```

**Otimizações para Dados em Massa:**
```env
UPLOAD_MAX_SIZE_MB=50          # Aumentado de 10 para 50
RATE_LIMIT_MAX_REQUESTS=500    # Aumentado de 100 para 500
MAX_BODY_SIZE=50mb
MAX_QUERY_SIZE=10000
CONNECTION_POOL_SIZE=20
```

**Branding - Atlas Soluções:**
```env
BRAND_NAME=Boutique Diniz
BRAND_DEVELOPER=Atlas Soluções
BRAND_YEAR=2026
BRAND_WEBSITE=https://www.atlassolutions.com.br
```

#### Arquivo Modificado: `src/config/index.js`

Adicionadas novas configurações:

```javascript
// SMTP (alias para compatibilidade)
smtp: {
  host: process.env.SMTP_HOST,
  port: parseInt(process.env.SMTP_PORT, 10),
  secure: process.env.SMTP_SECURE === 'true',
  user: process.env.SMTP_USER,
  pass: process.env.SMTP_PASS,
  from: process.env.EMAIL_FROM
}

// Google Apps Script
googleAppsScript: {
  url: process.env.GOOGLE_APPS_SCRIPT_URL
}

// Otimizações para dados em massa
performance: {
  maxBodySize: process.env.MAX_BODY_SIZE,
  maxQuerySize: parseInt(process.env.MAX_QUERY_SIZE, 10),
  connectionPoolSize: parseInt(process.env.CONNECTION_POOL_SIZE, 10)
}

// Branding
brand: {
  name: process.env.BRAND_NAME,
  developer: process.env.BRAND_DEVELOPER,
  year: process.env.BRAND_YEAR,
  website: process.env.BRAND_WEBSITE
}
```

### 4️⃣ Servidor Principal Atualizado

#### Arquivo Modificado: `src/server.js`

**Otimizações:**
```javascript
// Limite de body aumentado
app.use(express.json({ limit: config.performance.maxBodySize }));
app.use(express.urlencoded({ extended: true, limit: config.performance.maxBodySize }));
```

**Branding:**
```javascript
// Resposta da API raiz
app.get('/', (req, res) => {
  res.json({
    message: config.brand.name + ' API',
    developer: config.brand.developer,
    website: config.brand.website
  });
});
```

**Mensagem de Inicialização:**
```
╔════════════════════════════════════════════════════════════╗
║                  Boutique Diniz API                        ║
║                 Desenvolvido por Atlas Soluções            ║
╠════════════════════════════════════════════════════════════╣
║  Status: ✅ Online                                         ║
║  Ambiente: production                                      ║
║  Porta: 1535                                               ║
║  URL: http://0.0.0.0:1535                                  ║
╠════════════════════════════════════════════════════════════╣
║  Tarefas agendadas:                                        ║
║  • Backup automático: 0 3 * * *                            ║
║  • Limpeza de tokens: a cada hora                          ║
║  • Limpeza de backups: diariamente às 4h                   ║
║  • Notificações: Email e Google Apps Script                ║
╚════════════════════════════════════════════════════════════╝
```

### 5️⃣ Documentação

#### Novo Arquivo: `NOTIFICACOES.md`

Documentação completa do sistema de notificações:

- Tipos de notificações
- Configuração de email
- Integração com Google Apps Script
- Endpoints disponíveis
- Segurança
- Troubleshooting

#### Novo Arquivo: `SETUP.md`

Guia de instalação e configuração:

- Pré-requisitos
- Instalação rápida
- Configuração de email
- Banco de dados
- Segurança
- Deployment
- Monitoramento
- Troubleshooting

#### Novo Arquivo: `ALTERACOES.md`

Este arquivo - resumo de todas as mudanças realizadas.

---

## 📊 Tipos de Notificações Implementadas

### 1. Login
- ✅ Notificação ao fazer login
- ✅ Registro de IP e navegador
- ✅ Email formatado

### 2. Recuperação de Senha
- ✅ Código de 4 números + 3 letras
- ✅ Validade de 30 minutos
- ✅ Email com código

### 3. Atualização de Pedidos
- ✅ Notificação de mudança de status
- ✅ Informações do pedido
- ✅ Código de rastreio

### 4. Promoções
- ✅ Notificação de promoções
- ✅ Código de cupom
- ✅ Datas de validade

### 5. Atualização de Dados
- ✅ Notificação de alteração cadastral
- ✅ Campos alterados
- ✅ Segurança

### 6. Pagamento
- ✅ Notificação de status de pagamento
- ✅ Confirmação de transação
- ✅ Informações de pedido

---

## 🔌 Integração Google Apps Script

### URL Configurada
```
https://script.google.com/macros/s/AKfycbxmWQYuR6oxsj7fD1yeUQ0UIdw8_nC_GrAF-ZxKuy5kxSFsJvsBXbW-N8kvT8Q2MGCk/exec
```

### Funcionalidade
- Recebe dados de notificações
- Registra em planilha Google Sheets
- Fallback para email direto
- Tratamento de erros

---

## 🚀 Otimizações para Dados em Massa

### Configurações Aplicadas

| Configuração | Antes | Depois | Benefício |
|---|---|---|---|
| Upload Max | 10 MB | 50 MB | Suporta arquivos maiores |
| Rate Limit | 100 req/15min | 500 req/15min | Mais requisições simultâneas |
| Body Size | 10 MB | 50 MB | Dados mais volumosos |
| Query Size | N/A | 10.000 | Paginação eficiente |
| Pool Conexões | N/A | 20 | Melhor concorrência |

### Índices do Banco de Dados
- `idx_cliente_cpf` - Busca rápida por CPF
- `idx_cliente_email` - Busca rápida por email
- `idx_pedido_cliente` - Pedidos por cliente
- `idx_pedido_status` - Pedidos por status

---

## 🎨 Branding - Atlas Soluções

### Implementações

1. **Resposta da API**
   ```json
   {
     "message": "Boutique Diniz API",
     "developer": "Atlas Soluções",
     "website": "https://www.atlassolutions.com.br"
   }
   ```

2. **Emails**
   - Logo da Boutique Diniz
   - Rodapé com "Desenvolvido por Atlas Soluções"
   - Link para website

3. **Logs**
   - Mensagens incluem nome da marca
   - Identificação clara do desenvolvedor

4. **Mensagens de Inicialização**
   - Banner com nome da marca
   - Créditos ao desenvolvedor

---

## 🔐 Segurança Implementada

### Validações
- ✅ Validação de email
- ✅ Validação de CPF
- ✅ Validação de formato JSON
- ✅ Validação de token

### Criptografia
- ✅ Senhas com bcrypt
- ✅ Dados sensíveis com AES-256-GCM
- ✅ HTTPS em produção

### Rate Limiting
- ✅ 500 requisições por 15 minutos
- ✅ Proteção contra abuso

### Auditoria
- ✅ Logs de todas as notificações
- ✅ Histórico de alterações
- ✅ Rastreamento de login

---

## 📦 Dependências Adicionadas

```json
{
  "axios": "^1.6.0"
}
```

Axios foi adicionado para requisições HTTP ao Google Apps Script.

---

## 🧪 Testes Recomendados

### 1. Teste de Login
```bash
curl -X POST http://localhost:1535/api/clientes/login \
  -H "Content-Type: application/json" \
  -H "X-API-TOKEN: seu_token" \
  -d '{"cpf": "123.456.789-00", "senha": "senha123"}'
```

### 2. Teste de Recuperação de Senha
```bash
curl -X POST http://localhost:1535/api/clientes/recuperar-senha \
  -H "Content-Type: application/json" \
  -H "X-API-TOKEN: seu_token" \
  -d '{"cpf": "123.456.789-00"}'
```

### 3. Teste de Atualização de Pedido
```bash
curl -X PATCH http://localhost:1535/api/pedidos/1/status-pedido \
  -H "Content-Type: application/json" \
  -H "X-API-TOKEN: seu_token" \
  -d '{"status_pedido": "enviado"}'
```

---

## 📋 Checklist de Implementação

- ✅ Serviço de notificações criado
- ✅ Integração com Google Apps Script
- ✅ Fallback para email direto
- ✅ Controllers atualizados
- ✅ Configurações atualizadas
- ✅ Porta alterada para 1535
- ✅ Otimizações para dados em massa
- ✅ Branding da Atlas Soluções
- ✅ Documentação completa
- ✅ Dependências instaladas

---

## 🚀 Próximos Passos

1. Configurar credenciais SMTP no `.env`
2. Testar envio de emails
3. Configurar Google Apps Script
4. Fazer backup do banco de dados
5. Fazer deploy em produção
6. Monitorar logs
7. Coletar feedback dos usuários

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
