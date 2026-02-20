# Boutique Diniz API — CHANGELOG v3.0

## Correções de Erros Críticos

### 1. Erro ao Listar Produtos (`Cannot destructure property 'total'`)
- **Arquivo:** `src/controllers/produtoController.js`
- **Causa:** A query de contagem usava `sql.replace()` com regex frágil que falhava silenciosamente, retornando `undefined`.
- **Correção:** Substituída por query independente `SELECT COUNT(*) as total` com extração segura do `WHERE` via `sql.substring()`. Adicionado fallback `countResult ? countResult.total : 0`.

### 2. Coluna Inexistente no Estoque (`referencia_tipo`)
- **Arquivo:** `scripts/init-database.js` + `src/controllers/estoqueController.js`
- **Causa:** O controller usava colunas `referencia_tipo` e `referencia_id` que não existiam na tabela `estoque_movimento`.
- **Correção:** Adicionadas as colunas `referencia_tipo TEXT` e `referencia_id INTEGER` na tabela `estoque_movimento` no schema do banco.

### 3. Violação NOT NULL no Caixa (`filial_id`)
- **Arquivo:** `src/controllers/caixaController.js`
- **Causa:** Lançamentos de caixa eram criados sem `filial_id`, que é obrigatório.
- **Correção:** O controller agora valida `filial_id` obrigatório e retorna erro claro se ausente.

### 4. Erro de Banner (`caminho_imagem` vs `imagem_caminho`)
- **Arquivo:** `src/controllers/conteudoController.js` + `scripts/init-database.js`
- **Causa:** O controller usava `caminho_imagem` mas a tabela tinha `imagem_caminho`.
- **Correção:** Padronizado para `caminho_imagem` tanto no schema quanto no controller.

### 5. Login Admin (senha 1526 não funcionava)
- **Arquivo:** `src/controllers/adminController.js`
- **Causa:** O controller usava `async/await` em funções do `better-sqlite3` (que é síncrono), causando comportamento inesperado.
- **Correção:** Removido `async/await` de todas as funções. Login com senha `1526` agora funciona corretamente.

### 6. Queries de Contagem em Todos os Controllers
- **Arquivos:** `produtoController.js`, `pedidoController.js`, `caixaController.js`, `financeiroController.js`
- **Causa:** Todas usavam `sql.replace()` com regex que falhava quando o SELECT tinha formato diferente do esperado.
- **Correção:** Todas substituídas por queries independentes com extração segura do `WHERE`.

### 7. Schema do Banco Desalinhado
- **Arquivo:** `scripts/init-database.js`
- **Causa:** Diversas tabelas faltavam colunas usadas pelos controllers (cupom, notificação, pós-venda, reclamação, financeiro, etc.).
- **Correção:** Reescrito completamente o `init-database.js` com 25+ tabelas no CORE.DB e 11 tabelas no AUTH.DB, todas alinhadas com os controllers.

### 8. Trust Proxy
- **Arquivo:** `src/server.js`
- **Causa:** Rate limiter falhava atrás de proxy reverso (Nginx/Cloudflare).
- **Correção:** Adicionado `app.set('trust proxy', 1)`.

---

## Novas Funcionalidades

### 9. Regra de Caixa Flexível
- **Antes:** Não era possível abrir novo caixa enquanto houvesse outro com status `pendente_aprovacao`.
- **Agora:** Só bloqueia se houver caixa com status `aberto`. Caixas `pendente_aprovacao` NÃO bloqueiam abertura de novo caixa.
- **Melhoria:** `buscarSessao` agora retorna dados completos: valor de abertura, lançamentos detalhados, totais calculados em tempo real.

### 10. API Webhook (`webhookService.js` + `webhookController.js`)
- **Endpoints:**
  - `GET /api/webhook/config` — Ver configuração
  - `PUT /api/webhook/config` — Configurar URL e secret
  - `POST /api/webhook/testar` — Enviar evento de teste
  - `GET /api/webhook/logs` — Consultar logs de envio
  - `POST /api/webhook/callback/dispositivo` — Callback de aprovação de dispositivo
- **Eventos disparados automaticamente:**
  - `cliente.recuperacao_senha` — Com código, email e telefone
  - `cliente.dados_atualizados`
  - `pedido.criado`, `pedido.status_atualizado`, `pedido.pagamento_confirmado`
  - `funcionario.recuperacao_senha` — Com código, email e telefone
  - `dispositivo.autenticacao_solicitada/aprovada/rejeitada`
  - `caixa.aberto`, `caixa.fechado`, `caixa.aprovado`
- **Segurança:** Assinatura HMAC-SHA256 no header `X-Webhook-Signature`
- **Retry:** Até 3 tentativas com delay progressivo

### 11. Campo Telefone em Funcionários
- **Tabela:** `usuario_sistema` agora tem campo `telefone TEXT`
- **Uso:** Recuperação de senha envia email E telefone via webhook

### 12. Recuperação de Senha de Funcionários
- **Endpoints:**
  - `POST /api/admin/funcionarios/recuperar-senha` — Gera código de 6 dígitos
  - `POST /api/admin/funcionarios/redefinir-senha` — Redefine com código válido
- **Fluxo:** Gera código → salva hash no banco → dispara webhook com código + email/telefone → serviço externo envia SMS/email

### 13. Autenticação de Dispositivos (`dispositivoController.js`)
- **Fluxo:**
  1. `POST /api/dispositivos/solicitar` — Funcionário solicita (envia `dispositivo_id` + `funcionario_id`)
  2. Webhook dispara para o dono com IP, user-agent e nome do funcionário
  3. Dono aprova via `POST /api/webhook/callback/dispositivo`
  4. Token persistente é gerado e retornado
  5. Requisições futuras usam `X-Device-Token` no header
  6. `GET /api/dispositivos/validar` — Valida token sem reautenticar
- **Endpoints adicionais:**
  - `GET /api/dispositivos/status/:id` — Consultar status
  - `DELETE /api/dispositivos/:id/revogar` — Revogar acesso
  - `GET /api/dispositivos` — Listar todos (admin)

---

## Arquivos Modificados/Criados

| Arquivo | Ação |
|---------|------|
| `scripts/init-database.js` | Reescrito (schema completo) |
| `src/controllers/produtoController.js` | Corrigido (query contagem) |
| `src/controllers/estoqueController.js` | Corrigido (colunas) |
| `src/controllers/caixaController.js` | Corrigido (regra + dados completos) |
| `src/controllers/conteudoController.js` | Corrigido (banner) |
| `src/controllers/financeiroController.js` | Corrigido (queries contagem) |
| `src/controllers/pedidoController.js` | Corrigido (query contagem) |
| `src/controllers/adminController.js` | Reescrito (login + recuperação senha) |
| `src/controllers/webhookController.js` | **NOVO** |
| `src/controllers/dispositivoController.js` | **NOVO** |
| `src/services/webhookService.js` | **NOVO** |
| `src/routes/index.js` | Atualizado (novas rotas) |
| `src/server.js` | Corrigido (trust proxy) |

---

## Instalação

```bash
npm install
node scripts/init-database.js
node src/server.js
```

Login admin: senha `1526`
Login funcionário padrão: `admin` / `admin123`
