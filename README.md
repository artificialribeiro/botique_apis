# Boutique Diniz API

Sistema de gestão completo para Boutique Diniz, desenvolvido por **Estúdio Atlas**.

## Visão Geral

API RESTful completa para gestão de loja de roupas, incluindo:

- **Clientes**: Cadastro, login, recuperação de senha
- **Produtos**: Catálogo com variantes (cor/tamanho), imagens
- **Estoque**: Controle de movimentações, alertas de estoque baixo
- **Carrinho**: Gestão de carrinho de compras
- **Pedidos**: Vendas, status, rastreamento
- **Caixa**: Lançamentos financeiros, resumos
- **Cupons**: Descontos por percentual ou valor fixo
- **Banners**: Carrossel do site
- **Notificações**: Sistema de notificações
- **Pós-venda**: Cancelamentos, devoluções, reclamações
- **Backup**: Automático e manual

## Tecnologias

- **Node.js** (v18+)
- **Express.js** - Framework web
- **SQLite** (better-sqlite3) - Banco de dados
- **bcryptjs** - Hash de senhas
- **PM2** - Gerenciador de processos
- **node-cron** - Tarefas agendadas

## Instalação Rápida

```bash
# Clonar ou extrair o projeto
cd boutique-diniz-api

# Executar instalação automatizada
chmod +x scripts/install.sh
./scripts/install.sh

# Iniciar o servidor
npm run pm2:start
```

## Instalação Manual

```bash
# Instalar dependências
npm install

# Copiar e configurar variáveis de ambiente
cp .env.example .env
# Editar .env com suas configurações

# Inicializar banco de dados
npm run init-db

# Iniciar em desenvolvimento
npm run dev

# Ou iniciar em produção com PM2
npm run pm2:start
```

## Estrutura do Projeto

```
boutique-diniz-api/
├── src/
│   ├── config/          # Configurações
│   ├── controllers/     # Controladores das rotas
│   ├── middlewares/     # Middlewares (auth, upload, etc)
│   ├── routes/          # Definição de rotas
│   ├── services/        # Serviços (auditoria, etc)
│   ├── utils/           # Utilitários
│   ├── validators/      # Validadores
│   └── server.js        # Servidor principal
├── scripts/             # Scripts de automação
├── data/                # Bancos de dados e uploads
├── logs/                # Arquivos de log
├── docs/                # Documentação
└── ecosystem.config.js  # Configuração PM2
```

## Bancos de Dados

O sistema utiliza 3 arquivos SQLite separados para maior segurança:

- **core.db**: Operações da loja (clientes, produtos, pedidos, etc)
- **auth.db**: Segurança (usuários do sistema, tokens, permissões)
- **audit.db**: Auditoria (logs de alterações)

## Autenticação

### API Key
Todas as rotas protegidas requerem o header:
```
X-API-KEY: 1526
```

### Token de Integração
Além da API Key, é necessário um token temporário:
```
X-API-TOKEN: <token>
```

Para obter um token:
```bash
curl -X POST http://localhost:3000/api/token \
  -H "X-API-KEY: 1526"
```

## Comandos Úteis

```bash
# Desenvolvimento
npm run dev           # Inicia com nodemon

# Produção (PM2)
npm run pm2:start     # Inicia o servidor
npm run pm2:stop      # Para o servidor
npm run pm2:restart   # Reinicia o servidor
npm run pm2:logs      # Visualiza logs
npm run pm2:status    # Status do processo

# Banco de dados
npm run init-db       # Inicializa/reinicializa o banco

# Backup
npm run backup        # Cria backup manual
npm run restore       # Restaura backup
```

## Backup Automático

O sistema realiza backup automático diariamente às 3h da manhã. Os backups são mantidos por 30 dias (configurável).

Para backup manual:
```bash
npm run backup
```

Para restaurar:
```bash
npm run restore backup_2026-01-24_15-30.zip
```

## Variáveis de Ambiente

Veja o arquivo `.env.example` para todas as variáveis disponíveis.

Principais:
- `PORT`: Porta do servidor (padrão: 3000)
- `API_KEY`: Chave de API (padrão: 1526)
- `TOKEN_SECRET`: Segredo para tokens
- `ENCRYPTION_KEY`: Chave de criptografia (32 caracteres)

## Credenciais Padrão

- **Login**: admin
- **Senha**: admin123

⚠️ **ALTERE A SENHA APÓS O PRIMEIRO LOGIN!**

## Documentação da API

Consulte o arquivo `docs/API_DOCUMENTATION.md` para documentação completa de todas as rotas, parâmetros e exemplos.

## Suporte

Desenvolvido por **Estúdio Atlas**

---

© 2026 Boutique Diniz - Todos os direitos reservados
