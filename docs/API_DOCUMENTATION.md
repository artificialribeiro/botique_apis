# Documentação da API - Boutique Diniz

**Desenvolvido por Estúdio Atlas**

Versão: 1.0.0

---

## Sumário

1.  [Visão Geral](#1-visão-geral)
2.  [Configuração Geral](#2-configuração-geral)
3.  [Padrões de Resposta](#3-padrões-de-resposta)
4.  [Autenticação](#4-autenticação)
5.  [Paginação](#5-paginação)
6.  [Endpoints da API](#6-endpoints-da-api)
    *   [6.1 Sistema](#61-sistema)
    *   [6.2 Clientes](#62-clientes)
    *   [6.3 Endereços](#63-endereços)
    *   [6.4 Produtos](#64-produtos)
    *   [6.5 Variantes](#65-variantes)
    *   [6.6 Estoque](#66-estoque)
    *   [6.7 Carrinho](#67-carrinho)
    *   [6.8 Pedidos](#68-pedidos)
    *   [6.9 Caixa](#69-caixa)
    *   [6.10 Banners](#610-banners)
    *   [6.11 Cupons](#611-cupons)
    *   [6.12 Notificações](#612-notificações)
    *   [6.13 Pós-venda](#613-pós-venda)
    *   [6.14 Reclamações](#614-reclamações)
    *   [6.15 Tema](#615-tema)
    *   [6.16 Backup e Restauração](#616-backup-e-restauração)

---

## 1. Visão Geral

Esta documentação descreve a API RESTful para o sistema de gestão da Boutique Diniz. A API permite a integração com sistemas externos como sites, painéis administrativos e aplicativos móveis.

## 2. Configuração Geral

### Stack

*   **Backend**: Node.js + Express.js
*   **Banco de Dados**: SQLite (3 arquivos: `core.db`, `auth.db`, `audit.db`)
*   **Process Manager**: PM2

### URL Base

```
https://api.boutiquediniz.com
```

*Para ambiente de desenvolvimento, a URL base é `http://localhost:3000`.*

### Headers Padrão

Todas as requisições para rotas protegidas devem incluir os seguintes headers:

| Header        | Descrição                                      | Exemplo                                  |
|---------------|------------------------------------------------|------------------------------------------|
| `Content-Type`| Tipo de conteúdo do corpo da requisição        | `application/json`                       |
| `X-API-KEY`   | Chave de API fixa para identificar a aplicação | `1526`                                   |
| `X-API-TOKEN` | Token de integração temporário                 | `a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4`       |
| `X-User-Id`   | (Opcional) ID do usuário do sistema logado     | `1`                                      |

## 3. Padrões de Resposta

A API utiliza um formato JSON padrão para todas as respostas.

### Resposta de Sucesso

```json
{
  "success": true,
  "message": "Mensagem opcional sobre a operação.",
  "data": { ... } // ou [ ... ]
}
```

Para listagens paginadas, um campo `meta` é adicionado:

```json
{
  "success": true,
  "data": [ ... ],
  "meta": {
    "page": 1,
    "page_size": 20,
    "total": 150,
    "has_next": true
  }
}
```

### Resposta de Erro

```json
{
  "success": false,
  "message": "Descrição amigável do erro.",
  "error": {
    "code": "CODIGO_DO_ERRO",
    "details": [
      { "field": "nome_do_campo", "issue": "Descrição do problema" }
    ]
  }
}
```

**Códigos de Erro Comuns:**

| Código               | Status HTTP | Descrição                                            |
|----------------------|-------------|------------------------------------------------------|
| `VALIDATION_ERROR`   | 400         | Erro nos dados enviados na requisição.               |
| `UNAUTHORIZED`       | 401         | Autenticação falhou (API Key ou Token inválidos).    |
| `FORBIDDEN`          | 403         | Acesso negado à funcionalidade.                      |
| `NOT_FOUND`          | 404         | Recurso ou rota não encontrada.                      |
| `CONFLICT`           | 409         | Conflito de dados (ex: registro duplicado).          |
| `RATE_LIMIT_EXCEEDED`| 429         | Limite de requisições excedido.                      |
| `INTERNAL_ERROR`     | 500         | Erro inesperado no servidor.                         |

## 4. Autenticação

A autenticação é feita em duas camadas:

1.  **API Key**: Uma chave fixa (`X-API-KEY`) que identifica a aplicação cliente.
2.  **Token de Integração**: Um token temporário (`X-API-TOKEN`) que autoriza as operações.

**Fluxo:**

1.  A aplicação cliente faz uma requisição para `POST /api/token` enviando a `X-API-KEY`.
2.  A API retorna um token temporário.
3.  A aplicação cliente utiliza este token no header `X-API-TOKEN` para todas as requisições subsequentes.

## 5. Paginação

Endpoints que retornam listas de dados suportam paginação através de query params:

*   `page`: Número da página (padrão: `1`).
*   `page_size`: Quantidade de itens por página (padrão: `20`, máximo: `100`).

**Exemplo:** `GET /api/produtos?page=2&page_size=50`

---

## 6. Endpoints da API

### 6.1 Sistema

#### Health Check

Verifica o status da API e suas conexões.

*   **Endpoint**: `GET /api/health`
*   **Autenticação**: Nenhuma

**Resposta de Sucesso (200 OK):**
```json
{
  "success": true,
  "message": "Sistema operacional",
  "data": {
    "status": "online",
    "timestamp": "2026-01-24T19:30:00.000Z",
    "version": "1.0.0",
    "environment": "production",
    "databases": {
      "core": "connected",
      "auth": "connected",
      "audit": "connected"
    },
    "developer": "Estúdio Atlas"
  }
}
```

#### Gerar Token de Integração

Gera um token temporário para autenticar as requisições.

*   **Endpoint**: `POST /api/token`
*   **Autenticação**: Apenas `X-API-KEY`

**Headers:**
```
X-API-KEY: 1526
```

**Resposta de Sucesso (200 OK):**
```json
{
  "success": true,
  "message": "Token gerado com sucesso",
  "data": {
    "token": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
    "expires_in_seconds": 900
  }
}
```

### 6.2 Clientes

#### Login do Cliente

Autentica um cliente com CPF e senha.

*   **Endpoint**: `POST /api/clientes/login`
*   **Autenticação**: Completa (`X-API-KEY` + `X-API-TOKEN`)

**Corpo da Requisição:**
```json
{
  "cpf": "123.456.789-00",
  "senha": "Senha@123"
}
```

**Resposta de Sucesso (200 OK):**
```json
{
  "success": true,
  "message": "Login realizado com sucesso",
  "data": {
    "id": 1,
    "nome_completo": "Maria da Silva",
    "cpf": "12345678900",
    "email": "maria@email.com",
    "celular": "28999999999",
    "ativo": 1
  }
}
```

#### Criar Cliente

Cadastra um novo cliente.

*   **Endpoint**: `POST /api/clientes`
*   **Autenticação**: Completa

**Corpo da Requisição:**
```json
{
  "nome_completo": "João Ninguém",
  "cpf": "987.654.321-00",
  "email": "joao@email.com",
  "celular": "28988888888",
  "sexo": "M",
  "senha": "NovaSenha@2026"
}
```

**Resposta de Sucesso (201 Created):**
```json
{
  "success": true,
  "message": "Cliente criado com sucesso",
  "data": {
    "id": 2,
    "nome_completo": "João Ninguém",
    "cpf": "98765432100",
    "email": "joao@email.com",
    "celular": "28988888888",
    "sexo": "M",
    "ativo": 1,
    "criado_em": "2026-01-24T20:00:00.000Z",
    "atualizado_em": null
  }
}
```

#### Listar Clientes

Retorna uma lista paginada de clientes.

*   **Endpoint**: `GET /api/clientes`
*   **Autenticação**: Completa

**Query Params:**
*   `page`, `page_size`: Para paginação.
*   `q`: Termo de busca (nome, email, celular).
*   `ativo`: `1` para ativos, `0` para inativos.

**Exemplo:** `GET /api/clientes?q=Silva&ativo=1`

**Resposta de Sucesso (200 OK):**
```json
{
  "success": true,
  "data": [
    {
      "id": 1,
      "nome_completo": "Maria da Silva",
      "cpf": "12345678900",
      "email": "maria@email.com",
      "celular": "28999999999",
      "sexo": "F",
      "ativo": 1,
      "criado_em": "2026-01-24T19:30:00.000Z"
    }
  ],
  "meta": {
    "page": 1,
    "page_size": 20,
    "total": 1,
    "has_next": false
  }
}
```

*(Outros endpoints de Clientes como `GET /:id`, `PUT /:id`, `DELETE /:id`, `recuperar-senha` e `redefinir-senha` seguem o padrão RESTful)*

### 6.3 Endereços

#### Criar Endereço

Adiciona um novo endereço para um cliente.

*   **Endpoint**: `POST /api/clientes/:id/enderecos`
*   **Autenticação**: Completa

**Parâmetros de URL:**
*   `id`: ID do cliente.

**Corpo da Requisição:**
```json
{
  "tipo": "casa",
  "rua": "Rua das Flores",
  "numero": "123",
  "bairro": "Centro",
  "cidade": "Divinópolis",
  "estado": "MG",
  "cep": "35500-000",
  "principal": 1
}
```

**Resposta de Sucesso (201 Created):**
```json
{
  "success": true,
  "message": "Endereço criado com sucesso",
  "data": {
    "id": 1,
    "cliente_id": 1,
    "tipo": "casa",
    "rua": "Rua das Flores",
    "numero": "123",
    "bairro": "Centro",
    "cidade": "Divinópolis",
    "estado": "MG",
    "cep": "35500-000",
    "principal": 1,
    "criado_em": "2026-01-24T20:15:00.000Z"
  }
}
```

*(Outros endpoints de Endereços como `GET`, `PUT`, `DELETE` seguem o padrão RESTful)*

### 6.4 Produtos

#### Listar Produtos

Retorna uma lista paginada de produtos.

*   **Endpoint**: `GET /api/produtos`
*   **Autenticação**: Completa

**Query Params:**
*   `page`, `page_size`: Para paginação.
*   `q`: Termo de busca (nome, SKU, descrição).
*   `ativo`: `1` para ativos, `0` para inativos.
*   `filial_id`: Filtrar por filial.

**Resposta de Sucesso (200 OK):**
```json
{
  "success": true,
  "data": [
    {
      "id": 101,
      "sku": "CF-01-P",
      "nome": "Camisa Floral",
      "preco": 129.90,
      "ativo": 1,
      "imagens": [
        {
          "id": 201,
          "caminho": "/uploads/produtos/img1.webp",
          "ordem": 1
        }
      ]
    }
  ],
  "meta": { ... }
}
```

#### Buscar Produto por ID

Retorna os detalhes de um produto, incluindo suas variantes e imagens.

*   **Endpoint**: `GET /api/produtos/:id`
*   **Autenticação**: Completa

**Resposta de Sucesso (200 OK):**
```json
{
  "success": true,
  "data": {
    "id": 101,
    "sku": "CF-01-P",
    "nome": "Camisa Floral",
    "descricao": "Camisa de algodão com estampa floral.",
    "preco": 129.90,
    "ativo": 1,
    "variantes": [
      {
        "id": 301,
        "produto_id": 101,
        "tamanho": "M",
        "cor": "Azul",
        "estoque": 50
      }
    ],
    "imagens": [
      {
        "id": 201,
        "caminho": "/uploads/produtos/img1.webp",
        "ordem": 1
      }
    ]
  }
}
```

*(Outros endpoints de Produtos como `POST`, `PUT`, `PATCH /status`, `POST /imagens` seguem o padrão RESTful)*

### 6.5 Variantes

#### Criar Variante

Cria uma variante (tamanho/cor) para um produto.

*   **Endpoint**: `POST /api/produtos/:id/variantes`
*   **Autenticação**: Completa

**Corpo da Requisição:**
```json
{
  "tamanho": "G",
  "cor": "Preto",
  "estoque": 30,
  "estoque_minimo": 5
}
```

**Resposta de Sucesso (201 Created):**
```json
{
  "success": true,
  "message": "Variante criada com sucesso",
  "data": {
    "id": 302,
    "produto_id": 101,
    "tamanho": "G",
    "cor": "Preto",
    "estoque": 30,
    "estoque_minimo": 5,
    "ativo": 1
  }
}
```

### 6.6 Estoque

#### Registrar Movimento de Estoque

Registra uma entrada, saída ou ajuste no estoque de uma variante.

*   **Endpoint**: `POST /api/estoque/movimentos`
*   **Autenticação**: Completa

**Corpo da Requisição:**
```json
{
  "produto_variante_id": 301,
  "tipo": "entrada",
  "quantidade": 100,
  "motivo": "Recebimento de fornecedor",
  "usuario_id": 1
}
```

**Resposta de Sucesso (201 Created):**
```json
{
  "success": true,
  "message": "Movimento registrado com sucesso",
  "data": {
    "id": 501,
    "produto_variante_id": 301,
    "tipo": "entrada",
    "quantidade": 100,
    "estoque_anterior": 50,
    "estoque_atual": 150
  }
}
```

### 6.7 Carrinho

#### Adicionar Item ao Carrinho

*   **Endpoint**: `POST /api/carrinho`
*   **Autenticação**: Completa

**Corpo da Requisição:**
```json
{
  "cliente_id": 1,
  "produto_variante_id": 301,
  "quantidade": 2
}
```

#### Listar Carrinho

*   **Endpoint**: `GET /api/carrinho/:cliente_id`
*   **Autenticação**: Completa

**Resposta de Sucesso (200 OK):**
```json
{
  "success": true,
  "data": {
    "itens": [
      {
        "id": 701,
        "cliente_id": 1,
        "produto_variante_id": 301,
        "quantidade": 2,
        "produto_nome": "Camisa Floral",
        "preco_final": 129.90,
        "total_item": 259.80
      }
    ],
    "resumo": {
      "subtotal": 259.80,
      "desconto_total": 0,
      "total": 259.80
    }
  }
}
```

### 6.8 Pedidos

#### Criar Pedido

Cria um pedido a partir do carrinho do cliente.

*   **Endpoint**: `POST /api/pedidos`
*   **Autenticação**: Completa

**Corpo da Requisição:**
```json
{
  "cliente_id": 1,
  "filial_origem_id": 1,
  "endereco_entrega_id": 1,
  "pagamento_tipo": "pix",
  "pagamento_id_externo": "PAY-123456",
  "pagamento_status_detalhado": "approved",
  "frete": 15.50,
  "cupom_codigo": "BEMVINDO10"
}
```

**Resposta de Sucesso (201 Created):**
```json
{
  "success": true,
  "message": "Pedido criado com sucesso",
  "data": {
    "id": 1001,
    "cliente_id": 1,
    "status_pedido": "novo",
    "status_pagamento": "aguardando",
    "total": 249.32,
    "itens": [ ... ]
  }
}
#### Atualizar Status de Pagamento

*   **Endpoint**: `PATCH /api/pedidos/:id/status-pagamento`
*   **Autenticação**: Completa

**Corpo da Requisição:**
```json
{
  "status_pagamento": "pago",
  "pagamento_id_externo": "PAY-123456",
  "pagamento_status_detalhado": "approved"
}
```
### 6.9 Caixa

#### Criar Lançamento no Caixa

*   **Endpoint**: `POST /api/caixa/lancamentos`
*   **Autenticação**: Completa

**Corpo da Requisição:**
```json
{
  "filial_id": 2,
  "tipo": "entrada",
  "descricao": "Venda balcão - Camisa",
  "valor": 129.90,
  "forma_pagamento": "credito",
  "usuario_vendedor_id": 3,
  "origem": "loja"
}
```

### 6.10 Banners

#### Criar Banner

*   **Endpoint**: `POST /api/banners`
*   **Autenticação**: Completa
*   **Content-Type**: `multipart/form-data`

**Corpo da Requisição (form-data):**
*   `imagem`: Arquivo de imagem
*   `titulo`: (Opcional) Título do banner
*   `link`: (Opcional) Link de destino
*   `ordem`: (Opcional) Ordem de exibição

### 6.11 Cupons

#### Validar Cupom

*   **Endpoint**: `POST /api/cupons/validar`
*   **Autenticação**: Completa

**Corpo da Requisição:**
```json
{
  "codigo": "BEMVINDO10",
  "valor_carrinho": 259.80
}
```

**Resposta de Sucesso (200 OK):**
```json
{
  "success": true,
  "message": "Cupom válido",
  "data": {
    "valido": true,
    "desconto": 25.98,
    "valor_final": 233.82
  }
}
```

### 6.12 Notificações

*(Endpoints `POST`, `GET`, `PUT` seguem o padrão RESTful)*

### 6.13 Pós-venda

*(Endpoints `POST`, `GET`, `PATCH` seguem o padrão RESTful)*

### 6.14 Reclamações

*(Endpoints `POST`, `GET`, `PUT` seguem o padrão RESTful)*

### 6.15 Tema

#### Obter Tema

Retorna as configurações visuais do site/app.

*   **Endpoint**: `GET /api/tema`
*   **Autenticação**: Completa

### 6.16 Backup e Restauração

#### Criar Backup

*   **Endpoint**: `POST /api/backup`
*   **Autenticação**: Completa

**Resposta de Sucesso (200 OK):**
```json
{
  "success": true,
  "message": "Backup criado com sucesso",
  "data": {
    "arquivo": "backup_2026-01-24_21-00-00.zip",
    "tamanho_mb": "5.73"
  }
}
```

#### Restaurar Backup

*   **Endpoint**: `POST /api/restore`
*   **Autenticação**: Completa
*   **Content-Type**: `multipart/form-data`

**Corpo da Requisição (form-data):**
*   `arquivo`: Arquivo `.zip` do backup.

---

© 2026 Boutique Diniz - Desenvolvido por Estúdio Atlas
