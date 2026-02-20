#!/bin/bash
# ============================================
# BOUTIQUE DINIZ API - Script de Desinstalação
# Desenvolvido por Estúdio Atlas
# ============================================

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║       BOUTIQUE DINIZ API - Desinstalação                   ║"
echo "║                 Desenvolvido por Estúdio Atlas             ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

read -p "⚠️  Tem certeza que deseja desinstalar? (s/N): " confirm

if [ "$confirm" != "s" ] && [ "$confirm" != "S" ]; then
    echo "Operação cancelada."
    exit 0
fi

echo ""
echo "[INFO] Parando serviço PM2..."
pm2 stop boutique-diniz-api 2>/dev/null || true
pm2 delete boutique-diniz-api 2>/dev/null || true

read -p "Deseja remover os dados (banco de dados e uploads)? (s/N): " remove_data

if [ "$remove_data" = "s" ] || [ "$remove_data" = "S" ]; then
    echo "[INFO] Removendo dados..."
    rm -rf data/*.db
    rm -rf data/uploads/*
    echo "[INFO] Dados removidos."
else
    echo "[INFO] Dados mantidos."
fi

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║              ✅ DESINSTALAÇÃO CONCLUÍDA!                   ║"
echo "╠════════════════════════════════════════════════════════════╣"
echo "║                                                            ║"
echo "║  O serviço foi parado e removido do PM2.                   ║"
echo "║                                                            ║"
echo "║  Para remover completamente, delete a pasta do projeto:    ║"
echo "║  rm -rf /caminho/para/boutique-diniz-api                   ║"
echo "║                                                            ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
