@echo off
setlocal enabledelayedexpansion

:: Forçar o diretório de trabalho para a pasta onde o arquivo .bat está
cd /d "%~dp0"

title INSTALADOR BOUTIQUE DINIZ - VERSÃO COMPATIBILIDADE
echo ============================================================
echo   INSTALADOR - BOUTIQUE DINIZ API (WINDOWS x32/x64)
echo ============================================================
echo.
echo Pasta do Projeto: %cd%
echo.

:: 1. Verificar Node.js
node -v >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERRO] Node.js nao encontrado. Verifique sua instalacao.
    pause
    exit /b
)
echo [OK] Node.js detectado.

:: 2. Limpeza preventiva (evitar erro EPERM se rodar denovo)
if exist node_modules (
    echo [AVISO] Pasta node_modules ja existe. Tentando limpar...
    rmdir /s /q node_modules 2>nul
    if exist node_modules (
        echo [ERRO] Nao foi possivel remover a pasta node_modules.
        echo Feche qualquer programa que esteja usando a pasta e tente novamente.
        pause
        exit /b
    )
)

echo.
echo [PASSO 2] Instalando dependencias...
echo Usando versao de compatibilidade para Windows...
call npm install --no-audit --no-fund
if %errorlevel% neq 0 (
    echo.
    echo [ERRO] Falha ao instalar dependencias.
    echo Tente executar o comando: npm install sqlite3
    pause
    exit /b
)
echo [OK] Dependencias instaladas.

echo.
echo [PASSO 3] Inicializando Banco de Dados...
if exist "scripts\init-database.js" (
    node scripts\init-database.js
    if %errorlevel% neq 0 (
        echo.
        echo [ERRO] Falha ao inicializar o banco de dados.
        pause
        exit /b
    )
) else (
    echo [ERRO] Nao encontrei o arquivo scripts\init-database.js
    pause
    exit /b
)

echo.
echo ============================================================
echo   INSTALACAO CONCLUIDA COM SUCESSO!
echo ============================================================
echo Agora voce pode usar o ativa.bat para iniciar o servidor.
echo.
pause
