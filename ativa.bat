@echo off
setlocal enabledelayedexpansion

:: Forçar o diretório de trabalho para a pasta onde o arquivo .bat está
cd /d "%~dp0"

title ATIVADOR BOUTIQUE DINIZ
echo ============================================================
echo   ATIVADOR - BOUTIQUE DINIZ API
echo ============================================================
echo.
echo Pasta atual: %cd%
echo.

:: Verificar Node_modules
if not exist node_modules (
    echo [ERRO] Pasta node_modules nao encontrada!
    echo Por favor, execute o arquivo INSTALAR.BAT primeiro.
    echo.
    pause
    exit /b
)

:: Verificar se o banco de dados já foi inicializado
if not exist data\core.db (
    echo [AVISO] Banco de dados nao detectado. 
    echo Tentando inicializar automaticamente...
    if exist scripts\init-database.js (
        node scripts\init-database.js
    ) else (
        echo [ERRO] Nao foi possivel encontrar o script de inicializacao.
        echo Por favor, execute o INSTALAR.BAT.
        pause
        exit /b
    )
)

echo.
echo [1/1] Iniciando Servidor...
echo.

:: Iniciar o servidor usando o script start do package.json ou direto via node
if exist package.json (
    call npm start
) else (
    node src/server.js
)

if %errorlevel% neq 0 (
    echo.
    echo [ERRO] O servidor parou inesperadamente. 
    echo Verifique se a porta 3000 ja esta em uso ou se ha erros no console acima.
)

echo.
pause
