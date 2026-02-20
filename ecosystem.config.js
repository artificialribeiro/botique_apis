/**
 * BOUTIQUE DINIZ API - Configuração PM2
 * Desenvolvido por Estúdio Atlas
 * 
 * Este arquivo configura o PM2 para:
 * - Reinício automático em caso de falha
 * - Reinício automático quando o servidor reiniciar
 * - Gerenciamento de logs
 * - Monitoramento de memória
 */

module.exports = {
  apps: [
    {
      name: 'boutique-diniz-api',
      script: './src/server.js',
      cwd: __dirname,
      
      // Configurações de instância
      instances: 1,
      exec_mode: 'fork',
      
      // Variáveis de ambiente
      env: {
        NODE_ENV: 'development',
        PORT: 3000
      },
      env_production: {
        NODE_ENV: 'production',
        PORT: 3000
      },
      
      // Reinício automático
      autorestart: true,
      watch: false,
      max_memory_restart: '500M',
      
      // Configurações de reinício
      restart_delay: 4000,
      max_restarts: 10,
      min_uptime: '10s',
      
      // Logs
      log_file: './logs/combined.log',
      out_file: './logs/out.log',
      error_file: './logs/error.log',
      log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
      merge_logs: true,
      
      // Rotação de logs
      log_type: 'json',
      
      // Graceful shutdown
      kill_timeout: 5000,
      listen_timeout: 10000,
      
      // Cron para reinício programado (opcional - descomentado se necessário)
      // cron_restart: '0 4 * * *',
      
      // Variáveis de ambiente do arquivo .env
      node_args: '--env-file=.env'
    }
  ],
  
  // Configuração de deploy (opcional)
  deploy: {
    production: {
      user: 'ubuntu',
      host: 'seu-servidor.com',
      ref: 'origin/main',
      repo: 'git@github.com:estudioatlas/boutique-diniz-api.git',
      path: '/var/www/boutique-diniz-api',
      'pre-deploy-local': '',
      'post-deploy': 'npm install && pm2 reload ecosystem.config.js --env production',
      'pre-setup': ''
    }
  }
};
