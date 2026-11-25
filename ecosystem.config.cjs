// pm2 process file: `pm2 start ecosystem.config.cjs` (after `npm run build`).
// Secrets go in .env (see .env.example), never in this file.
module.exports = {
  apps: [
    {
      name: 'discount-verifier',
      script: 'dist/server/main.js',
      // Config, public/ and data/ are resolved relative to the working directory.
      cwd: __dirname,
      node_args: '--env-file=.env',
      // Sessions are kept in memory: run exactly one instance, never cluster mode.
      exec_mode: 'fork',
      instances: 1,
      env: {
        NODE_ENV: 'production',
        PORT: 8374,
      },
      // The server needs up to 5 s to close long-poll connections on shutdown.
      kill_timeout: 6000,
      max_memory_restart: '300M',
      time: true,
    },
  ],
};
