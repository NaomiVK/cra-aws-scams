module.exports = {
  apps: [
    {
      name: 'cra-api',
      script: 'dist/apps/api/main.js',
      cwd: '/home/ec2-user/cra-aws-scams',
      instances: 1,
      autorestart: true,
      watch: false,
      max_memory_restart: '500M',
      env: {
        NODE_ENV: 'production',
        PORT: 3000,
      },
    },
    {
      name: 'cra-frontend',
      script: 'npx',
      args: 'serve -s dist/apps/frontend -l 4200',
      cwd: '/home/ec2-user/cra-aws-scams',
      instances: 1,
      autorestart: true,
      watch: false,
      env: {
        NODE_ENV: 'production',
      },
    },
  ],
};
