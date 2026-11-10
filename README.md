# Veltrix Log

Portal com backend Node.js para cadastro de contratantes, login, sessões seguras e aprovação administrativa.

## Executar localmente

1. Instale Node.js 20 ou mais recente.
2. Copie `.env.example` para `.env` e preencha os valores privados nesse arquivo.
3. Defina `ADMIN_USERNAME` como o usuário do administrador e `ADMIN_PASSWORD` como uma senha privada com pelo menos 8 caracteres. Escolha uma senha forte antes de usar contas reais.
4. Defina `SESSION_SECRET` com um valor aleatório longo. Não compartilhe nem envie o `.env` ao GitHub.
5. Execute `npm install` e depois `npm start`.
6. Abra `http://localhost:3000`.

O administrador entra por **Acesso administrativo** e pode aprovar ou recusar solicitações. Senhas de contratantes são protegidas com hash scrypt e salt. As sessões usam cookies HTTP-only e ficam no SQLite.

## Publicar usando o GitHub

Este projeto precisa de uma hospedagem que execute Node.js. O GitHub Pages serve arquivos estáticos e não executa a API nem o painel de aprovação. Conecte este repositório a uma hospedagem Node.js e configure o comando de início `npm start`. Nos campos privados de ambiente da hospedagem, configure `SESSION_SECRET`, `ADMIN_USERNAME`, `ADMIN_PASSWORD` e `DATABASE_PATH`. Anexe armazenamento persistente ao diretório do banco SQLite para preservar as contas entre publicações.

O mesmo servidor entrega o site e a API. Não é necessário publicar chaves de API no navegador. Nunca envie `.env`, arquivos do banco ou dados reais de clientes ao GitHub.
