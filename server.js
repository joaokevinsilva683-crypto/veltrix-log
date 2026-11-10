import 'dotenv/config';
import express from 'express';
import session from 'express-session';
import SQLiteStoreFactory from 'connect-sqlite3';
import Database from 'better-sqlite3';
import { rateLimit } from 'express-rate-limit';
import { randomBytes, scrypt as scryptCallback, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import fs from 'node:fs';

const scrypt = promisify(scryptCallback);
const app = express();
const here = path.dirname(fileURLToPath(import.meta.url));
const dbPath = path.resolve(process.env.DATABASE_PATH || path.join(here, 'data', 'veltrix.sqlite'));
fs.mkdirSync(path.dirname(dbPath), { recursive: true });
const db = new Database(dbPath);
db.pragma('journal_mode = WAL');
db.exec(`CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, document TEXT NOT NULL UNIQUE,
  email TEXT NOT NULL UNIQUE, phone TEXT NOT NULL, password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'contractor', status TEXT NOT NULL DEFAULT 'pending',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
)`);

const required = ['SESSION_SECRET', 'ADMIN_USERNAME', 'ADMIN_PASSWORD'];
for (const key of required) if (!process.env[key]) throw new Error(`Missing required environment variable: ${key}`);
if (process.env.ADMIN_PASSWORD.length < 8) throw new Error('ADMIN_PASSWORD must contain at least 8 characters.');
if (process.env.SESSION_SECRET.length < 32) throw new Error('SESSION_SECRET must contain at least 32 characters.');
const username = process.env.ADMIN_USERNAME.trim().toLocaleUpperCase('pt-BR');
const password = process.env.ADMIN_PASSWORD;
const digest = async value => {
  const salt = randomBytes(16);
  const hash = await scrypt(value, salt, 64);
  return `${salt.toString('hex')}:${Buffer.from(hash).toString('hex')}`;
};
const verify = async (value, stored) => {
  try {
    const [saltHex, hashHex] = stored.split(':');
    const expected = Buffer.from(hashHex, 'hex');
    const actual = Buffer.from(await scrypt(value, Buffer.from(saltHex, 'hex'), expected.length));
    return expected.length === actual.length && timingSafeEqual(expected, actual);
  } catch { return false; }
};

const adminEmail = 'admin@veltrix.invalid';
let admin = db.prepare('SELECT id FROM users WHERE role = ? LIMIT 1').get('admin');
if (!admin) {
  const adminId = randomBytes(16).toString('hex');
  const passwordHash = await digest(password);
  db.prepare('INSERT INTO users (id,name,document,email,phone,password_hash,role,status) VALUES (?,?,?,?,?,?,?,?)')
    .run(adminId, username, `ADMIN-${adminId}`, adminEmail, '', passwordHash, 'admin', 'approved');
} else {
  db.prepare('UPDATE users SET name = ? WHERE role = ?').run(username, 'admin');
  // Rotate the admin credential from environment variables at each server start.
  const passwordHash = await digest(password);
  db.prepare('UPDATE users SET password_hash = ? WHERE role = ?').run(passwordHash, 'admin');
}

const SQLiteStore = SQLiteStoreFactory(session);
app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(express.json({ limit: '20kb' }));
app.use(session({
  name: 'veltrix.sid',
  secret: process.env.SESSION_SECRET,
  store: new SQLiteStore({ db: 'sessions.sqlite', dir: path.dirname(dbPath) }),
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax', maxAge: 8 * 60 * 60 * 1000 }
}));
const loginLimit = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: 'draft-8', legacyHeaders: false });
const signupLimit = rateLimit({ windowMs: 60 * 60 * 1000, limit: 5, standardHeaders: 'draft-8', legacyHeaders: false });
const clean = value => String(value ?? '').trim();
const normalizedDoc = value => clean(value).replace(/\W/g, '');
const safeUser = row => ({ id: row.id, name: row.name, email: row.email, role: row.role, status: row.status });
const requireAuth = (req, res, next) => req.session.user ? next() : res.status(401).json({ error: 'Entre na sua conta para continuar.' });
const requireAdmin = (req, res, next) => req.session.user?.role === 'admin' ? next() : res.status(403).json({ error: 'Acesso restrito ao administrador.' });

app.post('/api/signup', signupLimit, async (req, res) => {
  const name = clean(req.body?.name), document = normalizedDoc(req.body?.document), email = clean(req.body?.email).toLowerCase(), phone = clean(req.body?.phone), rawPassword = String(req.body?.password ?? '');
  if (!name || !document || !email || !phone || rawPassword.length < 10) return res.status(400).json({ error: 'Preencha todos os campos. A senha deve ter pelo menos 10 caracteres.' });
  if (document.length < 11 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'Confira o CPF/CNPJ e o e-mail informados.' });
  const existing = db.prepare('SELECT id FROM users WHERE email = ? OR document = ?').get(email, document);
  if (existing) return res.status(409).json({ error: 'Já existe um cadastro com esse e-mail ou documento.' });
  const passwordHash = await digest(rawPassword);
  const id = randomBytes(16).toString('hex');
  db.prepare('INSERT INTO users (id,name,document,email,phone,password_hash) VALUES (?,?,?,?,?,?)').run(id, name, document, email, phone, passwordHash);
  res.status(201).json({ message: 'Cadastro recebido e aguardando aprovação.' });
});

app.post('/api/login', loginLimit, async (req, res) => {
  const login = clean(req.body?.login), rawPassword = String(req.body?.password ?? '');
  const row = db.prepare('SELECT * FROM users WHERE email = ? OR document = ? OR (role = ? AND name = ?)')
    .get(login.toLowerCase(), normalizedDoc(login), 'admin', login.toLocaleUpperCase('pt-BR'));
  if (!row || !(await verify(rawPassword, row.password_hash))) return res.status(401).json({ error: 'Usuário ou senha incorretos.' });
  if (row.status !== 'approved') return res.status(403).json({ error: 'Seu cadastro ainda aguarda aprovação.' });
  req.session.regenerate(err => {
    if (err) return res.status(500).json({ error: 'Não foi possível iniciar sua sessão.' });
    req.session.user = safeUser(row);
    req.session.save(saveErr => saveErr ? res.status(500).json({ error: 'Não foi possível salvar sua sessão.' }) : res.json({ user: req.session.user }));
  });
});

app.get('/api/me', requireAuth, (req, res) => res.json({ user: req.session.user }));
app.post('/api/logout', (req, res) => req.session.destroy(() => { res.clearCookie('veltrix.sid'); res.status(204).end(); }));
app.get('/api/admin/applications', requireAuth, requireAdmin, (_req, res) => {
  const rows = db.prepare("SELECT id,name,document,email,phone,created_at AS createdAt FROM users WHERE role='contractor' AND status='pending' ORDER BY created_at").all();
  res.json({ applications: rows });
});
app.post('/api/admin/applications/:id/approve', requireAuth, requireAdmin, (req, res) => {
  const result = db.prepare("UPDATE users SET status='approved' WHERE id=? AND role='contractor' AND status='pending'").run(req.params.id);
  result.changes ? res.json({ message: 'Acesso aprovado.' }) : res.status(404).json({ error: 'Solicitação não encontrada ou já analisada.' });
});
app.post('/api/admin/applications/:id/reject', requireAuth, requireAdmin, (req, res) => {
  const result = db.prepare("DELETE FROM users WHERE id=? AND role='contractor' AND status='pending'").run(req.params.id);
  result.changes ? res.json({ message: 'Solicitação recusada e removida.' }) : res.status(404).json({ error: 'Solicitação não encontrada ou já analisada.' });
});

app.use(express.static(here));
app.get('*path', (_req, res) => res.sendFile(path.join(here, 'index.html')));
const port = Number(process.env.PORT || 3000);
app.listen(port, '0.0.0.0', () => console.log(`Veltrix Log listening on port ${port}`));
