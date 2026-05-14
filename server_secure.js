const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const initSqlJs = require('sql.js');

const app = express();
const DB_PATH = path.join(__dirname, 'app.db');
let db;

async function initDB() {
  const SQL = await initSqlJs();
  if (fs.existsSync(DB_PATH)) {
    db = new SQL.Database(fs.readFileSync(DB_PATH));
  } else {
    db = new SQL.Database();
  }
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT NOT NULL,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'user'
  )`);
  const check = db.exec("SELECT * FROM users WHERE username = 'admin'");
  if (!check.length || !check[0].values.length) {
    const ha = bcrypt.hashSync('admin123', 10);
    const hu = bcrypt.hashSync('user123', 10);
    db.run("INSERT INTO users (username,email,password,role) VALUES (?,?,?,?)", ['admin','admin@site.com',ha,'admin']);
    db.run("INSERT INTO users (username,email,password,role) VALUES (?,?,?,?)", ['john','john@site.com',hu,'user']);
  }
  saveDB();
}

function saveDB() {
  fs.writeFileSync(DB_PATH, Buffer.from(db.export()));
}

function dbGet(sql, params=[]) {
  try {
    const stmt = db.prepare(sql);
    stmt.bind(params);
    const row = stmt.step() ? stmt.getAsObject() : null;
    stmt.free();
    return row;
  } catch(e) { return null; }
}

function dbAll(sql, params=[]) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  const rows = [];
  while(stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  return rows;
}

function dbRun(sql, params=[]) {
  db.run(sql, params);
  saveDB();
}

// FIX 1: Output encoding — turns <script> into plain text
function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

// FIX 2: CSRF token helpers
function generateCsrfToken(req) {
  if (!req.session.csrfToken)
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');
  return req.session.csrfToken;
}
function verifyCsrfToken(req, res, next) {
  const token = req.body._csrf || req.headers['x-csrf-token'];
  if (!token || token !== req.session.csrfToken)
    return res.status(403).json({ error: 'Invalid CSRF token — request blocked' });
  next();
}

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
  secret: 'supersecret',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'Strict' }  // FIX 3: HttpOnly cookie
}));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

function requireLogin(req, res, next) {
  if (!req.session.user) return res.redirect('/login');
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== 'admin') return res.status(403).send('Forbidden');
  next();
}

app.get('/', (req, res) => res.render('home', { secure: true, user: req.session.user }));

app.get('/register', (req, res) => res.render('register', { secure: true, error: null }));
app.post('/register', async (req, res) => {
  const { username, email, password } = req.body;
  if (!/^[a-zA-Z0-9_]{3,20}$/.test(username))
    return res.render('register', { secure: true, error: 'Username must be 3-20 alphanumeric characters' });
  try {
    const hashed = await bcrypt.hash(password, 10);
    dbRun("INSERT INTO users (username,email,password) VALUES (?,?,?)", [username, email, hashed]);
    res.redirect('/login');
  } catch(e) {
    res.render('register', { secure: true, error: 'Username already taken' });
  }
});

app.get('/login', (req, res) => res.render('login', { secure: true, error: null }));
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  // FIX: parameterized query
  const user = dbGet("SELECT * FROM users WHERE username = ?", [username]);
  if (!user || !bcrypt.compareSync(password, user.password))
    return res.render('login', { secure: true, error: 'Invalid credentials' });
  req.session.user = { id: user.id, username: user.username, role: user.role };
  res.redirect('/dashboard');
});

app.get('/logout', (req, res) => { req.session.destroy(); res.redirect('/login'); });

app.get('/dashboard', requireLogin, (req, res) => {
  res.render('dashboard', { secure: true, user: req.session.user });
});

// SECURE: Search — parameterized query + escaped output
app.get('/search', requireLogin, (req, res) => {
  const q = req.query.q || '';
  // FIX 1: parameterized query
  const results = dbAll("SELECT id, username, email, role FROM users WHERE username LIKE ?", [`%${q}%`]);
  // FIX 2: escape before rendering
  const safeQ = escapeHtml(q);
  res.render('search_secure', { secure: true, user: req.session.user, q: safeQ, results, error: null });
});

// SECURE: Promote — CSRF token verified + role re-checked
app.post('/admin/promote', requireLogin, verifyCsrfToken, (req, res) => {
  if (req.session.user.role !== 'admin')
    return res.status(403).json({ error: 'Only admins can promote users' });
  const { username } = req.body;
  dbRun("UPDATE users SET role = 'admin' WHERE username = ?", [username]);
  res.json({ success: true, message: `${username} is now admin` });
});

app.get('/admin', requireAdmin, (req, res) => {
  const users = dbAll("SELECT id, username, email, role FROM users");
  const csrfToken = generateCsrfToken(req);
  res.render('admin_secure', { secure: true, user: req.session.user, users, csrfToken });
});

initDB().then(() => {
  app.listen(4000, () => console.log('SECURE app running at http://localhost:4000'));
});
