const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const path = require('path');
const fs = require('fs');
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
    console.log('Seeded: admin/admin123  and  john/user123');
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

function dbAllRaw(sql) {
  try {
    const result = db.exec(sql);
    if (!result.length) return [];
    const cols = result[0].columns;
    return result[0].values.map(row => {
      const obj = {};
      cols.forEach((c, i) => obj[c] = row[i]);
      return obj;
    });
  } catch(e) { throw e; }
}

function dbRun(sql, params=[]) {
  db.run(sql, params);
  saveDB();
}

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({ secret: 'supersecret', resave: false, saveUninitialized: false }));
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

app.get('/', (req, res) => res.render('home', { user: req.session.user }));

app.get('/register', (req, res) => res.render('register', { error: null }));
app.post('/register', async (req, res) => {
  const { username, email, password } = req.body;
  try {
    const hashed = await bcrypt.hash(password, 10);
    dbRun("INSERT INTO users (username,email,password) VALUES (?,?,?)", [username, email, hashed]);
    res.redirect('/login');
  } catch(e) {
    res.render('register', { error: 'Username already taken' });
  }
});

app.get('/login', (req, res) => res.render('login', { error: null }));
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = dbGet("SELECT * FROM users WHERE username = ?", [username]);
  if (!user || !bcrypt.compareSync(password, user.password))
    return res.render('login', { error: 'Invalid credentials' });
  req.session.user = { id: user.id, username: user.username, role: user.role };
  res.redirect('/dashboard');
});

app.get('/logout', (req, res) => { req.session.destroy(); res.redirect('/login'); });

app.get('/dashboard', requireLogin, (req, res) => {
  res.render('dashboard', { user: req.session.user });
});

// VULNERABLE: Search — raw SQL concat + raw HTML output
app.get('/search', requireLogin, (req, res) => {
  const q = req.query.q || '';
  let results = [];
  let error = null;
  try {
    // VULNERABILITY 1: SQL Injection
    const query = `SELECT id, username, email, role FROM users WHERE username LIKE '%${q}%'`;
    results = dbAllRaw(query);
  } catch(e) {
    error = e.message;
  }
  // VULNERABILITY 2: XSS — q rendered raw with <%-
  res.render('search', { user: req.session.user, q, results, error });
});

// VULNERABLE: Promote — no CSRF token check
app.post('/admin/promote', requireLogin, (req, res) => {
  const { username } = req.body;
  dbRun("UPDATE users SET role = 'admin' WHERE username = ?", [username]);
  res.json({ success: true, message: `${username} is now admin` });
});

app.get('/admin', requireAdmin, (req, res) => {
  const users = dbAll("SELECT id, username, email, role FROM users");
  res.render('admin', { user: req.session.user, users });
});

initDB().then(() => {
  app.listen(3000, () => console.log('VULNERABLE app running at http://localhost:3000'));
});
