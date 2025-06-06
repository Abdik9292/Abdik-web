require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = 3000;

// Trust proxy settings
app.set('trust proxy', true);

// Middleware setup
app.use(express.static('.'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Session configuration
app.use(session({
  secret: process.env.SESSION_SECRET || 'your-secret-session-key',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: false, // Set to true if using HTTPS
    sameSite: 'lax',
  },
}));

const USERS_FILE = path.join(__dirname, 'config', 'users.json');
const LOGS_FILE = path.join(__dirname, 'config', 'logs.json');
const CHAT_FILE = path.join(__dirname, 'config', 'chat.json');

// Helper functions
function loadJSON(filePath) {
  try {
    const data = fs.readFileSync(filePath);
    return JSON.parse(data);
  } catch {
    return [];
  }
}

function saveJSON(filePath, data) {
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
}

function getClientIP(req) {
  const ip = req.ip || req.connection.remoteAddress;
  return ip === '::1' ? '127.0.0.1' : ip;
}

function hasRegisteredIP(ip) {
  const users = loadJSON(USERS_FILE);
  return users.some(u => u.ip === ip);
}

function addLog(username, ip) {
  const logs = loadJSON(LOGS_FILE);
  logs.push({ username, ip, timestamp: new Date().toISOString() });
  saveJSON(LOGS_FILE, logs);
}

// Authentication middleware
function authRequired(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
  next();
}

function adminRequired(req, res, next) {
  if (!req.session.user || req.session.user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden: Admins only' });
  }
  next();
}

// Routes

// Register (users only, one per IP)
app.post('/register', (req, res) => {
  const { username, password } = req.body;
  const ip = getClientIP(req);

  if (!username || !password) return res.status(400).json({ error: 'Missing username or password' });

  if (username === process.env.ADMIN_USERNAME) {
    return res.status(400).json({ error: 'Cannot register as admin' });
  }

  if (hasRegisteredIP(ip)) {
    return res.status(400).json({ error: 'This IP has already registered a user' });
  }

  const users = loadJSON(USERS_FILE);
  if (users.find(u => u.username === username)) {
    return res.status(400).json({ error: 'Username already exists' });
  }

  users.push({ username, password, role: 'user', ip });
  saveJSON(USERS_FILE, users);

  req.session.user = { username, role: 'user' };
  addLog(username, ip);

  res.json({ success: true, message: 'Registered and logged in!' });
});

// Login (users and admin)
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const ip = getClientIP(req);

  if (!username || !password) return res.status(400).json({ error: 'Missing username or password' });

  if (username === process.env.ADMIN_USERNAME) {
    if (password === process.env.ADMIN_PASSWORD) {
      req.session.user = { username, role: 'admin' };
      addLog(username, ip);
      return res.json({ success: true, role: 'admin' });
    } else {
      return res.status(401).json({ error: 'Invalid admin credentials' });
    }
  }

  const users = loadJSON(USERS_FILE);
  const user = users.find(u => u.username === username && u.password === password);
  if (!user) {
    return res.status(401).json({ error: 'Invalid username or password' });
  }

  req.session.user = { username: user.username, role: 'user' };
  addLog(username, ip);

  res.json({ success: true, role: 'user' });
});

// Logout
app.post('/logout', authRequired, (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true });
  });
});

// Chat endpoints
app.get('/chat', authRequired, (req, res) => {
  const messages = loadJSON(CHAT_FILE);
  res.json(messages);
});

app.post('/chat', authRequired, (req, res) => {
  const { message } = req.body;
  if (!message) return res.status(400).json({ error: 'No message' });

  const messages = loadJSON(CHAT_FILE);
  messages.push({ user: req.session.user.username, message, timestamp: new Date().toISOString() });
  saveJSON(CHAT_FILE, messages);

  res.json({ success: true });
});

// Upload (placeholder)
app.post('/upload', authRequired, (req, res) => {
  res.json({ success: true, message: 'Upload endpoint placeholder' });
});

// Admin-only logs view
app.get('/logs', adminRequired, (req, res) => {
  const logs = loadJSON(LOGS_FILE);
  res.json(logs);
});

// Serve index.html
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
