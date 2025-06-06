require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = 3000;

// Ensure config directory exists
const configDir = path.join(__dirname, 'config');
if (!fs.existsSync(configDir)) {
  fs.mkdirSync(configDir);
}

app.use(express.static('.'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Session config with secret from .env
app.use(session({
  secret: process.env.SESSION_SECRET || 'fallback-secret',
  resave: false,
  saveUninitialized: false,
}));

const USERS_FILE = path.join(configDir, 'users.json');
const LOGS_FILE = path.join(configDir, 'logs.json');

// Helper to normalize IP (strip ::ffff: prefix if present)
function getClientIP(req) {
  let ip = req.ip || '';
  if (ip.startsWith('::ffff:')) {
    ip = ip.substring(7);
  }
  return ip;
}

// Load or initialize users file
function loadUsers() {
  try {
    const data = fs.readFileSync(USERS_FILE);
    return JSON.parse(data);
  } catch {
    return [];
  }
}

function saveUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

// Load or initialize logs file
function loadLogs() {
  try {
    const data = fs.readFileSync(LOGS_FILE);
    return JSON.parse(data);
  } catch {
    return [];
  }
}

function saveLogs(logs) {
  fs.writeFileSync(LOGS_FILE, JSON.stringify(logs, null, 2));
}

// Check if IP has registered
function hasRegisteredIP(ip) {
  const users = loadUsers();
  return users.some(u => u.ip === ip);
}

// Add login log entry
function addLog(username, ip) {
  const logs = loadLogs();
  logs.push({ username, ip, timestamp: new Date().toISOString() });
  saveLogs(logs);
}

// Middleware to check logged-in user
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

  // No admin registration allowed here
  if (username === process.env.ADMIN_USERNAME) {
    return res.status(400).json({ error: 'Cannot register as admin' });
  }

  if (hasRegisteredIP(ip)) {
    return res.status(400).json({ error: 'This IP has already registered a user' });
  }

  let users = loadUsers();
  if (users.find(u => u.username === username)) {
    return res.status(400).json({ error: 'Username already exists' });
  }

  users.push({ username, password, role: 'user', ip });
  saveUsers(users);

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
    // Admin login
    if (password === process.env.ADMIN_PASSWORD) {
      req.session.user = { username, role: 'admin' };
      addLog(username, ip);
      return res.json({ success: true, role: 'admin' });
    } else {
      return res.status(401).json({ error: 'Invalid admin credentials' });
    }
  }

  // User login
  const users = loadUsers();
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

// Get chat messages (simple in-memory)
const chatMessages = [];

app.get('/chat', authRequired, (req, res) => {
  res.json(chatMessages);
});

app.post('/chat', authRequired, (req, res) => {
  const { message } = req.body;
  if (!message) return res.status(400).json({ error: 'No message' });
  chatMessages.push({ user: req.session.user.username, message, timestamp: new Date().toISOString() });
  res.json({ success: true });
});

// Upload (dummy)
app.post('/upload', authRequired, (req, res) => {
  // For simplicity, no actual file upload implementation here.
  // You can add multer or other upload handlers later.
  res.json({ success: true, message: 'Upload endpoint placeholder' });
});

// Admin-only logs view
app.get('/logs', adminRequired, (req, res) => {
  res.json(loadLogs());
});

// Serve index.html
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
