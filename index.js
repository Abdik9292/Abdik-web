const express = require('express');
const session = require('express-session');
const fileUpload = require('express-fileupload');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const sharp = require('sharp');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// CORS: allow GitHub frontend
app.use(cors({
  origin: 'https://abdik9292.github.io',
  credentials: true,
}));

// Public file
app.use(express.static(path.join(__dirname, 'public')));

// Middleware
app.use(express.json());
app.use(fileUpload());
app.use(session({
  secret: process.env.SESSION_SECRET || 'default-secret',
  resave: false,
  saveUninitialized: true,
  cookie: {
    secure: false,
    sameSite: 'none'
  }
}));

// Trust proxy for correct IP logging (Railway support)
app.set('trust proxy', true);

// File paths
const CONFIG_DIR = path.join(__dirname, 'config');
const USERS_FILE = path.join(CONFIG_DIR, 'users.json');
const LOGS_FILE = path.join(CONFIG_DIR, 'log.json'); // For admin
const SUPER_LOG_FILE = path.join(CONFIG_DIR, 'superlog.json'); // For superadmin
const CHAT_FILE = path.join(CONFIG_DIR, 'chat.json');
const SUPERADMIN_FILE = path.join(CONFIG_DIR, 'superadmin.json');

// Ensure config dir/files exist
if (!fs.existsSync(CONFIG_DIR)) fs.mkdirSync(CONFIG_DIR);
if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, '{}');
if (!fs.existsSync(LOGS_FILE)) fs.writeFileSync(LOGS_FILE, '[]');
if (!fs.existsSync(SUPER_LOG_FILE)) fs.writeFileSync(SUPER_LOG_FILE, '[]');
if (!fs.existsSync(CHAT_FILE)) fs.writeFileSync(CHAT_FILE, '[]');
if (!fs.existsSync(SUPERADMIN_FILE)) {
  fs.writeFileSync(SUPERADMIN_FILE, JSON.stringify({
    username: 'superadmin',
    password: 'supersecret',
    publicInfo: 'This is the Superadmin.'
  }));
}

// Helpers
function loadUsers() {
  return JSON.parse(fs.readFileSync(USERS_FILE));
}

function saveUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

function loadSuperadmin() {
  return JSON.parse(fs.readFileSync(SUPERADMIN_FILE));
}

function getIP(req) {
  return req.headers['x-forwarded-for']?.split(',')[0] || req.ip;
}

function logEvent(user, ip, target, file) {
  const logs = JSON.parse(fs.readFileSync(file));
  logs.push({
    user,
    target,
    ip,
    timestamp: new Date().toISOString()
  });
  fs.writeFileSync(file, JSON.stringify(logs, null, 2));
}

function loadChat() {
  return JSON.parse(fs.readFileSync(CHAT_FILE));
}

function saveChat(messages) {
  const maxMessages = 1250;
  const trimmed = messages.slice(-maxMessages);
  fs.writeFileSync(CHAT_FILE, JSON.stringify(trimmed, null, 2));
}

// Routes
app.post('/register', (req, res) => {
  const { username, password } = req.body;
  if (!username || username.length < 3 || username.length > 16)
    return res.status(400).json({ error: 'Username must be 3–16 characters.' });
  if (!password || password.length < 8)
    return res.status(400).json({ error: 'Password must be at least 8 characters.' });

  const users = loadUsers();
  if (users[username]) return res.status(400).json({ error: 'Username already taken.' });

  users[username] = { password, role: 'user' };
  saveUsers(users);
  req.session.user = { username, role: 'user' };
  res.json({ message: 'Registered successfully.', role: 'user' });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;

  const superadmin = loadSuperadmin();
  const users = loadUsers();
  const ip = getIP(req);

  // Superadmin login
  if (username === superadmin.username && password === superadmin.password) {
    req.session.user = { username, role: 'superadmin' };
    logEvent(username, ip, 'superadmin_login', SUPER_LOG_FILE);
    return res.json({ message: 'Superadmin login successful', role: 'superadmin' });
  }

  // Admins from .env
  if (process.env.ADMIN_USERNAME && process.env.ADMIN_PASSWORD &&
      username === process.env.ADMIN_USERNAME && password === process.env.ADMIN_PASSWORD) {
    req.session.user = { username, role: 'admin' };
    logEvent(username, ip, 'admin_login', LOGS_FILE);
    return res.json({ message: 'Admin login successful', role: 'admin' });
  }

  // Regular users
  const user = users[username];
  if (!user || user.password !== password)
    return res.status(401).json({ error: 'Invalid credentials' });

  req.session.user = { username, role: user.role };
  logEvent(username, ip, 'user_login', LOGS_FILE);
  res.json({ message: 'Login successful', role: user.role });
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => res.json({ message: 'Logged out.' }));
});

// Get logs
app.get('/logs', (req, res) => {
  const user = req.session.user;
  if (!user) return res.status(401).json({ error: 'Unauthorized' });

  if (user.role === 'admin') {
    return res.json(JSON.parse(fs.readFileSync(LOGS_FILE)));
  }

  if (user.role === 'superadmin') {
    return res.json(JSON.parse(fs.readFileSync(SUPER_LOG_FILE)));
  }

  res.status(403).json({ error: 'Forbidden' });
});

// Chat system
app.get('/chat', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
  const messages = loadChat();
  res.json(messages.slice(-50));
});

app.post('/chat', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });

  const { message } = req.body;
  if (!message || typeof message !== 'string') {
    return res.status(400).json({ error: 'Message must be a string.' });
  }

  const messages = loadChat();
  messages.push({
    user: req.session.user.username,
    message,
    timestamp: new Date().toISOString()
  });
  saveChat(messages);
  res.json({ message: 'Message posted.' });
});

// Upload avatar (PFP)
app.post('/upload', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
  if (!req.files || !req.files.image) return res.status(400).json({ error: 'No file uploaded.' });

  const file = req.files.image;
  const allowedFormats = ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/svg+xml', 'image/bmp', 'image/tiff', 'image/heif', 'image/heic'];
  if (!allowedFormats.includes(file.mimetype)) return res.status(400).json({ error: 'Invalid file format.' });
  if (file.size > 10 * 1024 * 1024) return res.status(400).json({ error: 'File too large (max 10MB).' });

  const uploadPath = path.join(__dirname, 'uploads');
  if (!fs.existsSync(uploadPath)) fs.mkdirSync(uploadPath);

  const filePath = path.join(uploadPath, `${req.session.user.username}.png`);
  sharp(file.data)
    .resize(512, 512)
    .blur(1)
    .toFile(filePath, (err, info) => {
      if (err) return res.status(500).json({ error: 'Upload failed.' });
      res.json({ message: 'Upload successful.' });
    });
});

// Upload files to chat
app.post('/upload-chat', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
  if (!req.files || !req.files.file) return res.status(400).json({ error: 'No file uploaded.' });

  const file = req.files.file;
  if (file.size > 125 * 1024 * 1024) return res.status(400).json({ error: 'File too large (max 125MB).' });

  const uploadPath = path.join(__dirname, 'uploads');
  if (!fs.existsSync(uploadPath)) fs.mkdirSync(uploadPath);

  const filePath = path.join(uploadPath, `${Date.now()}-${file.name}`);
  file.mv(filePath, err => {
    if (err) return res.status(500).json({ error: 'Upload failed.' });
    const messages = loadChat();
    messages.push({
      user: req.session.user.username,
      message: `Uploaded a file: ${file.name}`,
      timestamp: new Date().toISOString(),
      file: filePath
    });
    saveChat(messages);
    res.json({ message: 'File uploaded.' });
  });
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start
app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ Server running on port ${PORT}`);
});
