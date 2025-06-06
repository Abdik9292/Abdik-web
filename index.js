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

// CORS
app.use(cors({
  origin: 'https://abdik9292.github.io/Abdik-web/',
  credentials: true,
}));

// Middleware
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());
app.use(fileUpload());
app.use(session({
  secret: process.env.SESSION_SECRET || 'default-secret',
  resave: false,
  saveUninitialized: true,
  cookie: {
    secure: false,
    sameSite: 'lax',
  }
}));

app.set('trust proxy', true);

// File paths
const CONFIG_DIR = path.join(__dirname, 'config');
const USERS_FILE = path.join(CONFIG_DIR, 'users.json');
const LOGS_FILE = path.join(CONFIG_DIR, 'log.json');
const SUPER_LOG_FILE = path.join(CONFIG_DIR, 'superlog.json');
const CHAT_FILE = path.join(CONFIG_DIR, 'chat.json');
const SUPERADMIN_FILE = path.join(CONFIG_DIR, 'superadmin.json');
const UPLOADS_DIR = path.join(__dirname, 'uploads');
const PFP_DIR = path.join(UPLOADS_DIR, 'pfp');
const FILES_DIR = path.join(UPLOADS_DIR, 'files');

// Ensure directories and files exist
[CONFIG_DIR, UPLOADS_DIR, PFP_DIR, FILES_DIR].forEach(dir => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

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
  logs.push({ user, target, ip, timestamp: new Date().toISOString() });
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

// Registration
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

// Login
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const users = loadUsers();
  const ip = getIP(req);
  const superadmin = loadSuperadmin();

  if (username === superadmin.username && password === superadmin.password) {
    req.session.user = { username, role: 'superadmin' };
    logEvent(username, ip, 'superadmin_login', SUPER_LOG_FILE);
    return res.json({ message: 'Superadmin login successful', role: 'superadmin' });
  }

  if (process.env.ADMIN_USERNAME === username && process.env.ADMIN_PASSWORD === password) {
    req.session.user = { username, role: 'admin' };
    logEvent(username, ip, 'admin_login', LOGS_FILE);
    return res.json({ message: 'Admin login successful', role: 'admin' });
  }

  const user = users[username];
  if (!user || user.password !== password)
    return res.status(401).json({ error: 'Invalid credentials' });

  req.session.user = { username, role: user.role };
  logEvent(username, ip, 'user_login', LOGS_FILE);
  res.json({ message: 'Login successful', role: user.role });
});

// Logout
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

// Get chat messages
app.get('/chat', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
  const messages = loadChat();
  res.json(messages.slice(-50));
});

// Send chat message or file
app.post('/chat', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });

  const messages = loadChat();
  const username = req.session.user.username;

  if (req.files && req.files.file) {
    const file = req.files.file;
    if (file.size > 125 * 1024 * 1024) {
      return res.status(400).json({ error: 'File too large (max 125MB).' });
    }

    const fileName = `${Date.now()}_${file.name}`;
    const filePath = path.join(FILES_DIR, fileName);
    file.mv(filePath, err => {
      if (err) return res.status(500).json({ error: 'File upload failed.' });

      messages.push({
        user: username,
        file: `/uploads/files/${fileName}`,
        timestamp: new Date().toISOString()
      });
      saveChat(messages);
      res.json({ message: 'File uploaded to chat.' });
    });
  } else if (req.body.message) {
    messages.push({
      user: username,
      message: req.body.message,
      timestamp: new Date().toISOString()
    });
    saveChat(messages);
    res.json({ message: 'Message sent.' });
  } else {
    res.status(400).json({ error: 'No message or file provided.' });
  }
});

// Upload profile picture (resized and blurred)
app.post('/upload', async (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
  if (!req.files || !req.files.image) return res.status(400).json({ error: 'No image uploaded.' });

  const file = req.files.image;
  if (!file.mimetype.startsWith('image/'))
    return res.status(400).json({ error: 'Only image files allowed.' });

  if (file.size > 10 * 1024 * 1024)
    return res.status(400).json({ error: 'Image too large (max 10MB).' });

  const outputPath = path.join(PFP_DIR, `${req.session.user.username}.webp`);
  try {
    await sharp(file.data)
      .resize(128, 128)
      .blur()
      .webp({ quality: 80 })
      .toFile(outputPath);

    res.json({ message: 'Profile picture uploaded.' });
  } catch (err) {
    res.status(500).json({ error: 'Image processing failed.' });
  }
});

// Fallback route
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ Server running on port ${PORT}`);
});
