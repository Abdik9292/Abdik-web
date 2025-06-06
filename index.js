const express = require('express');
const session = require('express-session');
const fileUpload = require('express-fileupload');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = process.env.PORT || 3000;

// Trust proxy for correct client IP (Railway or other proxies)
app.set('trust proxy', 1);

// CORS for GitHub Pages frontend
app.use(cors({
  origin: 'https://abdik9292.github.io/Abdik-web',
  credentials: true,
}));

// Middleware
app.use(express.json());
app.use(fileUpload());
app.use(session({
  secret: process.env.SESSION_SECRET || 'secret-key',
  resave: false,
  saveUninitialized: true,
  cookie: {
    maxAge: 24 * 60 * 60 * 1000, // 1 day
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'none',
  }
}));

// Config paths
const CONFIG_DIR = path.join(__dirname, 'config');
if (!fs.existsSync(CONFIG_DIR)) fs.mkdirSync(CONFIG_DIR);

const USERS_FILE = path.join(CONFIG_DIR, 'users.json');
const LOGS_FILE = path.join(CONFIG_DIR, 'logs.json');
const CHAT_FILE = path.join(CONFIG_DIR, 'chat.json');

if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, '{}');
if (!fs.existsSync(LOGS_FILE)) fs.writeFileSync(LOGS_FILE, '[]');
if (!fs.existsSync(CHAT_FILE)) fs.writeFileSync(CHAT_FILE, '[]');

// Helper functions
function loadUsers() {
  return JSON.parse(fs.readFileSync(USERS_FILE));
}

function saveUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

function logLogin(username, ip) {
  const logs = JSON.parse(fs.readFileSync(LOGS_FILE));
  logs.push({ username, ip, timestamp: Date.now() });
  fs.writeFileSync(LOGS_FILE, JSON.stringify(logs, null, 2));
}

function loadChat() {
  return JSON.parse(fs.readFileSync(CHAT_FILE));
}

function saveChat(messages) {
  fs.writeFileSync(CHAT_FILE, JSON.stringify(messages, null, 2));
}

// Routes

// Register
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required.' });
  }
  const users = loadUsers();
  if (users[username]) {
    return res.status(400).json({ error: 'Username already exists.' });
  }
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    users[username] = { password: hashedPassword, role: 'user' };
    saveUsers(users);
    req.session.user = { username, role: 'user' };
    res.json({ message: 'Registered successfully.', role: 'user' });
  } catch (err) {
    res.status(500).json({ error: 'Error registering user.' });
  }
});

// Login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required.' });
  }
  const users = loadUsers();
  const user = users[username];
  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials.' });
  }
  try {
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: 'Invalid credentials.' });

    req.session.user = { username, role: user.role };
    logLogin(username, req.ip);
    res.json({ message: 'Login successful.', role: user.role });
  } catch {
    res.status(500).json({ error: 'Login error.' });
  }
});

// Logout
app.post('/logout', (req, res) => {
  req.session.destroy(() => res.json({ message: 'Logged out.' }));
});

// Get chat messages
app.get('/chat', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
  res.json(loadChat());
});

// Send chat message
app.post('/chat', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
  const { message } = req.body;
  if (!message || typeof message !== 'string') {
    return res.status(400).json({ error: 'Invalid message.' });
  }
  const chat = loadChat();
  chat.push({ user: req.session.user.username, message, timestamp: Date.now() });
  saveChat(chat);
  res.json({ message: 'Message sent.' });
});

// Get login logs (admin only)
app.get('/logs', (req, res) => {
  if (!req.session.user || req.session.user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden' });
  }
  const logs = JSON.parse(fs.readFileSync(LOGS_FILE));
  res.json(logs);
});

// File upload
app.post('/upload', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
  if (!req.files || !req.files.file) {
    return res.status(400).json({ error: 'No file uploaded.' });
  }

  const uploadPath = path.join(__dirname, 'uploads');
  if (!fs.existsSync(uploadPath)) fs.mkdirSync(uploadPath);

  const file = req.files.file;

  // Sanitize filename and add timestamp to avoid overwrites
  const safeName = path.basename(file.name).replace(/[^a-z0-9\.\-_]/gi, '_');
  const uniqueName = `${Date.now()}_${safeName}`;
  const filePath = path.join(uploadPath, uniqueName);

  file.mv(filePath, err => {
    if (err) return res.status(500).json({ error: 'File upload failed.' });
    res.json({ message: 'File uploaded successfully.', filename: uniqueName });
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// Error handler
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Internal server error' });
});

// Start server
app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
});
