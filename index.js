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

// ========== MIDDLEWARE SETUP ========== //
app.set('trust proxy', true);
app.use(cors({
  origin: 'https://abdik9292.github.io/Abdik-web/',
  credentials: true,
}));
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

// ========== FILE PATHS ========== //
const CONFIG = path.join(__dirname, 'config');
const UPLOADS = path.join(__dirname, 'uploads');
const PFP_DIR = path.join(UPLOADS, 'pfp');
const FILES_DIR = path.join(UPLOADS, 'files');
const USERS_FILE = path.join(CONFIG, 'users.json');
const LOGS_FILE = path.join(CONFIG, 'log.json');
const SUPER_LOG = path.join(CONFIG, 'superlog.json');
const CHAT_FILE = path.join(CONFIG, 'chat.json');
const SUPERADMIN_FILE = path.join(CONFIG, 'superadmin.json');

// ========== INIT DIRECTORIES & FILES ========== //
[CONFIG, UPLOADS, PFP_DIR, FILES_DIR].forEach(dir => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});
const initFile = (file, def) => {
  if (!fs.existsSync(file)) fs.writeFileSync(file, JSON.stringify(def, null, 2));
};
initFile(USERS_FILE, {});
initFile(LOGS_FILE, []);
initFile(SUPER_LOG, []);
initFile(CHAT_FILE, []);
initFile(SUPERADMIN_FILE, {
  username: 'superadmin',
  password: 'supersecret',
  publicInfo: 'This is the Superadmin.'
});

// ========== HELPERS ========== //
const getIP = req => req.headers['x-forwarded-for']?.split(',')[0] || req.ip;
const load = file => JSON.parse(fs.readFileSync(file));
const save = (file, data) => fs.writeFileSync(file, JSON.stringify(data, null, 2));
const logEvent = (user, ip, target, file) => {
  const logs = load(file);
  logs.push({ user, target, ip, timestamp: new Date().toISOString() });
  save(file, logs);
};

// ========== ROUTES ========== //

// --- Register
app.post('/register', (req, res) => {
  const { username, password } = req.body;
  if (!username || username.length < 3 || username.length > 16)
    return res.status(400).json({ error: 'Username must be 3–16 characters.' });

  if (!password || password.length < 8)
    return res.status(400).json({ error: 'Password must be at least 8 characters.' });

  const users = load(USERS_FILE);
  if (users[username])
    return res.status(400).json({ error: 'Username already taken.' });

  users[username] = { password, role: 'user' };
  save(USERS_FILE, users);
  req.session.user = { username, role: 'user' };
  res.json({ message: 'Registered successfully.', role: 'user' });
});

// --- Login
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const users = load(USERS_FILE);
  const superadmin = load(SUPERADMIN_FILE);
  const ip = getIP(req);

  if (username === superadmin.username && password === superadmin.password) {
    req.session.user = { username, role: 'superadmin' };
    logEvent(username, ip, 'superadmin_login', SUPER_LOG);
    return res.json({ message: 'Superadmin login successful', role: 'superadmin' });
  }

  if (username === process.env.ADMIN_USERNAME && password === process.env.ADMIN_PASSWORD) {
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

// --- Logout
app.post('/logout', (req, res) => {
  req.session.destroy(() => res.json({ message: 'Logged out.' }));
});

// --- Logs
app.get('/logs', (req, res) => {
  const user = req.session.user;
  if (!user) return res.status(401).json({ error: 'Unauthorized' });

  if (user.role === 'admin') return res.json(load(LOGS_FILE));
  if (user.role === 'superadmin') return res.json(load(SUPER_LOG));

  res.status(403).json({ error: 'Forbidden' });
});

// --- Chat
app.get('/chat', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
  const messages = load(CHAT_FILE);
  res.json(messages.slice(-50));
});

app.post('/chat', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });

  const messages = load(CHAT_FILE);
  const username = req.session.user.username;

  if (req.files?.file) {
    const file = req.files.file;
    if (file.size > 125 * 1024 * 1024)
      return res.status(400).json({ error: 'File too large (max 125MB).' });

    const filename = `${Date.now()}_${file.name}`;
    const filepath = path.join(FILES_DIR, filename);
    file.mv(filepath, err => {
      if (err) return res.status(500).json({ error: 'File upload failed.' });

      messages.push({ user: username, file: `/uploads/files/${filename}`, timestamp: new Date().toISOString() });
      save(CHAT_FILE, messages.slice(-1250));
      res.json({ message: 'File uploaded to chat.' });
    });
  } else if (req.body.message) {
    messages.push({ user: username, message: req.body.message, timestamp: new Date().toISOString() });
    save(CHAT_FILE, messages.slice(-1250));
    res.json({ message: 'Message sent.' });
  } else {
    res.status(400).json({ error: 'No message or file provided.' });
  }
});

// --- Profile Picture Upload
app.post('/upload', async (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
  if (!req.files?.image) return res.status(400).json({ error: 'No image uploaded.' });

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

// --- Fallback Route
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ========== SERVER START ========== //
app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ Server running on port ${PORT}`);
});
