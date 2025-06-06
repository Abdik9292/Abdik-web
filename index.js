const express = require('express');
const session = require('express-session');
const fileUpload = require('express-fileupload');
const cors = require('cors');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors({
  origin: 'https://abdik9292.github.io',
  credentials: true,
}));
app.use(express.json());
app.use(fileUpload());
app.use(session({
  secret: 'secret-key',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: true } // set true only if using HTTPS
}));

const USERS_FILE = path.join(__dirname, 'config/users.json');
const LOGS_FILE = path.join(__dirname, 'config/logs.json');
const CHAT_FILE = path.join(__dirname, 'config/chat.json');

if (!fs.existsSync('config')) fs.mkdirSync('config');
if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, '{}');
if (!fs.existsSync(LOGS_FILE)) fs.writeFileSync(LOGS_FILE, '[]');
if (!fs.existsSync(CHAT_FILE)) fs.writeFileSync(CHAT_FILE, '[]');

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

// Register
app.post('/register', (req, res) => {
  const { username, password } = req.body;
  const users = loadUsers();
  if (users[username]) {
    return res.status(400).json({ error: 'Username already exists.' });
  }
  users[username] = { password, role: 'user' };
  saveUsers(users);
  req.session.user = { username, role: 'user' };
  res.json({ message: 'Registered successfully.', role: 'user' });
});

// Login
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const users = loadUsers();
  const user = users[username];
  if (!user || user.password !== password) {
    return res.status(401).json({ error: 'Invalid credentials.' });
  }
  req.session.user = { username, role: user.role };
  logLogin(username, req.ip);
  res.json({ message: 'Login successful.', role: user.role });
});

// Logout
app.post('/logout', (req, res) => {
  req.session.destroy(() => res.json({ message: 'Logged out.' }));
});

// Chat get
app.get('/chat', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
  res.json(loadChat());
});

// Chat post
app.post('/chat', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
  const { message } = req.body;
  const chat = loadChat();
  chat.push({ user: req.session.user.username, message, timestamp: Date.now() });
  saveChat(chat);
  res.json({ message: 'Message sent.' });
});

// Logs (admin only)
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
  const filePath = path.join(uploadPath, file.name);
  file.mv(filePath, err => {
    if (err) return res.status(500).json({ error: 'File upload failed.' });
    res.json({ message: 'File uploaded successfully.' });
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
