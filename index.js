// index.js

const express = require('express');
const session = require('express-session');
const fileUpload = require('express-fileupload');
const fs = require('fs');
const path = require('path');
const dotenv = require('dotenv');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(fileUpload({
  limits: { fileSize: 1 * 1024 * 1024 }, // 1MB limit
  abortOnLimit: true,
  responseOnLimit: 'File size limit has been reached',
}));
app.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: true,
  cookie: {
    secure: false, // Set to true if using HTTPS
    sameSite: 'lax',
  },
}));
app.use(express.static(path.join(__dirname, 'public')));

// Ensure necessary directories and files exist
const ensureFile = (filePath, defaultContent) => {
  if (!fs.existsSync(filePath)) {
    fs.writeFileSync(filePath, JSON.stringify(defaultContent, null, 2));
  }
};

const configDir = path.join(__dirname, 'config');
if (!fs.existsSync(configDir)) fs.mkdirSync(configDir);

ensureFile(path.join(configDir, 'users.json'), {});
ensureFile(path.join(configDir, 'chat.json'), []);
ensureFile(path.join(configDir, 'log.json'), []);
ensureFile(path.join(configDir, 'superlog.json'), []);

const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir);

// Helper functions
const loadJSON = (filePath) => JSON.parse(fs.readFileSync(filePath));
const saveJSON = (filePath, data) => fs.writeFileSync(filePath, JSON.stringify(data, null, 2));

// Load superadmin credentials
const superadminPath = path.join(__dirname, 'superadmin.json');
let superadmin = { username: 'superadmin', password: 'superpassword' }; // Default
if (fs.existsSync(superadminPath)) {
  superadmin = loadJSON(superadminPath);
} else {
  saveJSON(superadminPath, superadmin);
}

// Routes

// Register
app.post('/register', (req, res) => {
  const { username, password } = req.body;
  if (
    typeof username !== 'string' ||
    typeof password !== 'string' ||
    username.length < 3 ||
    username.length > 16 ||
    password.length < 8
  ) {
    return res.status(400).json({ error: 'Invalid username or password format.' });
  }

  const users = loadJSON(path.join(configDir, 'users.json'));
  if (users[username]) {
    return res.status(400).json({ error: 'Username already exists.' });
  }

  users[username] = { password, role: 'user' };
  saveJSON(path.join(configDir, 'users.json'), users);
  req.session.user = { username, role: 'user' };
  res.json({ message: 'Registered successfully.', role: 'user' });
});

// Login
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const users = loadJSON(path.join(configDir, 'users.json'));

  if (users[username] && users[username].password === password) {
    req.session.user = { username, role: users[username].role };
    logLogin(username, req.ip, users[username].role);
    return res.json({ message: 'Login successful.', role: users[username].role });
  }

  if (
    username === process.env.ADMIN_USERNAME &&
    password === process.env.ADMIN_PASSWORD
  ) {
    req.session.user = { username, role: 'admin' };
    logLogin(username, req.ip, 'admin');
    return res.json({ message: 'Admin login successful.', role: 'admin' });
  }

  if (
    username === superadmin.username &&
    password === superadmin.password
  ) {
    req.session.user = { username, role: 'superadmin' };
    logLogin(username, req.ip, 'superadmin');
    return res.json({ message: 'Superadmin login successful.', role: 'superadmin' });
  }

  res.status(401).json({ error: 'Invalid credentials.' });
});

// Logout
app.post('/logout', (req, res) => {
  req.session.destroy(() => res.json({ message: 'Logged out.' }));
});

// Chat - Get messages
app.get('/chat', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
  const chat = loadJSON(path.join(configDir, 'chat.json'));
  res.json(chat.slice(-50));
});

// Chat - Post message
app.post('/chat', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
  const { message } = req.body;
  if (typeof message !== 'string' || message.trim() === '') {
    return res.status(400).json({ error: 'Message cannot be empty.' });
  }

  const chatPath = path.join(configDir, 'chat.json');
  const chat = loadJSON(chatPath);
  chat.push({
    user: req.session.user.username,
    message: message.trim(),
    timestamp: Date.now(),
  });

  if (chat.length > 1250) chat.splice(0, chat.length - 1250);
  saveJSON(chatPath, chat);
  res.json({ message: 'Message sent.' });
});

// Upload profile image
app.post('/upload', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
  if (!req.files || !req.files.file) {
    return res.status(400).json({ error: 'No file uploaded.' });
  }

  const file = req.files.file;
  if (file.mimetype !== 'image/png') {
    return res.status(400).json({ error: 'Only PNG files are allowed.' });
  }

  const filename = `${req.session.user.username}.png`;
  const filepath = path.join(uploadsDir, filename);

  file.mv(filepath, (err) => {
    if (err) return res.status(500).json({ error: 'File upload failed.' });
    res.json({ message: 'File uploaded successfully.' });
  });
});

// Get logs
app.get('/logs', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });

  const role = req.session.user.role;
  if (role === 'admin') {
    const logs = loadJSON(path.join(configDir, 'log.json'));
    return res.json(logs);
  }

  if (role === 'superadmin') {
    const logs = loadJSON(path.join(configDir, 'superlog.json'));
    return res.json(logs);
  }

  res.status(403).json({ error: 'Forbidden' });
});

// Helper function to log logins
const logLogin = (username, ip, role) => {
  const timestamp = new Date().toISOString();
  const logEntry = { username, ip, role, timestamp };

  if (role === 'user') {
    const logPath = path.join(configDir, 'log.json');
    const logs = loadJSON(logPath);
    logs.push(logEntry);
    saveJSON(logPath, logs);
  }

  const superlogPath = path.join(configDir, 'superlog.json');
  const superlogs = loadJSON(superlogPath);
  superlogs.push(logEntry);
  saveJSON(superlogPath, superlogs);
};

// Start server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
