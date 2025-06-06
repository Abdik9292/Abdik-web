require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');
const http = require('http');
const WebSocket = require('ws');

const app = express();
const server = http.createServer(app);
const PORT = process.env.PORT || 3000;

// Serve static files from public
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.use(session({
  secret: 'your-secret-session-key',
  resave: false,
  saveUninitialized: false,
}));

const USERS_FILE = path.join(__dirname, 'config', 'users.json');
const LOGS_FILE = path.join(__dirname, 'config', 'logs.json');

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

function hasRegisteredIP(ip) {
  const users = loadUsers();
  return users.some(u => u.ip === ip);
}

function addLog(username, ip) {
  const logs = loadLogs();
  logs.push({ username, ip, timestamp: new Date().toISOString() });
  saveLogs(logs);
}

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

// --- Routes ---
app.post('/register', (req, res) => {
  const { username, password } = req.body;
  const ip = req.ip;

  if (!username || !password) return res.status(400).json({ error: 'Missing username or password' });
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

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const ip = req.ip;

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

  const users = loadUsers();
  const user = users.find(u => u.username === username && u.password === password);
  if (!user) return res.status(401).json({ error: 'Invalid username or password' });

  req.session.user = { username: user.username, role: 'user' };
  addLog(username, ip);
  res.json({ success: true, role: 'user' });
});

app.post('/logout', authRequired, (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true });
  });
});

// In-memory chat
const chatMessages = [];

app.get('/chat', authRequired, (req, res) => {
  res.json(chatMessages);
});

app.post('/chat', authRequired, (req, res) => {
  const { message } = req.body;
  if (!message) return res.status(400).json({ error: 'No message' });

  chatMessages.push({
    user: req.session.user.username,
    message,
    timestamp: new Date().toISOString()
  });

  res.json({ success: true });
});

app.post('/upload', authRequired, (req, res) => {
  res.json({ success: true, message: 'Upload endpoint placeholder' });
});

app.get('/logs', adminRequired, (req, res) => {
  res.json(loadLogs());
});

// Serve frontend (index.html in public/)
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// --- WebSocket Setup ---
const wss = new WebSocket.Server({ server });

let clients = [];

wss.on('connection', (ws) => {
  clients.push(ws);
  console.log('Client connected. Total clients:', clients.length);

  ws.on('message', (message) => {
    console.log('Received:', message);

    // Broadcast to others
    clients.forEach(client => {
      if (client !== ws && client.readyState === WebSocket.OPEN) {
        client.send(message);
      }
    });
  });

  ws.on('close', () => {
    clients = clients.filter(c => c !== ws);
    console.log('Client disconnected. Total clients:', clients.length);
  });

  ws.on('error', (error) => {
    console.error('WebSocket error:', error);
  });
});

server.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
