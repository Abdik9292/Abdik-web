
// server.js
const express = require("express");
const session = require("express-session");
const fs = require("fs");
const path = require("path");
const multer = require("multer");
const app = express();

const configAdmin = require("./config_admin.js");
const USERS_FILE = path.join(__dirname, "config_users.json");

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session setup
app.use(session({
  secret: "your_secret_here",
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 24*60*60*1000 }
}));

// Multer setup for uploads
const upload = multer({ dest: path.join(__dirname, "uploads/") });

// Utility: load users from JSON file
function loadUsers() {
  try {
    const data = fs.readFileSync(USERS_FILE, "utf8");
    return JSON.parse(data);
  } catch {
    return [];
  }
}

// Utility: save users to JSON file
function saveUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

// Utility: check if username exists
function userExists(username) {
  const users = loadUsers();
  return users.some(u => u.username.toLowerCase() === username.toLowerCase());
}

// Utility: get user by username
function getUser(username) {
  const users = loadUsers();
  return users.find(u => u.username.toLowerCase() === username.toLowerCase());
}

// Utility: IP logger file
const LOG_FILE = path.join(__dirname, "login_logs.txt");

// Middleware to get IP address (trust proxy if behind proxies)
function getClientIp(req) {
  return req.headers['x-forwarded-for']?.split(',')[0].trim() || req.connection.remoteAddress;
}

// Save login log
function logLogin(username, ip) {
  const entry = `${new Date().toISOString()} - ${username} logged in from IP: ${ip}`;
  fs.appendFileSync(LOG_FILE, entry + "\n");
}

// Register route
app.post("/api/register", (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.json({ success: false, message: "Missing username or password" });
  }

  // Admin registration not allowed
  if (username.toLowerCase() === configAdmin.admin.username.toLowerCase()) {
    return res.json({ success: false, message: "Cannot register as admin" });
  }

  const users = loadUsers();

  if (users.some(u => u.username.toLowerCase() === username.toLowerCase())) {
    return res.json({ success: false, message: "Username already taken" });
  }

  const ip = getClientIp(req);

  // One registration per IP
  if (users.some(u => u.ip === ip)) {
    return res.json({ success: false, message: "One account per IP allowed" });
  }

  // Add new user
  users.push({ username, password, ip });
  saveUsers(users);

  return res.json({ success: true, message: "Registration successful. Please login." });
});

// Login route
app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.json({ success: false, message: "Missing username or password" });
  }

  // Check admin login
  if (username === configAdmin.admin.username && password === configAdmin.admin.password) {
    req.session.user = { username, role: "admin" };
    const ip = getClientIp(req);
    logLogin(username, ip);
    return res.json({ success: true, role: "admin" });
  }

  // Check user login
  const user = getUser(username);
  if (!user || user.password !== password) {
    return res.json({ success: false, message: "Invalid username or password" });
  }

  req.session.user = { username, role: "user" };
  const ip = getClientIp(req);
  logLogin(username, ip);

  return res.json({ success: true, role: "user" });
});

// Logout route
app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true });
  });
});

// Session check route
app.get("/api/session", (req, res) => {
  if (req.session.user) {
    res.json({ loggedIn: true, username: req.session.user.username, role: req.session.user.role });
  } else {
    res.json({ loggedIn: false });
  }
});

// Admin only middleware
function requireAdmin(req, res, next) {
  if (req.session.user && req.session.user.role === "admin") {
    next();
  } else {
    res.status(403).json({ success: false, message: "Forbidden" });
  }
}

// Chat messages (in-memory)
let chatMessages = [];

// Chat route
app.post("/api/chat", (req, res) => {
  if (!req.session.user) {
    return res.json({ success: false, message: "Not logged in" });
  }
  const user = req.session.user.username;
  const msg = req.body.message;
  if (!msg || msg.trim().length === 0) {
    return res.json({ success: false, message: "Empty message" });
  }

  const fullMsg = `${user}: ${msg}`;
  chatMessages.push(fullMsg);

  // Limit chat history length
  if (chatMessages.length > 100) chatMessages.shift();

  return res.json({ success: true, message: fullMsg });
});

// Upload route (any logged in user)
app.post("/api/upload", upload.single("file"), (req, res) => {
  if (!req.session.user) {
    return res.json({ success: false, message: "Not logged in" });
  }
  if (!req.file) {
    return res.json({ success: false, message: "No file uploaded" });
  }
  return res.json({ success: true, message: "File uploaded successfully" });
});

// Admin logs route
app.get("/api/logs", requireAdmin, (req, res) => {
  try {
    const logs = fs.readFileSync(LOG_FILE, "utf8").trim().split("\n").reverse();
    res.json({ success: true, logs });
  } catch {
    res.json({ success: false, logs: [] });
  }
});

// Serve index.html
app.use(express.static(path.join(__dirname)));

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
