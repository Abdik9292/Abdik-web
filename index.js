/**
 * index.js - Express backend for user panel, chat, uploads, roles, logs
 */

const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const fs = require('fs');
const path = require('path');
const multer = require('multer');
const sharp = require('sharp');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Directories
const DATA_DIR = path.join(__dirname, 'data');
const PUBLIC_DIR = path.join(__dirname, 'public');
const UPLOADS_DIR = path.join(PUBLIC_DIR, 'uploads');
const PFP_DIR = path.join(UPLOADS_DIR, 'pfps');
const FILES_DIR = path.join(UPLOADS_DIR, 'files');

// Ensure directories exist
for (const dir of [DATA_DIR, UPLOADS_DIR, PFP_DIR, FILES_DIR]) {
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

// Load admin credentials from .env
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH || '';
const SUPERADMIN_USERNAME = 'superadmin';
const SUPERADMIN_PASSWORD_HASH = process.env.SUPERADMIN_PASSWORD_HASH || '';

// JSON data file paths
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const CHAT_FILE = path.join(DATA_DIR, 'chat.json');
const LOG_ADMIN_FILE = path.join(DATA_DIR, 'log_admin.json');
const LOG_SUPERADMIN_FILE = path.join(DATA_DIR, 'log_superadmin.json');

// Load or initialize JSON data
function loadJSON(file, defaultData) {
    try {
        if (fs.existsSync(file)) {
            return JSON.parse(fs.readFileSync(file, 'utf8'));
        }
    } catch (e) {
        console.error(`Error reading ${file}:`, e);
    }
    return defaultData;
}
function saveJSON(file, data) {
    try {
        fs.writeFileSync(file, JSON.stringify(data, null, 2), 'utf8');
    } catch (e) {
        console.error(`Error writing ${file}:`, e);
    }
}

let users = loadJSON(USERS_FILE, {}); 
// users: { username: { id, passwordHash, role, pfpFilename } }

let chatMessages = loadJSON(CHAT_FILE, []); 
// chatMessages: [{ username, message, timestamp, pfpFilename, fileUrl? }]

let logAdmin = loadJSON(LOG_ADMIN_FILE, []);
let logSuperadmin = loadJSON(LOG_SUPERADMIN_FILE, []);

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(PUBLIC_DIR));
app.use(session({
    secret: crypto.randomBytes(64).toString('hex'),
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 }
}));

// Utility functions
function sanitizeUsername(name) {
    return name.trim().toLowerCase();
}

function validateUsername(name) {
    return typeof name === 'string' &&
        /^[a-zA-Z0-9_-]{3,16}$/.test(name);
}

function validatePassword(pw) {
    return typeof pw === 'string' && pw.length >= 8;
}

function genUniqueFilename(ext) {
    return crypto.randomBytes(16).toString('hex') + ext;
}

function genUniqueId() {
    return crypto.randomBytes(12).toString('hex');
}

function logLogin(username, role, success, ip) {
    const entry = {
        username,
        role,
        success,
        ip,
        timestamp: new Date().toISOString()
    };
    if (role === 'admin') {
        logAdmin.push(entry);
        if (logAdmin.length > 1000) logAdmin.shift();
        saveJSON(LOG_ADMIN_FILE, logAdmin);
    }
    logSuperadmin.push(entry);
    if (logSuperadmin.length > 2000) logSuperadmin.shift();
    saveJSON(LOG_SUPERADMIN_FILE, logSuperadmin);
}

// Auth middleware
function requireLogin(req, res, next) {
    if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
    next();
}

function requireRole(...roles) {
    return (req, res, next) => {
        if (!req.session.user || !roles.includes(req.session.user.role)) {
            return res.status(403).json({ error: 'Forbidden' });
        }
        next();
    };
}

// Routes

// Register
app.post('/api/register', async (req, res) => {
    try {
        let { username, password } = req.body;
        username = sanitizeUsername(username);

        if (!validateUsername(username)) {
            return res.status(400).json({ error: 'Invalid username. 3-16 chars, letters/numbers/_/- only.' });
        }
        if (!validatePassword(password)) {
            return res.status(400).json({ error: 'Password must be at least 8 characters.' });
        }
        if (users[username]) {
            return res.status(400).json({ error: 'Username already exists.' });
        }

        const passwordHash = await bcrypt.hash(password, 12);
        const id = genUniqueId();

        users[username] = { id, passwordHash, role: 'user', pfpFilename: null };
        saveJSON(USERS_FILE, users);

        req.session.user = { username, role: 'user', id, pfpFilename: null };
        logLogin(username, 'user', true, req.ip);

        res.json({ success: true, username, role: 'user', id, pfpFilename: null });
    } catch (e) {
        console.error('Register error:', e);
        res.status(500).json({ error: 'Internal server error.' });
    }
});

// Login
app.post('/api/login', async (req, res) => {
    try {
        let { username, password } = req.body;
        username = sanitizeUsername(username);

        // Superadmin check
        if (username === SUPERADMIN_USERNAME) {
            if (!SUPERADMIN_PASSWORD_HASH) {
                return res.status(500).json({ error: 'Superadmin password not configured.' });
            }
            const match = await bcrypt.compare(password, SUPERADMIN_PASSWORD_HASH);
            if (match) {
                req.session.user = { username: SUPERADMIN_USERNAME, role: 'superadmin', id: null, pfpFilename: null };
                logLogin(username, 'superadmin', true, req.ip);
                return res.json({ success: true, username, role: 'superadmin', id: null, pfpFilename: null });
            } else {
                logLogin(username, 'superadmin', false, req.ip);
                return res.status(401).json({ error: 'Invalid credentials.' });
            }
        }

        // Admin check
        if (username === ADMIN_USERNAME) {
            if (!ADMIN_PASSWORD_HASH) {
                return res.status(500).json({ error: 'Admin password not configured.' });
            }
            const match = await bcrypt.compare(password, ADMIN_PASSWORD_HASH);
            if (match) {
                req.session.user = { username: ADMIN_USERNAME, role: 'admin', id: null, pfpFilename: null };
                logLogin(username, 'admin', true, req.ip);
                return res.json({ success: true, username, role: 'admin', id: null, pfpFilename: null });
            } else {
                logLogin(username, 'admin', false, req.ip);
                return res.status(401).json({ error: 'Invalid credentials.' });
            }
        }

        // Regular user login
        const user = users[username];
        if (!user) {
            logLogin(username, 'user', false, req.ip);
            return res.status(401).json({ error: 'Invalid credentials.' });
        }
        const match = await bcrypt.compare(password, user.passwordHash);
        if (!match) {
            logLogin(username, user.role, false, req.ip);
            return res.status(401).json({ error: 'Invalid credentials.' });
        }

        req.session.user = { username, role: user.role, id: user.id, pfpFilename: user.pfpFilename || null };
        logLogin(username, user.role, true, req.ip);

        res.json({ success: true, username, role: user.role, id: user.id, pfpFilename: user.pfpFilename || null });
    } catch (e) {
        console.error('Login error:', e);
        res.status(500).json({ error: 'Internal server error.' });
    }
});

// Logout
app.post('/api/logout', (req, res) => {
    req.session.destroy(() => res.json({ success: true }));
});

// Get current user info
app.get('/api/me', (req, res) => {
    if (!req.session.user) return res.json(null);
    res.json(req.session.user);
});

// -------------------
// Multer setup for uploads

// Profile picture upload (10 MB limit)
const pfpStorage = multer.memoryStorage();
const pfpUpload = multer({
    storage: pfpStorage,
    limits: { fileSize: 10 * 1024 * 1024 }, // 10 MB
    fileFilter: (req, file, cb) => {
        const allowedTypes = /jpeg|jpg|png|gif|bmp/;
        const ext = path.extname(file.originalname).toLowerCase();
        if (allowedTypes.test(ext.substring(1))) {
            cb(null, true);
        } else {
            cb(new Error('Only image files are allowed (jpeg, png, gif, bmp).'));
        }
    }
}).single('pfp');

// File upload in chat (125 MB limit)
const fileStorage = multer.diskStorage({
    destination: FILES_DIR,
    filename: (req, file, cb) => {
        const uniqueName = genUniqueFilename(path.extname(file.originalname));
        cb(null, uniqueName);
    }
});
const chatFileUpload = multer({
    storage: fileStorage,
    limits: { fileSize: 125 * 1024 * 1024 }, // 125 MB
}).single('file');

// Upload profile picture
app.post('/api/upload-pfp', requireLogin, (req, res) => {
    pfpUpload(req, res, async function (err) {
        if (err) {
            return res.status(400).json({ error: err.message });
        }
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded.' });
        }

        // Resize and blur using sharp, save to disk
        const ext = path.extname(req.file.originalname).toLowerCase();
        const filename = genUniqueFilename(ext);
        const filepath = path.join(PFP_DIR, filename);

        try {
            await sharp(req.file.buffer)
                .resize(128, 128, { fit: 'cover' })
                .blur(1)
                .toFile(filepath);

            // Update user data and session
            const username = req.session.user.username;
            if (users[username]) {
                users[username].pfpFilename = filename;
                saveJSON(USERS_FILE, users);
            }
            req.session.user.pfpFilename = filename;

            res.json({ success: true, pfpFilename: filename });
        } catch (e) {
            console.error('PFP processing error:', e);
            res.status(500).json({ error: 'Image processing failed.' });
        }
    });
});

// Send chat message (text + optional file)
app.post('/api/chat/send', requireLogin, (req, res) => {
    chatFileUpload(req, res, (err) => {
        if (err) {
            return res.status(400).json({ error: err.message });
        }

        const messageText = req.body.message?.trim();
        if (!messageText && !req.file) {
            return res.status(400).json({ error: 'Message text or file required.' });
        }

        const username = req.session.user.username;
        const pfpFilename = req.session.user.pfpFilename || null;
        const timestamp = new Date().toISOString();

        let newMessage = {
            username,
            message: messageText || '',
            timestamp,
            pfpFilename
        };

        if (req.file) {
            // Save file URL relative to /uploads/files/
            newMessage.fileUrl = `/uploads/files/${req.file.filename}`;
            newMessage.fileOriginalName = req.file.originalname;
        }

        chatMessages.push(newMessage);
        // Limit to last 1250 messages
        if (chatMessages.length > 1250) chatMessages.shift();

        saveJSON(CHAT_FILE, chatMessages);

        res.json({ success: true, message: newMessage });
    });
});

// Get chat messages (last 50)
app.get('/api/chat', requireLogin, (req, res) => {
    const lastMessages = chatMessages.slice(-50);
    res.json(lastMessages);
});

// Admin: get user login logs
app.get('/api/logs/admin', requireLogin, requireRole('admin', 'superadmin'), (req, res) => {
    res.json(logAdmin);
});

// Superadmin: get all logs
app.get('/api/logs/superadmin', requireLogin, requireRole('superadmin'), (req, res) => {
    res.json(logSuperadmin);
});

// Catch-all for frontend
app.get('*', (req, res) => {
    res.sendFile(path.join(PUBLIC_DIR, 'index.html'));
});

// Start server
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
