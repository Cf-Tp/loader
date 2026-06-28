const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// =============================================
// BANCO DE DADOS
// =============================================
const db = new sqlite3.Database('./database.db');

db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_license TEXT UNIQUE NOT NULL,
            subscription TEXT DEFAULT 'free',
            expires_in TEXT DEFAULT '7d',
            expires_at DATETIME,
            status TEXT DEFAULT 'Not Used',
            hwid TEXT,
            username TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            used_at DATETIME,
            banned INTEGER DEFAULT 0,
            ban_reason TEXT
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT,
            password TEXT,
            key_license TEXT UNIQUE,
            subscription TEXT DEFAULT 'free',
            hwid TEXT,
            expires_at DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_login DATETIME,
            is_banned INTEGER DEFAULT 0
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    `);

    const defaultPassword = bcrypt.hashSync('admin123', 10);
    db.run('INSERT OR IGNORE INTO admins (id, username, password) VALUES (1, ?, ?)', ['admin', defaultPassword]);
});

// =============================================
// FUNÇÕES AUXILIARES
// =============================================
function generateKey() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let key = '';
    for (let i = 0; i < 16; i++) {
        key += chars.charAt(Math.floor(Math.random() * chars.length));
        if (i === 3 || i === 7 || i === 11) key += '-';
    }
    return key;
}

function getExpirationDate(expiresIn) {
    if (expiresIn === 'infinity') return null;
    const now = new Date();
    const value = parseInt(expiresIn);
    const unit = expiresIn.replace(/[0-9]/g, '');
    switch (unit) {
        case 'h': now.setHours(now.getHours() + value); break;
        case 'd': now.setDate(now.getDate() + value); break;
        case 'm': now.setMonth(now.getMonth() + value); break;
        case 'y': now.setFullYear(now.getFullYear() + value); break;
        default: now.setDate(now.getDate() + 7);
    }
    return now.toISOString();
}

// =============================================
// ROTAS DA API
// =============================================

app.get('/', (req, res) => {
    res.json({ status: 'online', message: 'Loader API funcionando!' });
});

// ============ GERAR KEY ============
app.post('/api/generate-key', (req, res) => {
    const { admin_token, subscription, expires_in, quantity } = req.body;

    if (admin_token !== 'ADMIN_SECRET_TOKEN_123') {
        return res.status(403).json({ success: false, message: 'Unauthorized' });
    }

    const qty = parseInt(quantity) || 1;
    const keys = [];
    let inserted = 0;

    for (let i = 0; i < qty; i++) {
        const key = generateKey();
        const expiresAt = getExpirationDate(expires_in || '7d');

        db.run(
            'INSERT INTO keys (key_license, subscription, expires_in, expires_at, status) VALUES (?, ?, ?, ?, ?)',
            [key, subscription || 'premium', expires_in || '7d', expiresAt, 'Not Used'],
            function(err) {
                if (!err) keys.push(key);
                inserted++;
                if (inserted === qty) {
                    res.json({ success: true, keys: keys, message: qty + ' key(s) generated' });
                }
            }
        );
    }
});

// ============ LISTAR KEYS ============
app.get('/api/keys', (req, res) => {
    const { admin_token } = req.query;
    if (admin_token !== 'ADMIN_SECRET_TOKEN_123') {
        return res.status(403).json({ success: false, message: 'Unauthorized' });
    }

    db.all('SELECT * FROM keys ORDER BY created_at DESC', (err, keys) => {
        if (err) return res.json({ success: false, message: 'Database error' });
        res.json({ success: true, keys: keys || [] });
    });
});

// ============ BAN KEY ============
app.post('/api/ban-key', (req, res) => {
    const { admin_token, key, reason } = req.body;
    if (admin_token !== 'ADMIN_SECRET_TOKEN_123') {
        return res.status(403).json({ success: false, message: 'Unauthorized' });
    }

    db.run('UPDATE keys SET banned = 1, ban_reason = ? WHERE key_license = ?', [reason || 'No reason', key], function(err) {
        if (err) return res.json({ success: false, message: 'Error banning key' });
        res.json({ success: true, message: 'Key banned' });
    });
});

// ============ UNBAN KEY ============
app.post('/api/unban-key', (req, res) => {
    const { admin_token, key } = req.body;
    if (admin_token !== 'ADMIN_SECRET_TOKEN_123') {
        return res.status(403).json({ success: false, message: 'Unauthorized' });
    }

    db.run('UPDATE keys SET banned = 0, ban_reason = NULL WHERE key_license = ?', [key], function(err) {
        if (err) return res.json({ success: false, message: 'Error unbanning key' });
        res.json({ success: true, message: 'Key unbanned' });
    });
});

// ============ DELETAR KEY ============
app.delete('/api/delete-key/:key', (req, res) => {
    const { admin_token } = req.query;
    const { key } = req.params;

    if (admin_token !== 'ADMIN_SECRET_TOKEN_123') {
        return res.status(403).json({ success: false, message: 'Unauthorized' });
    }

    db.run('DELETE FROM keys WHERE key_license = ?', [key], function(err) {
        if (err) return res.json({ success: false, message: 'Error deleting key' });
        res.json({ success: true, message: 'Key deleted' });
    });
});

// ============ LISTAR USUARIOS ============
app.get('/api/users', (req, res) => {
    const { admin_token } = req.query;
    if (admin_token !== 'ADMIN_SECRET_TOKEN_123') {
        return res.status(403).json({ success: false, message: 'Unauthorized' });
    }

    db.all('SELECT * FROM users ORDER BY created_at DESC', (err, users) => {
        if (err) return res.json({ success: false, message: 'Database error' });
        res.json({ success: true, users: users || [] });
    });
});

// ============ BAN USER ============
app.post('/api/ban-user', (req, res) => {
    const { admin_token, username, reason } = req.body;
    if (admin_token !== 'ADMIN_SECRET_TOKEN_123') {
        return res.status(403).json({ success: false, message: 'Unauthorized' });
    }

    db.run('UPDATE users SET is_banned = 1 WHERE username = ?', [username], function(err) {
        if (err) return res.json({ success: false, message: 'Error banning user' });
        res.json({ success: true, message: 'User banned' });
    });
});

// ============ UNBAN USER ============
app.post('/api/unban-user', (req, res) => {
    const { admin_token, username } = req.body;
    if (admin_token !== 'ADMIN_SECRET_TOKEN_123') {
        return res.status(403).json({ success: false, message: 'Unauthorized' });
    }

    db.run('UPDATE users SET is_banned = 0 WHERE username = ?', [username], function(err) {
        if (err) return res.json({ success: false, message: 'Error unbanning user' });
        res.json({ success: true, message: 'User unbanned' });
    });
});

// ============ LOGIN ============
app.post('/api/login', (req, res) => {
    const { key, hwid } = req.body;

    if (!key) return res.json({ success: false, message: 'License key required' });
    if (!hwid) return res.json({ success: false, message: 'HWID required' });

    db.get('SELECT * FROM keys WHERE key_license = ?', [key], (err, keyData) => {
        if (err || !keyData) {
            return res.json({ success: false, message: 'Invalid license key' });
        }

        if (keyData.banned) {
            return res.json({ success: false, message: 'Key is banned: ' + (keyData.ban_reason || 'No reason') });
        }

        if (keyData.status === 'Used') {
            if (keyData.hwid && keyData.hwid !== hwid) {
                return res.json({ success: false, message: 'HWID mismatch! This key is locked to another device.' });
            }

            db.get('SELECT * FROM users WHERE key_license = ?', [key], (err, user) => {
                if (err || !user) return res.json({ success: false, message: 'User not found' });
                if (user.is_banned) return res.json({ success: false, message: 'User is banned' });

                if (user.expires_at && new Date(user.expires_at) < new Date()) {
                    return res.json({ success: false, message: 'License expired' });
                }

                db.run('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', [user.id]);

                res.json({
                    success: true,
                    message: 'Login successful',
                    user: {
                        id: user.id,
                        username: user.username,
                        email: user.email,
                        subscription: user.subscription,
                        expires_at: user.expires_at
                    }
                });
            });
            return;
        }

        // Key não usada - ativar
        const expiresAt = keyData.expires_at;
        const username = 'user_' + Date.now().toString().slice(-6);

        db.run(
            'INSERT INTO users (username, key_license, subscription, hwid, expires_at) VALUES (?, ?, ?, ?, ?)',
            [username, key, keyData.subscription, hwid, expiresAt],
            function(err) {
                if (err) return res.json({ success: false, message: 'Error activating key: ' + err.message });

                const userId = this.lastID;
                db.run(
                    'UPDATE keys SET status = "Used", hwid = ?, username = ?, used_at = CURRENT_TIMESTAMP WHERE key_license = ?',
                    [hwid, username, key]
                );

                res.json({
                    success: true,
                    message: 'Key activated successfully',
                    user: {
                        id: userId,
                        username: username,
                        subscription: keyData.subscription,
                        expires_at: expiresAt
                    }
                });
            }
        );
    });
});

// ============ REGISTER ============
app.post('/api/register', (req, res) => {
    const { username, email, password, key, hwid } = req.body;

    if (!username || !email || !password || !key) {
        return res.json({ success: false, message: 'All fields required' });
    }
    if (username.length < 3) return res.json({ success: false, message: 'Username must be at least 3 characters' });
    if (password.length < 6) return res.json({ success: false, message: 'Password must be at least 6 characters' });
    if (!email.includes('@')) return res.json({ success: false, message: 'Invalid email' });

    db.get('SELECT id FROM users WHERE username = ?', [username], (err, existingUser) => {
        if (err) return res.json({ success: false, message: 'Database error' });
        if (existingUser) return res.json({ success: false, message: 'Username already exists' });

        db.get('SELECT * FROM keys WHERE key_license = ?', [key], (err, keyData) => {
            if (err || !keyData) return res.json({ success: false, message: 'Invalid license key' });
            if (keyData.banned) return res.json({ success: false, message: 'Key is banned' });
            if (keyData.status === 'Used') return res.json({ success: false, message: 'Key already used' });

            const hashedPassword = bcrypt.hashSync(password, 10);
            const expiresAt = keyData.expires_at;

            db.run(
                'INSERT INTO users (username, email, password, key_license, subscription, hwid, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
                [username, email, hashedPassword, key, keyData.subscription, hwid || null, expiresAt],
                function(err) {
                    if (err) return res.json({ success: false, message: 'Error creating user: ' + err.message });

                    db.run(
                        'UPDATE keys SET status = "Used", hwid = ?, username = ?, used_at = CURRENT_TIMESTAMP WHERE key_license = ?',
                        [hwid || null, username, key]
                    );

                    res.json({
                        success: true,
                        message: 'Account created successfully',
                        user: {
                            id: this.lastID,
                            username: username,
                            email: email,
                            subscription: keyData.subscription,
                            expires_at: expiresAt
                        }
                    });
                }
            );
        });
    });
});

// ============ VERIFICAR TOKEN ============
app.post('/api/verify', (req, res) => {
    const { token } = req.body;
    if (!token) return res.json({ success: false, message: 'Token required' });

    try {
        const decoded = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString());
        const userId = decoded.userId;

        db.get('SELECT * FROM users WHERE id = ?', [userId], (err, user) => {
            if (err || !user) return res.json({ success: false, message: 'Invalid token' });
            if (user.is_banned) return res.json({ success: false, message: 'User is banned' });

            res.json({
                success: true,
                user: {
                    id: user.id,
                    username: user.username,
                    email: user.email,
                    subscription: user.subscription,
                    expires_at: user.expires_at
                }
            });
        });
    } catch {
        res.json({ success: false, message: 'Invalid token' });
    }
});

// ============ LOGOUT ============
app.post('/api/logout', (req, res) => {
    res.json({ success: true, message: 'Logged out' });
});

// =============================================
// INICIAR SERVIDOR
// =============================================
app.listen(PORT, () => {
    console.log('🚀 API rodando em http://localhost:' + PORT);
    console.log('🔑 Admin Token: ADMIN_SECRET_TOKEN_123');
    console.log('🔐 Admin Login: admin / admin123');
});
