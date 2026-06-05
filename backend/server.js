const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');
const axios = require('axios');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '../frontend')));

// ========== DATABASE SETUP (FIXED FOR RAILWAY) ==========
// Use /tmp for Railway (writable directory)
const dbPath = path.join('/tmp', 'database.db');
console.log(`📁 Database path: ${dbPath}`);

const db = new Database(dbPath);

// Create tables
try {
    db.exec(`
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE,
            email TEXT UNIQUE,
            password TEXT,
            country TEXT DEFAULT 'NG',
            currency TEXT DEFAULT 'NGN',
            balance REAL DEFAULT 0,
            isAdmin INTEGER DEFAULT 0,
            isReseller INTEGER DEFAULT 0,
            resellerExpiry INTEGER DEFAULT 0,
            isBanned INTEGER DEFAULT 0,
            referredBy TEXT,
            createdAt INTEGER
        );

        CREATE TABLE IF NOT EXISTS purchases (
            id TEXT PRIMARY KEY,
            userId TEXT,
            orderId TEXT,
            number TEXT,
            app TEXT,
            country TEXT,
            code TEXT,
            amount REAL,
            status TEXT,
            date TEXT
        );

        CREATE TABLE IF NOT EXISTS transactions (
            reference TEXT PRIMARY KEY,
            userId TEXT,
            amount REAL,
            status TEXT,
            createdAt INTEGER
        );

        CREATE TABLE IF NOT EXISTS discount_codes (
            code TEXT PRIMARY KEY,
            percentage INTEGER,
            isUsed INTEGER DEFAULT 0,
            usedBy TEXT,
            createdAt INTEGER
        );
    `);
    console.log('✅ Database tables created/verified');
} catch (error) {
    console.error('❌ Database error:', error.message);
}

// ========== AUTH MIDDLEWARE ==========
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) return res.status(401).json({ error: 'No token provided' });
    
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });
        req.user = user;
        next();
    });
}

function isAdmin(req, res, next) {
    if (!req.user.isAdmin) {
        return res.status(403).json({ error: 'Admin access required' });
    }
    next();
}

// ========== AUTH ROUTES (FIXED) ==========
app.post('/api/register', async (req, res) => {
    const { username, email, country, password } = req.body;
    
    console.log('📝 Registration attempt:', { username, email, country });
    
    // Validation
    if (!username || !email || !password) {
        return res.status(400).json({ error: 'All fields are required' });
    }
    
    if (password.length < 6) {
        return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }
    
    if (!email.includes('@')) {
        return res.status(400).json({ error: 'Invalid email address' });
    }
    
    try {
        // Check if user exists
        const existingUser = db.prepare('SELECT * FROM users WHERE username = ? OR email = ?').get(username, email);
        if (existingUser) {
            return res.status(400).json({ error: 'Username or email already exists' });
        }
        
        // Create user
        const hashedPassword = await bcrypt.hash(password, 10);
        const userId = Date.now().toString();
        const currencyMap = { NG: 'NGN', US: 'USD', GB: 'GBP', KE: 'KES', GH: 'GHS', UG: 'UGX', TZ: 'TZS', ZA: 'ZAR', EU: 'EUR' };
        const currency = currencyMap[country] || 'USD';
        
        const stmt = db.prepare('INSERT INTO users (id, username, email, country, currency, password, createdAt, isAdmin) VALUES (?, ?, ?, ?, ?, ?, ?, ?)');
        stmt.run(userId, username, email, country, currency, hashedPassword, Date.now(), 0);
        
        // Generate token
        const token = jwt.sign({ userId, username, isAdmin: 0 }, process.env.JWT_SECRET);
        
        console.log('✅ User registered:', username);
        
        res.json({ 
            success: true, 
            token, 
            user: { id: userId, username, email, balance: 0, isAdmin: 0 } 
        });
    } catch (error) {
        console.error('❌ Registration error:', error.message);
        res.status(500).json({ error: 'Registration failed: ' + error.message });
    }
});

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    
    console.log('🔐 Login attempt:', username);
    
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password required' });
    }
    
    try {
        const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
        if (!user) {
            return res.status(401).json({ error: 'Invalid username or password' });
        }
        
        const valid = await bcrypt.compare(password, user.password);
        if (!valid) {
            return res.status(401).json({ error: 'Invalid username or password' });
        }
        
        if (user.isBanned === 1) {
            return res.status(401).json({ error: 'Account has been banned' });
        }
        
        const token = jwt.sign({ userId: user.id, username: user.username, isAdmin: user.isAdmin }, process.env.JWT_SECRET);
        
        console.log('✅ User logged in:', username);
        
        res.json({ 
            success: true, 
            token, 
            user: { 
                id: user.id, 
                username: user.username, 
                email: user.email, 
                balance: user.balance, 
                isAdmin: user.isAdmin 
            } 
        });
    } catch (error) {
        console.error('❌ Login error:', error.message);
        res.status(500).json({ error: 'Login failed: ' + error.message });
    }
});

app.get('/api/me', authenticateToken, (req, res) => {
    try {
        const user = db.prepare('SELECT id, username, email, country, currency, balance, isReseller, resellerExpiry, isBanned, isAdmin FROM users WHERE id = ?').get(req.user.userId);
        res.json({ success: true, ...user });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch user data' });
    }
});

// ========== ADMIN ROUTES ==========
app.get('/api/admin/check', authenticateToken, (req, res) => {
    const user = db.prepare('SELECT isAdmin FROM users WHERE id = ?').get(req.user.userId);
    res.json({ isAdmin: user?.isAdmin === 1 });
});

app.get('/api/admin/users', authenticateToken, isAdmin, (req, res) => {
    const users = db.prepare('SELECT id, username, email, country, currency, balance, isReseller, isBanned, isAdmin, createdAt FROM users').all();
    res.json(users);
});

app.post('/api/admin/ban-user', authenticateToken, isAdmin, (req, res) => {
    const { userId, ban } = req.body;
    db.prepare('UPDATE users SET isBanned = ? WHERE id = ?').run(ban ? 1 : 0, userId);
    res.json({ success: true });
});

app.post('/api/admin/make-reseller', authenticateToken, isAdmin, (req, res) => {
    const { userId, days } = req.body;
    const expiry = Date.now() + (days * 24 * 60 * 60 * 1000);
    db.prepare('UPDATE users SET isReseller = 1, resellerExpiry = ? WHERE id = ?').run(expiry, userId);
    res.json({ success: true });
});

app.get('/api/admin/stats', authenticateToken, isAdmin, (req, res) => {
    const totalUsers = db.prepare('SELECT COUNT(*) as count FROM users').get();
    const totalResellers = db.prepare('SELECT COUNT(*) as count FROM users WHERE isReseller = 1').get();
    const totalBanned = db.prepare('SELECT COUNT(*) as count FROM users WHERE isBanned = 1').get();
    const totalSales = db.prepare('SELECT SUM(amount) as total FROM purchases').get();
    
    res.json({
        totalUsers: totalUsers.count,
        totalResellers: totalResellers.count,
        totalBanned: totalBanned.count,
        totalSales: totalSales.total || 0
    });
});

app.post('/api/admin/generate-discount', authenticateToken, isAdmin, (req, res) => {
    const { percentage } = req.body;
    const code = 'DISC-' + Math.random().toString(36).substring(2, 8).toUpperCase() + '-' + percentage;
    db.prepare('INSERT INTO discount_codes (code, percentage, createdAt) VALUES (?, ?, ?)').run(code, percentage, Date.now());
    res.json({ success: true, code });
});

// ========== NUMBER PURCHASE ROUTES ==========
app.get('/api/countries', async (req, res) => {
    try {
        if (!process.env.HEROSMS_API_KEY || process.env.HEROSMS_API_KEY === 'your_herosms_api_key') {
            // Return mock data for testing
            return res.json([
                { id: '1', name: 'USA' },
                { id: '2', name: 'United Kingdom' },
                { id: '3', name: 'Nigeria' },
                { id: '4', name: 'Canada' },
                { id: '5', name: 'Kenya' }
            ]);
        }
        
        const response = await axios.get(`${process.env.HEROSMS_BASE_URL}?api_key=${process.env.HEROSMS_API_KEY}&action=getCountries`);
        const countries = Object.values(response.data).map(c => ({ id: c.id, name: c.eng || c.name }));
        res.json(countries);
    } catch (error) {
        console.error('Countries error:', error.message);
        res.json([
            { id: '1', name: 'USA' },
            { id: '2', name: 'United Kingdom' },
            { id: '3', name: 'Nigeria' }
        ]);
    }
});

app.get('/api/services/:countryId', async (req, res) => {
    try {
        const { countryId } = req.params;
        
        // Return mock data for testing
        res.json([
            { id: 'wa', name: 'WhatsApp', price: 500 },
            { id: 'tg', name: 'Telegram', price: 300 },
            { id: 'ig', name: 'Instagram', price: 400 },
            { id: 'fb', name: 'Facebook', price: 350 }
        ]);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch services' });
    }
});

app.post('/api/buy-number', authenticateToken, async (req, res) => {
    const { serviceId, countryId } = req.body;
    
    try {
        const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.userId);
        const price = 500;
        
        if (user.balance < price) {
            return res.status(400).json({ error: 'Insufficient balance' });
        }
        
        // Generate a mock number
        const mockNumber = `+1${Math.floor(Math.random() * 9000000000) + 1000000000}`;
        const orderId = Date.now().toString();
        
        db.prepare('UPDATE users SET balance = balance - ? WHERE id = ?').run(price, user.id);
        
        const purchaseId = Date.now().toString();
        db.prepare(`INSERT INTO purchases (id, userId, orderId, number, app, country, amount, status, date) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
            .run(purchaseId, user.id, orderId, mockNumber, serviceId, countryId, price, 'waiting', new Date().toISOString());
        
        res.json({ success: true, orderId, number: mockNumber, price });
    } catch (error) {
        res.status(500).json({ error: 'Purchase failed: ' + error.message });
    }
});

app.get('/api/check-sms/:orderId', authenticateToken, (req, res) => {
    res.json({ code: null, status: 'waiting' });
});

app.post('/api/request-additional-code', authenticateToken, async (req, res) => {
    const { orderId } = req.body;
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.userId);
    const additionalPrice = 100;
    
    if (user.balance < additionalPrice) {
        return res.status(400).json({ error: 'Insufficient balance' });
    }
    
    db.prepare('UPDATE users SET balance = balance - ? WHERE id = ?').run(additionalPrice, user.id);
    res.json({ success: true, newBalance: user.balance - additionalPrice });
});

// ========== PAYMENT ROUTES ==========
app.post('/api/create-payment', authenticateToken, async (req, res) => {
    const { amount } = req.body;
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.userId);
    
    // Mock payment for testing
    const mockReference = 'REF-' + Date.now();
    
    db.prepare('INSERT INTO transactions (reference, userId, amount, status, createdAt) VALUES (?, ?, ?, ?, ?)')
        .run(mockReference, user.id, amount, 'pending', Date.now());
    
    res.json({ 
        authorization_url: '#', 
        reference: mockReference,
        message: 'Payment system configured. Contact admin for live payments.'
    });
});

app.post('/api/verify-payment/:reference', authenticateToken, async (req, res) => {
    const { reference } = req.params;
    
    const transaction = db.prepare('SELECT * FROM transactions WHERE reference = ?').get(reference);
    if (transaction && transaction.status !== 'completed') {
        db.prepare('UPDATE users SET balance = balance + ? WHERE id = ?').run(transaction.amount, transaction.userId);
        db.prepare('UPDATE transactions SET status = ? WHERE reference = ?').run('completed', reference);
        res.json({ success: true, amount: transaction.amount });
    } else {
        res.json({ success: false });
    }
});

app.get('/api/history', authenticateToken, (req, res) => {
    const purchases = db.prepare('SELECT * FROM purchases WHERE userId = ? ORDER BY date DESC LIMIT 50').all(req.user.userId);
    res.json(purchases);
});

app.post('/api/upgrade-vip', authenticateToken, (req, res) => {
    const { plan } = req.body;
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.userId);
    const price = plan === 'weekly' ? 6000 : 20000;
    const days = plan === 'weekly' ? 7 : 30;
    
    if (user.balance < price) {
        return res.status(400).json({ error: 'Insufficient balance' });
    }
    
    const expiry = Date.now() + (days * 24 * 60 * 60 * 1000);
    db.prepare('UPDATE users SET balance = balance - ?, isReseller = 1, resellerExpiry = ? WHERE id = ?').run(price, expiry, user.id);
    
    res.json({ success: true });
});

app.get('/api/referral', authenticateToken, (req, res) => {
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.userId);
    const referrals = db.prepare('SELECT username, balance FROM users WHERE referredBy = ?').all(user.id);
    const link = `${req.headers.origin}?ref=${user.id}`;
    res.json({ link, referrals });
});

app.post('/api/redeem-discount', authenticateToken, (req, res) => {
    const { code } = req.body;
    const discount = db.prepare('SELECT * FROM discount_codes WHERE code = ? AND isUsed = 0').get(code);
    
    if (!discount) {
        return res.status(400).json({ error: 'Invalid or used code' });
    }
    
    db.prepare('UPDATE discount_codes SET isUsed = 1, usedBy = ? WHERE code = ?').run(req.user.userId, code);
    res.json({ success: true, percentage: discount.percentage });
});

// ========== SERVE FRONTEND ==========
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend/index.html'));
});

// ========== START SERVER ==========
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`📁 Database path: ${dbPath}`);
    console.log(`🌐 Frontend available at: http://localhost:${PORT}`);
});
