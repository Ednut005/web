const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');
const axios = require('axios');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '../frontend')));

// Database setup
const db = new Database('database.db');

// Create tables
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
    const adminIds = process.env.ADMIN_IDS ? process.env.ADMIN_IDS.split(',') : [];
    if (!adminIds.includes(req.user.userId) && !req.user.isAdmin) {
        return res.status(403).json({ error: 'Admin access required' });
    }
    next();
}

// ========== AUTH ROUTES ==========
app.post('/api/register', async (req, res) => {
    const { username, email, country, password } = req.body;
    
    try {
        const existingUser = db.prepare('SELECT * FROM users WHERE username = ? OR email = ?').get(username, email);
        if (existingUser) {
            return res.status(400).json({ error: 'Username or email already exists' });
        }
        
        const hashedPassword = await bcrypt.hash(password, 10);
        const userId = Date.now().toString();
        const currencyMap = { NG: 'NGN', US: 'USD', GB: 'GBP', KE: 'KES', GH: 'GHS', UG: 'UGX', TZ: 'TZS', ZA: 'ZAR', EU: 'EUR' };
        
        db.prepare('INSERT INTO users (id, username, email, country, currency, password, createdAt, isAdmin) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
            .run(userId, username, email, country, currencyMap[country] || 'USD', hashedPassword, Date.now(), 0);
        
        const token = jwt.sign({ userId, username, isAdmin: 0 }, process.env.JWT_SECRET);
        res.json({ success: true, token, user: { id: userId, username, email, balance: 0, isAdmin: 0 } });
    } catch (error) {
        res.status(500).json({ error: 'Registration failed' });
    }
});

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    
    try {
        const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
        if (!user) return res.status(401).json({ error: 'Invalid credentials' });
        
        const valid = await bcrypt.compare(password, user.password);
        if (!valid) return res.status(401).json({ error: 'Invalid credentials' });
        
        if (user.isBanned === 1) return res.status(401).json({ error: 'Account banned' });
        
        const token = jwt.sign({ userId: user.id, username: user.username, isAdmin: user.isAdmin }, process.env.JWT_SECRET);
        res.json({ success: true, token, user: { id: user.id, username: user.username, email: user.email, balance: user.balance, isAdmin: user.isAdmin } });
    } catch (error) {
        res.status(500).json({ error: 'Login failed' });
    }
});

app.get('/api/me', authenticateToken, (req, res) => {
    const user = db.prepare('SELECT id, username, email, country, currency, balance, isReseller, resellerExpiry, isBanned, isAdmin FROM users WHERE id = ?').get(req.user.userId);
    res.json({ success: true, ...user });
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
        const response = await axios.get(`${process.env.HEROSMS_BASE_URL}?api_key=${process.env.HEROSMS_API_KEY}&action=getCountries`);
        const countries = Object.values(response.data).map(c => ({ id: c.id, name: c.eng || c.name }));
        res.json(countries);
    } catch (error) {
        res.json([{ id: '1', name: 'USA' }, { id: '2', name: 'UK' }, { id: '3', name: 'Nigeria' }]);
    }
});

app.get('/api/services/:countryId', async (req, res) => {
    try {
        const { countryId } = req.params;
        const response = await axios.get(`${process.env.HEROSMS_BASE_URL}?api_key=${process.env.HEROSMS_API_KEY}&action=getPrices&country=${countryId}`);
        const services = response.data[countryId] || response.data;
        
        const apps = [];
        const popularApps = { wa: 'WhatsApp', tg: 'Telegram', lf: 'TikTok', ig: 'Instagram', fb: 'Facebook', tw: 'Twitter', sn: 'Snapchat' };
        
        for (const [code, name] of Object.entries(popularApps)) {
            const match = Object.entries(services).find(([id]) => id.startsWith(code));
            if (match) {
                apps.push({ id: match[0], name, price: Math.ceil(parseFloat(match[1].cost) * 1650 * 2) });
            }
        }
        res.json(apps);
    } catch (error) {
        res.json([{ id: 'wa', name: 'WhatsApp', price: 500 }, { id: 'tg', name: 'Telegram', price: 300 }]);
    }
});

app.post('/api/buy-number', authenticateToken, async (req, res) => {
    const { serviceId, countryId } = req.body;
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.userId);
    
    try {
        const response = await axios.get(`${process.env.HEROSMS_BASE_URL}?api_key=${process.env.HEROSMS_API_KEY}&action=getNumber&service=${serviceId}&country=${countryId}`);
        
        if (response.data.includes('ACCESS_NUMBER')) {
            const [, orderId, number] = response.data.split(':');
            const price = 500;
            
            if (user.balance < price) {
                return res.status(400).json({ error: 'Insufficient balance' });
            }
            
            db.prepare('UPDATE users SET balance = balance - ? WHERE id = ?').run(price, user.id);
            
            const purchaseId = Date.now().toString();
            db.prepare(`INSERT INTO purchases (id, userId, orderId, number, app, country, amount, status, date) 
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
                .run(purchaseId, user.id, orderId, number, serviceId, countryId, price, 'waiting', new Date().toISOString());
            
            res.json({ success: true, orderId, number, price });
        } else {
            res.status(400).json({ error: 'No numbers available' });
        }
    } catch (error) {
        res.status(500).json({ error: 'Purchase failed' });
    }
});

app.get('/api/check-sms/:orderId', authenticateToken, (req, res) => {
    const { orderId } = req.params;
    const purchase = db.prepare('SELECT code, status FROM purchases WHERE orderId = ? AND userId = ?').get(orderId, req.user.userId);
    res.json({ code: purchase?.code, status: purchase?.status });
});

app.post('/api/request-additional-code', authenticateToken, async (req, res) => {
    const { orderId } = req.body;
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.userId);
    const additionalPrice = 100;
    
    if (user.balance < additionalPrice) {
        return res.status(400).json({ error: 'Insufficient balance' });
    }
    
    db.prepare('UPDATE users SET balance = balance - ? WHERE id = ?').run(additionalPrice, user.id);
    
    try {
        await axios.get(`${process.env.HEROSMS_BASE_URL}?api_key=${process.env.HEROSMS_API_KEY}&action=requestCode&id=${orderId}`);
        res.json({ success: true, newBalance: user.balance - additionalPrice });
    } catch (error) {
        db.prepare('UPDATE users SET balance = balance + ? WHERE id = ?').run(additionalPrice, user.id);
        res.status(500).json({ error: 'Failed to request code' });
    }
});

// ========== PAYMENT ROUTES ==========
app.post('/api/create-payment', authenticateToken, async (req, res) => {
    const { amount } = req.body;
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.userId);
    
    try {
        const response = await axios.post('https://api.paystack.co/transaction/initialize', {
            email: user.email,
            amount: amount * 100,
            callback_url: `${req.headers.origin}/verify-payment.html`
        }, {
            headers: { Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}` }
        });
        
        db.prepare('INSERT INTO transactions (reference, userId, amount, status, createdAt) VALUES (?, ?, ?, ?, ?)')
            .run(response.data.data.reference, user.id, amount, 'pending', Date.now());
        
        res.json({ authorization_url: response.data.data.authorization_url, reference: response.data.data.reference });
    } catch (error) {
        res.status(500).json({ error: 'Payment initialization failed' });
    }
});

app.post('/api/verify-payment/:reference', authenticateToken, async (req, res) => {
    const { reference } = req.params;
    
    try {
        const response = await axios.get(`https://api.paystack.co/transaction/verify/${reference}`, {
            headers: { Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}` }
        });
        
        if (response.data.data.status === 'success') {
            const transaction = db.prepare('SELECT * FROM transactions WHERE reference = ?').get(reference);
            if (transaction && transaction.status !== 'completed') {
                db.prepare('UPDATE users SET balance = balance + ? WHERE id = ?').run(response.data.data.amount / 100, transaction.userId);
                db.prepare('UPDATE transactions SET status = ? WHERE reference = ?').run('completed', reference);
                res.json({ success: true, amount: response.data.data.amount / 100 });
            } else {
                res.json({ success: false, error: 'Already processed' });
            }
        } else {
            res.json({ success: false });
        }
    } catch (error) {
        res.status(500).json({ error: 'Verification failed' });
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

// Serve frontend
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend/index.html'));
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
