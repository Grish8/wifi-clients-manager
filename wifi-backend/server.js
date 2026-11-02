const { google } = require('googleapis');
const path = require('path');


const dns = require('node:dns');
dns.setDefaultResultOrder('ipv4first');

const express = require('express');
require('dotenv').config();

const cors = require('cors');
const { Pool, types } = require('pg');
const bcrypt = require('bcrypt');
const crypto = require('crypto');

types.setTypeParser(1082, value => value);

const app = express();
app.use(cors());
app.use(express.json());

// =====================================================
// STARTUP DIAGNOSTICS
// =====================================================
console.log('');
console.log('========================================');
console.log('  WiFi Manager Backend Starting...');
console.log('========================================');

if (!process.env.DATABASE_URL) {
    console.error('❌ FATAL: DATABASE_URL is not set!');
    console.error('   Create a .env file in this folder with:');
    console.error('   DATABASE_URL=postgresql://your-neon-connection-string');
    console.error('');
    process.exit(1);
}

console.log('✅ DATABASE_URL loaded');
console.log('   Host preview:', process.env.DATABASE_URL.split('@')[1]?.split('/')[0] || 'unknown');
console.log('');

// =====================================================
// DATABASE CONNECTION
// =====================================================
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false },
    max: 5,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 10000
});

// Test connection + verify tables
(async () => {
    try {
        const r = await pool.query('SELECT NOW() as now, current_database() as db');
        console.log('✅ Connected to Neon PostgreSQL');
        console.log('   Database:', r.rows[0].db);
        console.log('   Server time:', r.rows[0].now);
        console.log('');

        // Ensure required tables exist
        await pool.query(`
            CREATE TABLE IF NOT EXISTS clients (
                id SERIAL PRIMARY KEY,
                account_number VARCHAR(50) UNIQUE NOT NULL,
                name VARCHAR(150) NOT NULL,
                phone VARCHAR(30) NOT NULL,
                email VARCHAR(150),
                address TEXT,
                plan VARCHAR(100) NOT NULL,
                price NUMERIC(10, 2) NOT NULL,
                start_date DATE NOT NULL,
                end_date DATE NOT NULL
            );
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS renewal_history (
                id SERIAL PRIMARY KEY,
                account_number VARCHAR(50) NOT NULL,
                client_name VARCHAR(150) NOT NULL,
                plan VARCHAR(100) NOT NULL,
                type VARCHAR(20) NOT NULL,
                previous_end_date DATE,
                new_end_date DATE,
                created_at TIMESTAMP DEFAULT NOW()
            );
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS admin_credentials (
                id SERIAL PRIMARY KEY,
                password_hash VARCHAR(255) NOT NULL,
                updated_at TIMESTAMP DEFAULT NOW()
            );
        `);

        console.log('✅ All tables ready (clients, renewal_history, admin_credentials)');

        // Seed default admin password if none exists
        const creds = await pool.query('SELECT COUNT(*) as c FROM admin_credentials');
        if (Number(creds.rows[0].c) === 0) {
            const defaultHash = await bcrypt.hash('admin123', 10);
            await pool.query('INSERT INTO admin_credentials (password_hash) VALUES ($1)', [defaultHash]);
            console.log('✅ Default admin password created: admin123');
            console.log('   ⚠️  Change it after first login!');
        } else {
            console.log('✅ Admin credentials already configured');
        }

        const count = await pool.query('SELECT COUNT(*) as c FROM clients');
        console.log(`   Clients in DB: ${count.rows[0].c}`);
    } catch (err) {
        console.error('❌ Database startup FAILED');
        console.error('   Error:', err.message);
        console.error('   Code:', err.code);
    }
    console.log('========================================');
    console.log('');
})();

// =====================================================
// ERROR HELPER
// =====================================================
function sendDbError(res, err, context) {
    console.error(`❌ ${context} error:`, err.message);
    if (err.detail) console.error('   Detail:', err.detail);
    if (err.hint) console.error('   Hint:', err.hint);
    res.status(500).json({
        error: err.message,
        detail: err.detail || null,
        hint: err.hint || null,
        code: err.code || null
    });
}

// =====================================================
// SESSION MANAGEMENT (in-memory tokens)
// =====================================================
// Sessions are stored in memory. They reset when the server
// restarts, which is fine for a single-user admin tool.
// For multi-user, migrate to a persistent session store.
const sessions = new Map();
const SESSION_TTL_MS = 8 * 60 * 60 * 1000; // 8 hours

function createSession() {
    const token = crypto.randomBytes(32).toString('hex');
    sessions.set(token, { createdAt: Date.now() });
    return token;
}

function isValidSession(token) {
    if (!token) return false;
    const s = sessions.get(token);
    if (!s) return false;
    if (Date.now() - s.createdAt > SESSION_TTL_MS) {
        sessions.delete(token);
        return false;
    }
    return true;
}

function requireAuth(req, res, next) {
    const token = req.headers['x-auth-token'];
    if (!isValidSession(token)) {
        return res.status(401).json({ error: 'Unauthorized. Please log in.' });
    }
    next();
}

// =====================================================
// AUTH ROUTES
// =====================================================
app.post('/api/auth/login', async (req, res) => {
    const { password } = req.body;
    if (!password) return res.status(400).json({ error: 'Password required' });

    try {
        const result = await pool.query('SELECT password_hash FROM admin_credentials ORDER BY id DESC LIMIT 1');
        if (result.rows.length === 0) {
            return res.status(500).json({ error: 'Admin credentials not configured' });
        }
        const ok = await bcrypt.compare(password, result.rows[0].password_hash);
        if (!ok) return res.status(401).json({ error: 'Incorrect password' });

        const token = createSession();
        res.json({ success: true, token });
    } catch (err) {
        sendDbError(res, err, 'Login');
    }
});

app.post('/api/auth/logout', (req, res) => {
    const token = req.headers['x-auth-token'];
    if (token) sessions.delete(token);
    res.json({ success: true });
});

app.post('/api/auth/change-password', requireAuth, async (req, res) => {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) {
        return res.status(400).json({ error: 'Both passwords required' });
    }
    if (newPassword.length < 6) {
        return res.status(400).json({ error: 'New password must be at least 6 characters' });
    }

    try {
        const result = await pool.query('SELECT id, password_hash FROM admin_credentials ORDER BY id DESC LIMIT 1');
        const row = result.rows[0];
        if (!row) return res.status(500).json({ error: 'Admin credentials not configured' });

        const ok = await bcrypt.compare(currentPassword, row.password_hash);
        if (!ok) return res.status(401).json({ error: 'Current password is incorrect' });

        const newHash = await bcrypt.hash(newPassword, 10);
        await pool.query('UPDATE admin_credentials SET password_hash = $1, updated_at = NOW() WHERE id = $2', [newHash, row.id]);
        console.log('✅ Admin password changed');
        res.json({ success: true });
    } catch (err) {
        sendDbError(res, err, 'Change password');
    }
});

// =====================================================
// HEALTH
// =====================================================
app.get('/api/health', async (req, res) => {
    try {
        const r = await pool.query('SELECT NOW() as now');
        res.json({ status: 'ok', database: 'connected', time: r.rows[0].now });
    } catch (err) {
        sendDbError(res, err, 'Health check');
    }
});

// =====================================================
// CLIENTS ROUTES
// =====================================================
app.get('/api/clients', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM clients ORDER BY id DESC');
        res.json(result.rows);
    } catch (err) {
        sendDbError(res, err, 'GET');
    }
});

app.get('/api/clients/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const result = await pool.query('SELECT * FROM clients WHERE id = $1', [id]);
        if (result.rows.length === 0) return res.status(404).json({ error: 'Client not found' });
        res.json(result.rows[0]);
    } catch (err) {
        sendDbError(res, err, 'GET single');
    }
});

app.post('/api/clients', async (req, res) => {
    const { account_number, name, phone, email, address, plan, price, start_date, end_date } = req.body;
    if (!account_number || !name || !phone || !plan || price == null || !start_date || !end_date) {
        return res.status(400).json({ error: 'Missing required fields' });
    }
    try {
        const result = await pool.query(
            `INSERT INTO clients 
                (account_number, name, phone, email, address, plan, price, start_date, end_date)
             VALUES 
                ($1, $2, $3, $4, $5, $6, $7, $8, $9) 
             RETURNING *`,
            [account_number, name, phone, email || null, address || null, plan, price, start_date, end_date]
        );
        console.log(`✅ Added client: ${name} (${account_number})`);
        res.status(201).json(result.rows[0]);
    } catch (err) {
        if (err.code === '23505') return res.status(400).json({ error: 'Account number already exists' });
        sendDbError(res, err, 'POST');
    }
});

app.put('/api/clients/:id', async (req, res) => {
    const { id } = req.params;
    const { account_number, name, phone, email, address, plan, price, start_date, end_date } = req.body;
    if (!account_number || !name || !phone || !plan || price == null || !start_date || !end_date) {
        return res.status(400).json({ error: 'Missing required fields' });
    }
    try {
        const result = await pool.query(
            `UPDATE clients SET 
                account_number = $1, name = $2, phone = $3, email = $4, address = $5,
                plan = $6, price = $7, start_date = $8, end_date = $9
             WHERE id = $10 
             RETURNING *`,
            [account_number, name, phone, email || null, address || null, plan, price, start_date, end_date, id]
        );
        if (result.rows.length === 0) return res.status(404).json({ error: 'Client not found' });
        console.log(`✅ Updated client: ${name} (${account_number})`);
        res.json(result.rows[0]);
    } catch (err) {
        if (err.code === '23505') return res.status(400).json({ error: 'Account number already exists' });
        sendDbError(res, err, 'PUT');
    }
});

app.delete('/api/clients/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const result = await pool.query('DELETE FROM clients WHERE id = $1 RETURNING *', [id]);
        if (result.rows.length === 0) return res.status(404).json({ error: 'Client not found' });
        console.log(`✅ Deleted client: ${result.rows[0].name} (${result.rows[0].account_number})`);
        res.json({ message: 'Client deleted', client: result.rows[0] });
    } catch (err) {
        sendDbError(res, err, 'DELETE');
    }
});

// =====================================================
// RENEWAL HISTORY ROUTES
// =====================================================
app.get('/api/history', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM renewal_history ORDER BY created_at DESC, id DESC');
        res.json(result.rows);
    } catch (err) {
        sendDbError(res, err, 'GET history');
    }
});

app.post('/api/history', async (req, res) => {
    const { account_number, client_name, plan, type, previous_end_date, new_end_date } = req.body;
    if (!account_number || !client_name || !plan || !type) {
        return res.status(400).json({ error: 'Missing required fields' });
    }
    try {
        const result = await pool.query(
            `INSERT INTO renewal_history 
                (account_number, client_name, plan, type, previous_end_date, new_end_date)
             VALUES 
                ($1, $2, $3, $4, $5, $6) 
             RETURNING *`,
            [account_number, client_name, plan, type, previous_end_date || null, new_end_date || null]
        );
        console.log(`✅ History recorded: ${type} - ${client_name}`);
        res.status(201).json(result.rows[0]);
    } catch (err) {
        sendDbError(res, err, 'POST history');
    }
});

app.delete('/api/history/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const result = await pool.query('DELETE FROM renewal_history WHERE id = $1 RETURNING *', [id]);
        if (result.rows.length === 0) return res.status(404).json({ error: 'History record not found' });
        console.log(`✅ Deleted history record #${id}`);
        res.json({ message: 'History record deleted' });
    } catch (err) {
        sendDbError(res, err, 'DELETE history');
    }
});

app.delete('/api/history', async (req, res) => {
    try {
        const result = await pool.query('DELETE FROM renewal_history');
        console.log(`✅ Cleared all history (${result.rowCount} records)`);
        res.json({ message: 'All history cleared', deleted: result.rowCount });
    } catch (err) {
        sendDbError(res, err, 'DELETE all history');
    }
});

// =====================================================
// GOOGLE SHEETS SYNC
// =====================================================
async function syncFromGoogleSheet() {
    console.log('🔄 Starting Google Sheets sync...');
    try {
        const auth = new google.auth.GoogleAuth({
            keyFile: process.env.GOOGLE_APPLICATION_CREDENTIALS,
            scopes: ['https://www.googleapis.com/auth/spreadsheets.readonly'],
        });
        const sheets = google.sheets({ version: 'v4', auth });
        const TAB_NAMES = ['Sheet1', 'Sheet2'];
        let inserted = 0;
        let updated = 0;
        let skipped = 0;

        for (const tab of TAB_NAMES) {
            console.log(`   Reading tab: ${tab}`);
            try {
                const response = await sheets.spreadsheets.values.get({
                    spreadsheetId: process.env.GOOGLE_SHEET_ID,
                    range: `${tab}!A2:I`,
                });
                const rows = response.data.values || [];
                if (rows.length === 0) {
                    console.log(`   ⏭️  ${tab} is empty, skipping.`);
                    continue;
                }

                for (const row of rows) {
                    const [
                        account_number, name, phone, email, address,
                        plan, price, start_date, end_date
                    ] = row;

                    if (!account_number) {
                        skipped++;
                        continue;
                    }

                    try {
                        const result = await pool.query(
                            `INSERT INTO clients
                                (account_number, name, phone, email, address, plan, price, start_date, end_date)
                             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                             ON CONFLICT (account_number)
                             DO UPDATE SET
                                name = EXCLUDED.name,
                                phone = EXCLUDED.phone,
                                email = EXCLUDED.email,
                                address = EXCLUDED.address,
                                plan = EXCLUDED.plan,
                                price = EXCLUDED.price,
                                start_date = EXCLUDED.start_date,
                                end_date = EXCLUDED.end_date
                             RETURNING (xmax = 0) AS inserted`,
                            [
                                account_number, name, phone, email || null, address || null,
                                plan, Number.parseFloat(price) || 0, start_date, end_date
                            ]
                        );
                        if (result.rows[0].inserted) inserted++;
                        else updated++;
                    } catch (rowErr) {
                        console.error(`❌ Row ${account_number} in ${tab}:`, rowErr.message);
                        skipped++;
                    }
                }
            } catch (tabErr) {
                console.error(`❌ Could not read tab "${tab}":`, tabErr.message);
            }
        }

        console.log(`✅ Sync complete: ${inserted} inserted, ${updated} updated, ${skipped} skipped.`);
        return { success: true, inserted, updated, skipped };
    } catch (err) {
        console.error('❌ Google Sheets sync failed:', err.message);
        throw err;
    }
}

app.post('/api/sync-sheets', requireAuth, async (req, res) => {
    try {
        const result = await syncFromGoogleSheet();
        res.json(result);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

if (process.env.GOOGLE_APPLICATION_CREDENTIALS && process.env.GOOGLE_SHEET_ID) {
    setInterval(() => {
        syncFromGoogleSheet().catch(err => console.error('Scheduled sync error:', err));
    }, 60 * 60 * 1000);
}

// =====================================================
// START SERVER
// =====================================================
const PORT = process.env.PORT || 3000;
const server = app.listen(PORT, () => {
    console.log(`🚀 Backend running on http://localhost:${PORT}`);
    console.log(`   Health check:  http://localhost:${PORT}/api/health`);
    console.log(`   Clients API:   http://localhost:${PORT}/api/clients`);
    console.log(`   History API:   http://localhost:${PORT}/api/history`);
    console.log(`   Auth login:    POST http://localhost:${PORT}/api/auth/login`);
    console.log('');
});

process.on('SIGINT', async () => {
    console.log('\n🛑 Shutting down...');
    await pool.end();
    server.close(() => {
        console.log('✅ Server closed');
        process.exit(0);
    });
});

process.on('SIGTERM', async () => {
    await pool.end();
    server.close(() => process.exit(0));
});