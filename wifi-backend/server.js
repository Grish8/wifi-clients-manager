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

        // clients table — end_date is now NULLABLE
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
                start_date DATE,
                end_date DATE
            );
        `);

        // Migration: if the table already exists with NOT NULL, drop that constraint
        await pool.query(`ALTER TABLE clients ALTER COLUMN start_date DROP NOT NULL;`);
        await pool.query(`ALTER TABLE clients ALTER COLUMN end_date DROP NOT NULL;`);
        await pool.query(`ALTER TABLE clients ADD COLUMN IF NOT EXISTS pending_end_date BOOLEAN DEFAULT FALSE;`);
        await pool.query(`ALTER TABLE clients ADD COLUMN IF NOT EXISTS message_sent BOOLEAN DEFAULT FALSE;`);
        await pool.query(`ALTER TABLE clients ADD COLUMN IF NOT EXISTS wifi_disabled BOOLEAN DEFAULT FALSE;`);

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

        if (process.env.GOOGLE_APPLICATION_CREDENTIALS && process.env.GOOGLE_SHEET_ID) {
            syncFromGoogleSheet().catch(err => console.error('Startup sync error:', err));
        }
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
// SESSION MANAGEMENT
// =====================================================
const sessions = new Map();
const SESSION_TTL_MS = 8 * 60 * 60 * 1000;

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
    if (!currentPassword || !newPassword) return res.status(400).json({ error: 'Both passwords required' });
    if (newPassword.length < 6) return res.status(400).json({ error: 'New password must be at least 6 characters' });
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
// LIGHTWEIGHT KEEP-ALIVE (no DB hit)
// =====================================================
app.get('/api/ping', (req, res) => {
    res.json({ ok: true, time: new Date().toISOString() });
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
                (account_number, name, phone, email, address, plan, price, start_date, end_date, pending_end_date)
             VALUES
                ($1, $2, $3, $4, $5, $6, $7, $8, $9, FALSE)
             RETURNING *`,
            [account_number, name, phone, email || null, address || null, plan, price, start_date || null, end_date || null]
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
    if (!account_number || !name || !phone || !plan || price == null || !start_date) {
        return res.status(400).json({ error: 'Missing required fields' });
    }
    try {
        const current = await pool.query(
            'SELECT end_date, pending_end_date FROM clients WHERE id = $1',
            [id]
        );
        if (current.rows.length === 0) return res.status(404).json({ error: 'Client not found' });

        const previousEndDate = current.rows[0].end_date;
        const wasPending = current.rows[0].pending_end_date === true;

        const result = await pool.query(
            `UPDATE clients SET
                account_number = $1, name = $2, phone = $3, email = $4, address = $5,
                plan = $6, price = $7, start_date = $8, end_date = $9,
                pending_end_date = FALSE,
                wifi_disabled = FALSE,
                message_sent = FALSE
             WHERE id = $10
             RETURNING *`,
            [account_number, name, phone, email || null, address || null, plan, price, start_date || null, end_date || null, id]
        );
        if (result.rows.length === 0) return res.status(404).json({ error: 'Client not found' });

        console.log(`✅ Updated client: ${name} (${account_number})`);
        res.json({
            ...result.rows[0],
            _previous_end_date: previousEndDate,
            _was_pending: wasPending
        });
    } catch (err) {
        if (err.code === '23505') return res.status(400).json({ error: 'Account number already exists' });
        sendDbError(res, err, 'PUT');
    }
});

// =====================================================
// TOGGLE: message_sent (Expiring Soon tab)
// =====================================================
app.post('/api/clients/:id/toggle-message-sent', requireAuth, async (req, res) => {
    const { id } = req.params;
    const { value } = req.body; // boolean
    try {
        const result = await pool.query(
            `UPDATE clients SET message_sent = $1 WHERE id = $2 RETURNING *`,
            [!!value, id]
        );
        if (result.rows.length === 0) return res.status(404).json({ error: 'Client not found' });
        console.log(`✅ message_sent=${!!value} for ${result.rows[0].account_number}`);
        res.json(result.rows[0]);
    } catch (err) {
        sendDbError(res, err, 'Toggle message_sent');
    }
});

// =====================================================
// TOGGLE: wifi_disabled (Expired Users tab)
// =====================================================
app.post('/api/clients/:id/toggle-wifi-disabled', requireAuth, async (req, res) => {
    const { id } = req.params;
    const { value } = req.body; // boolean
    try {
        const result = await pool.query(
            `UPDATE clients SET wifi_disabled = $1 WHERE id = $2 RETURNING *`,
            [!!value, id]
        );
        if (result.rows.length === 0) return res.status(404).json({ error: 'Client not found' });
        console.log(`✅ wifi_disabled=${!!value} for ${result.rows[0].account_number}`);
        res.json(result.rows[0]);
    } catch (err) {
        sendDbError(res, err, 'Toggle wifi_disabled');
    }
});

// =====================================================
// RESET TO PENDING (renewal date set, no end date)
// =====================================================
app.post('/api/clients/:id/reset-pending', requireAuth, async (req, res) => {
    const { id } = req.params;
    const { start_date } = req.body; // optional new start date
    try {
        const result = await pool.query(
            `UPDATE clients SET
                start_date = COALESCE($1, start_date),
                end_date = NULL,
                pending_end_date = TRUE
             WHERE id = $2
             RETURNING *`,
            [start_date || null, id]
        );
        if (result.rows.length === 0) return res.status(404).json({ error: 'Client not found' });
        console.log(`✅ Reset to pending: ${result.rows[0].name} (${result.rows[0].account_number})`);
        res.json(result.rows[0]);
    } catch (err) {
        sendDbError(res, err, 'Reset to pending');
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
function normalizeSheetDate(v) {
    if (!v) return null;
    const s = String(v).trim();
    if (!s) return null;

    let year, month, day;
    if (/^\d{4}-\d{2}-\d{2}$/.test(s)) {
        [year, month, day] = s.split('-').map(Number);
    } else {
        const match = s.match(/^(\d{1,2})[\/-](\d{1,2})[\/-](\d{2,4})$/);
        if (match) {
            month = Number(match[1]);
            day = Number(match[2]);
            year = Number(match[3]);
            if (year < 100) year += 2000;
            if (month > 12) [month, day] = [day, month];
        } else {
            const parsed = new Date(s);
            if (Number.isNaN(parsed.getTime())) return null;
            year = parsed.getFullYear();
            month = parsed.getMonth() + 1;
            day = parsed.getDate();
        }
    }

    const normalized = `${year}-${String(month).padStart(2, '0')}-${String(day).padStart(2, '0')}`;
    const parsedDate = new Date(`${normalized}T00:00:00Z`);
    return !Number.isNaN(parsedDate.getTime()) && parsedDate.toISOString().slice(0, 10) === normalized
        ? normalized
        : null;
}

async function syncFromGoogleSheet() {
    console.log('🔄 Starting Google Sheets sync...');
    try {
        const keyPath = path.resolve(__dirname, process.env.GOOGLE_APPLICATION_CREDENTIALS);
        const auth = new google.auth.GoogleAuth({
            keyFile: keyPath,
            scopes: ['https://www.googleapis.com/auth/spreadsheets.readonly'],
        });
        const sheets = google.sheets({ version: 'v4', auth });
        const SOURCES = [
            { id: process.env.GOOGLE_SHEET_ID, tab: 'OCTOBER-CONFG' },
            { id: process.env.GOOGLE_SHEET_ID, tab: 'NOVEMBER-CONFIG' },
        ];

        let inserted = 0, updated = 0, skipped = 0, deleted = 0;
        const errors = [];

        // ── Track every account_number found in ANY synced tab ──
        // We use a Set so duplicates across tabs don't matter.
        const sheetAccounts = new Set();

        for (const src of SOURCES) {
            if (!src.id) {
                console.log('   ⏭️  Skipping (no ID)');
                continue;
            }

            console.log(`   Reading tab: ${src.tab}`);
            try {
                const response = await sheets.spreadsheets.values.get({
                    spreadsheetId: src.id,
                    range: `'${src.tab}'!A1:ZZ`,
                });
                const rows = response.data.values || [];
                if (rows.length < 2) {
                    console.log(`   ⏭️  No data rows in ${src.tab}`);
                    continue;
                }

                const headers = rows[0];
                const headerIndex = {};
                headers.forEach((h, i) => {
                    if (h) headerIndex[h.trim().toUpperCase()] = i;
                });

                const REQUIRED_SHEET_HEADERS = [
                    'ACCOUNT', 'FIRST NAME', 'SECOND NAME',
                    'PHONE NO.', 'PACKAGE', 'AMOUNT',
                ];
                const missing = REQUIRED_SHEET_HEADERS.filter(h => headerIndex[h] === undefined);
                if (missing.length > 0) {
                    const msg = `Missing header(s) in "${src.tab}": ${missing.join(', ')}`;
                    console.error(`   ❌ ${msg}`);
                    errors.push(msg);
                    continue;
                }

                const get = (row, sheetHeader) => {
                    const idx = headerIndex[sheetHeader.trim().toUpperCase()];
                    if (idx === undefined) return null;
                    const val = row[idx];
                    return val === undefined ? null : String(val).trim();
                };

                for (let r = 1; r < rows.length; r++) {
                    const row = rows[r];
                    if (!row || row.length === 0 || !get(row, 'ACCOUNT')) {
                        skipped++;
                        continue;
                    }

                    const account_number = get(row, 'ACCOUNT');
                    if (account_number) sheetAccounts.add(String(account_number).toUpperCase());

                    const firstName = get(row, 'FIRST NAME');
                    const secondName = get(row, 'SECOND NAME');
                    const fullName = [firstName, secondName].filter(Boolean).join(' ').trim();

                    const renewalDate = get(row, 'RENEWAL DATE');
                    const sheetStartDate = get(row, 'START DATE');
                    const sheetEndDate = get(row, 'END DATE');

                    const renewalNorm = normalizeSheetDate(renewalDate);
                    const startNorm = normalizeSheetDate(sheetStartDate);
                    const endNorm = normalizeSheetDate(sheetEndDate);

                    let startDate, endDate, pendingEndDate;
                    if (renewalNorm) {
                        startDate = renewalNorm;
                        endDate = null;
                        pendingEndDate = true;
                    } else {
                        startDate = startNorm || null;
                        endDate = endNorm || null;
                        pendingEndDate = false;
                    }

                    const record = {
                        account_number,
                        name: fullName,
                        phone: get(row, 'PHONE NO.'),
                        email: get(row, 'EMAIL'),
                        address: get(row, 'LOCATION') || get(row, 'ADDRESS') || null,
                        plan: get(row, 'PACKAGE'),
                        price: parseFloat(get(row, 'AMOUNT')) || 0,
                        start_date: startDate,
                        end_date: endDate,
                    };

                    if (!record.account_number || !record.name || !record.phone || !record.plan) {
                        console.warn(`   ⚠️  Row ${r + 1}: missing required field(s), skipping`);
                        skipped++;
                        continue;
                    }

                    try {
                        const result = await pool.query(
                            `INSERT INTO clients
                                (account_number, name, phone, email, address, plan, price, start_date, end_date, pending_end_date)
                             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                             ON CONFLICT (account_number)
                             DO UPDATE SET
                                name = EXCLUDED.name,
                                phone = EXCLUDED.phone,
                                email = EXCLUDED.email,
                                address = EXCLUDED.address,
                                plan = EXCLUDED.plan,
                                price = EXCLUDED.price,
                                start_date = EXCLUDED.start_date,
                                end_date = CASE
                                    WHEN clients.end_date IS NULL AND clients.pending_end_date = TRUE THEN EXCLUDED.end_date
                                    ELSE clients.end_date
                                END,
                                pending_end_date = CASE
                                    WHEN clients.pending_end_date = TRUE
                                         AND clients.end_date IS NULL
                                         AND EXCLUDED.end_date IS NULL THEN TRUE
                                    ELSE FALSE
                                END
                             RETURNING (xmax = 0) AS inserted`,
                            [
                                record.account_number,
                                record.name,
                                record.phone,
                                record.email || null,
                                record.address,
                                record.plan,
                                record.price,
                                record.start_date,
                                record.end_date,
                                pendingEndDate,
                            ]
                        );
                        if (result.rows[0].inserted) inserted++;
                        else updated++;
                    } catch (rowErr) {
                        const msg = `Row ${r + 1} (${record.account_number}): ${rowErr.message}`;
                        console.error(`   ❌ ${msg}`);
                        errors.push(msg);
                        skipped++;
                    }
                }
            } catch (tabErr) {
                const msg = `Could not read "${src.tab}": ${tabErr.message}`;
                console.error(`   ❌ ${msg}`);
                errors.push(msg);
            }
        }

        // ── Step 2: Delete DB clients that no longer exist in the sheet ──
        // Only run this if at least one tab was read successfully.
        // (Otherwise a failed sheet read would delete EVERYTHING.)
        if (sheetAccounts.size > 0) {
            console.log(`   🗑️  Checking for deleted accounts (${sheetAccounts.size} accounts in sheet)...`);

            // Find DB clients whose account_number is NOT in sheetAccounts
            const dbAccounts = await pool.query('SELECT account_number FROM clients');
            const toDelete = dbAccounts.rows
                .map(r => r.account_number)
                .filter(acc => acc && !sheetAccounts.has(String(acc).toUpperCase()));

            if (toDelete.length > 0) {
                // Delete them one by one with logging
                for (const acc of toDelete) {
                    try {
                        const del = await pool.query(
                            'DELETE FROM clients WHERE account_number = $1 RETURNING account_number, name',
                            [acc]
                        );
                        if (del.rows.length > 0) {
                            console.log(`   🗑️  Deleted: ${del.rows[0].name} (${del.rows[0].account_number})`);
                            deleted++;
                            // Record the deletion in history
                            try {
                                await pool.query(
                                    `INSERT INTO renewal_history
                                        (account_number, client_name, plan, type, previous_end_date, new_end_date)
                                     VALUES ($1, $2, $3, 'deleted', NULL, NULL)`,
                                    [del.rows[0].account_number, del.rows[0].name, '—']
                                );
                            } catch (histErr) {
                                console.error(`   ⚠️  Failed to log deletion to history: ${histErr.message}`);
                            }
                        }
                    } catch (delErr) {
                        const msg = `Delete failed for ${acc}: ${delErr.message}`;
                        console.error(`   ❌ ${msg}`);
                        errors.push(msg);
                    }
                }
            } else {
                console.log('   ✓ No deleted accounts to remove.');
            }
        } else {
            console.warn('   ⚠️  Skipping deletion step: no accounts were read from the sheet.');
            console.warn('      (Prevents accidental data wipe when the sheet is unreachable.)');
        }

        console.log(`✅ Sync complete: ${inserted} inserted, ${updated} updated, ${deleted} deleted, ${skipped} skipped`);
        return { success: true, inserted, updated, deleted, skipped, errors };
    } catch (err) {
        console.error('❌ Sync failed:', err.message);
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