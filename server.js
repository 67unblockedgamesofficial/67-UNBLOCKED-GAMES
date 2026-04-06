const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const { Pool } = require('pg');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcrypt');
const multer = require('multer');
const session = require('express-session');
const { v4: uuidv4 } = require('uuid');
const cors = require('cors');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.DATABASE_URL && process.env.DATABASE_URL.includes('localhost')
        ? false : { rejectUnauthorized: false }
});

// ─── CORS ─────────────────────────────────────────────────────────────────────
// CORS_ORIGIN env var = comma-separated list of allowed origins (e.g. GitHub Pages URL)
// Leave unset for same-origin / Replit dev (all origins allowed in that case)
const corsOrigins = process.env.CORS_ORIGIN
    ? process.env.CORS_ORIGIN.split(',').map(s => s.trim())
    : null;

app.use(cors({
    origin: (origin, callback) => {
        if (!origin || !corsOrigins || corsOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error(`Origin ${origin} not allowed by CORS`));
        }
    },
    credentials: true
}));

// ─── Middleware ──────────────────────────────────────────────────────────────
app.use(express.json());
app.use(session({
    secret: process.env.SESSION_SECRET || 'sixseven-secret-key-2024',
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 7 * 24 * 60 * 60 * 1000,
        // Cross-origin (GitHub Pages → Render): cookies need SameSite=None + Secure
        sameSite: corsOrigins ? 'none' : 'lax',
        secure: !!corsOrigins
    }
}));

// Serve uploads and static files
if (!fs.existsSync('uploads')) fs.mkdirSync('uploads');
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(express.static(path.join(__dirname)));

// ─── File Upload Setup ────────────────────────────────────────────────────────
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, 'uploads/'),
    filename: (req, file, cb) => {
        const ext = path.extname(file.originalname);
        cb(null, uuidv4() + ext);
    }
});
const upload = multer({
    storage,
    limits: { fileSize: 50 * 1024 * 1024 }, // 50MB
    fileFilter: (req, file, cb) => {
        const allowed = /image\/(jpeg|jpg|png|gif|webp)|video\/(mp4|webm|ogg)/;
        if (allowed.test(file.mimetype)) cb(null, true);
        else cb(new Error('Only images and videos allowed.'));
    }
});

// ─── Auth Middleware ──────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
    if (req.session.username) return next();
    res.status(401).json({ error: 'Not logged in.' });
}

// ─── Auth Routes ─────────────────────────────────────────────────────────────
app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required.' });
    if (username.length < 2 || username.length > 30) return res.status(400).json({ error: 'Username must be 2-30 characters.' });
    if (!/^[a-zA-Z0-9_]+$/.test(username)) return res.status(400).json({ error: 'Username can only contain letters, numbers, underscores.' });
    if (password.length < 4) return res.status(400).json({ error: 'Password must be at least 4 characters.' });

    try {
        const hash = await bcrypt.hash(password, 10);
        await pool.query('INSERT INTO users (username, password_hash) VALUES ($1, $2)', [username, hash]);
        req.session.username = username;
        res.json({ success: true, username });
    } catch (err) {
        if (err.code === '23505') return res.status(409).json({ error: 'Username already taken.' });
        console.error(err);
        res.status(500).json({ error: 'Server error.' });
    }
});

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required.' });

    try {
        const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        if (result.rows.length === 0) return res.status(401).json({ error: 'Invalid username or password.' });
        const user = result.rows[0];
        const match = await bcrypt.compare(password, user.password_hash);
        if (!match) return res.status(401).json({ error: 'Invalid username or password.' });
        req.session.username = user.username;
        res.json({ success: true, username: user.username });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error.' });
    }
});

app.post('/api/logout', (req, res) => {
    req.session.destroy();
    res.json({ success: true });
});

app.get('/api/me', async (req, res) => {
    if (!req.session.username) return res.status(401).json({ error: 'Not logged in.' });
    const staffRes = await pool.query('SELECT 1 FROM staff WHERE username = $1', [req.session.username]).catch(() => ({ rows: [] }));
    res.json({ username: req.session.username, isStaff: staffRes.rows.length > 0 });
});

// ─── Staff List ───────────────────────────────────────────────────────────────
app.get('/api/staff', async (req, res) => {
    try {
        const result = await pool.query('SELECT username FROM staff ORDER BY created_at');
        res.json(result.rows.map(r => r.username));
    } catch (err) { res.status(500).json({ error: 'Server error.' }); }
});

// ─── Assign Staff (staff only) ────────────────────────────────────────────────
app.post('/api/staff/assign', requireAuth, async (req, res) => {
    const caller = req.session.username;
    const target = (req.body.username || '').trim();
    if (!target) return res.status(400).json({ error: 'No username provided.' });
    try {
        const callerIsStaff = await pool.query('SELECT 1 FROM staff WHERE username = $1', [caller]);
        if (!callerIsStaff.rows.length) return res.status(403).json({ error: 'Only staff can assign staff.' });
        const userExists = await pool.query('SELECT 1 FROM users WHERE username = $1', [target]);
        if (!userExists.rows.length) return res.status(404).json({ error: `User "${target}" does not exist.` });
        await pool.query('INSERT INTO staff (username, assigned_by) VALUES ($1, $2) ON CONFLICT DO NOTHING', [target, caller]);
        res.json({ success: true, message: `${target} is now staff.` });
    } catch (err) { console.error(err); res.status(500).json({ error: 'Server error.' }); }
});

// ─── File Upload Route ────────────────────────────────────────────────────────
app.post('/api/upload', requireAuth, upload.single('file'), (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded.' });
    const mediaType = req.file.mimetype.startsWith('video') ? 'video' : 'image';
    res.json({
        url: `/uploads/${req.file.filename}`,
        mediaType
    });
});

// ─── Chat Message History ─────────────────────────────────────────────────────
app.get('/api/messages/:roomCode', async (req, res) => {
    const roomCode = req.params.roomCode.toUpperCase();
    try {
        const result = await pool.query(
            `SELECT id, username, message, media_url, media_type, reply_to_username, reply_to_message, created_at 
             FROM chat_messages WHERE room_code = $1 
             ORDER BY created_at DESC LIMIT 80`,
            [roomCode]
        );
        res.json(result.rows.reverse());
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to load messages.' });
    }
});

// ─── Create Room (registers owner in DB before anyone joins) ──────────────────
app.post('/api/create-room', requireAuth, async (req, res) => {
    let roomCode = ((req.body.roomCode || '').trim().toUpperCase()) || null;
    if (!roomCode) {
        roomCode = Math.random().toString(36).substring(2, 8).toUpperCase();
    }
    if (!/^[A-Z0-9]{2,20}$/.test(roomCode)) {
        return res.status(400).json({ error: 'Room code must be 2-20 letters/numbers.' });
    }
    try {
        const existing = await pool.query('SELECT owner_username FROM room_owners WHERE room_code = $1', [roomCode]);
        if (existing.rows.length > 0) {
            return res.status(409).json({ error: `Room "${roomCode}" already exists. Choose a different code.` });
        }
        await pool.query('INSERT INTO room_owners (room_code, owner_username) VALUES ($1, $2)', [roomCode, req.session.username]);
        res.json({ roomCode, owner: req.session.username });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error.' });
    }
});

// ─── Ban List (owner only) ────────────────────────────────────────────────────
app.get('/api/room/:roomCode/bans', requireAuth, async (req, res) => {
    const roomCode = req.params.roomCode.toUpperCase();
    try {
        const ownerRes = await pool.query('SELECT owner_username FROM room_owners WHERE room_code = $1', [roomCode]);
        if (!ownerRes.rows.length || ownerRes.rows[0].owner_username !== req.session.username) {
            return res.status(403).json({ error: 'Only the room owner can view the ban list.' });
        }
        const bans = await pool.query(
            'SELECT banned_username FROM room_bans WHERE room_code = $1 ORDER BY id DESC',
            [roomCode]
        );
        res.json(bans.rows.map(r => r.banned_username));
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error.' });
    }
});

// ─── Room Owner Check ─────────────────────────────────────────────────────────
app.get('/api/room/:roomCode/owner', async (req, res) => {
    const roomCode = req.params.roomCode.toUpperCase();
    try {
        const result = await pool.query('SELECT owner_username FROM room_owners WHERE room_code = $1', [roomCode]);
        res.json({ owner: result.rows[0]?.owner_username || null });
    } catch (err) {
        res.status(500).json({ error: 'Server error.' });
    }
});

// ─── DM Conversations List ────────────────────────────────────────────────────
app.get('/api/dm/conversations', requireAuth, async (req, res) => {
    const me = req.session.username;
    try {
        const result = await pool.query(`
            SELECT
                CASE WHEN from_username = $1 THEN to_username ELSE from_username END AS other_user,
                MAX(created_at) AS last_at,
                COALESCE(COUNT(*) FILTER (WHERE to_username = $1 AND NOT is_read), 0)::int AS unread
            FROM direct_messages
            WHERE from_username = $1 OR to_username = $1
            GROUP BY other_user
            ORDER BY last_at DESC
        `, [me]);
        res.json(result.rows);
    } catch(err) { console.error(err); res.status(500).json({ error: 'Server error.' }); }
});

// ─── DM History with a User ───────────────────────────────────────────────────
app.get('/api/dm/:username', requireAuth, async (req, res) => {
    const me    = req.session.username;
    const other = req.params.username;
    try {
        const blockRes = await pool.query(
            'SELECT blocker_username FROM user_blocks WHERE (blocker_username=$1 AND blocked_username=$2) OR (blocker_username=$2 AND blocked_username=$1)',
            [me, other]
        );
        if (blockRes.rows.length > 0) {
            return res.status(403).json({ error: 'blocked', blocker: blockRes.rows[0].blocker_username });
        }
        const msgs = await pool.query(`
            SELECT id, from_username, to_username, message, media_url, media_type, is_read, created_at
            FROM direct_messages
            WHERE (from_username=$1 AND to_username=$2) OR (from_username=$2 AND to_username=$1)
            ORDER BY created_at ASC LIMIT 200
        `, [me, other]);
        await pool.query(
            'UPDATE direct_messages SET is_read=TRUE WHERE to_username=$1 AND from_username=$2 AND NOT is_read',
            [me, other]
        );
        res.json(msgs.rows);
    } catch(err) { console.error(err); res.status(500).json({ error: 'Server error.' }); }
});

// ─── Block a User ─────────────────────────────────────────────────────────────
app.post('/api/block/:username', requireAuth, async (req, res) => {
    const me = req.session.username, target = req.params.username;
    if (me === target) return res.status(400).json({ error: 'Cannot block yourself.' });
    try {
        await pool.query(
            'INSERT INTO user_blocks (blocker_username, blocked_username) VALUES ($1, $2) ON CONFLICT DO NOTHING',
            [me, target]
        );
        res.json({ success: true });
    } catch(err) { res.status(500).json({ error: 'Server error.' }); }
});

// ─── Unblock a User ───────────────────────────────────────────────────────────
app.delete('/api/block/:username', requireAuth, async (req, res) => {
    const me = req.session.username, target = req.params.username;
    try {
        await pool.query(
            'DELETE FROM user_blocks WHERE blocker_username=$1 AND blocked_username=$2',
            [me, target]
        );
        res.json({ success: true });
    } catch(err) { res.status(500).json({ error: 'Server error.' }); }
});

// ─── My Block List ────────────────────────────────────────────────────────────
app.get('/api/blocks', requireAuth, async (req, res) => {
    const me = req.session.username;
    try {
        const result = await pool.query('SELECT blocked_username FROM user_blocks WHERE blocker_username=$1', [me]);
        res.json(result.rows.map(r => r.blocked_username));
    } catch(err) { res.status(500).json({ error: 'Server error.' }); }
});

// ─── Report a Room ────────────────────────────────────────────────────────────
app.post('/api/room/:roomCode/report', requireAuth, async (req, res) => {
    const reporter = req.session.username;
    const roomCode = req.params.roomCode.toUpperCase();
    const reason   = (req.body.reason || '').trim().slice(0, 500);
    if (!reason) return res.status(400).json({ error: 'Reason required.' });
    try {
        await pool.query(
            'INSERT INTO room_reports (room_code, reporter_username, reason) VALUES ($1, $2, $3)',
            [roomCode, reporter, reason]
        );
        res.json({ success: true });
    } catch(err) { console.error(err); res.status(500).json({ error: 'Server error.' }); }
});

// ─── Get Reports (staff only) ─────────────────────────────────────────────────
app.get('/api/reports', requireAuth, async (req, res) => {
    const caller = req.session.username;
    try {
        const staffRes = await pool.query('SELECT 1 FROM staff WHERE username = $1', [caller]);
        if (!staffRes.rows.length) return res.status(403).json({ error: 'Staff only.' });
        const result = await pool.query(
            `SELECT id, room_code, reporter_username, reason, resolved, created_at
             FROM room_reports ORDER BY resolved ASC, created_at DESC LIMIT 100`
        );
        res.json(result.rows);
    } catch(err) { console.error(err); res.status(500).json({ error: 'Server error.' }); }
});

// ─── Resolve Report (staff only) ──────────────────────────────────────────────
app.post('/api/reports/:id/resolve', requireAuth, async (req, res) => {
    const caller = req.session.username;
    const id = parseInt(req.params.id, 10);
    try {
        const staffRes = await pool.query('SELECT 1 FROM staff WHERE username = $1', [caller]);
        if (!staffRes.rows.length) return res.status(403).json({ error: 'Staff only.' });
        await pool.query('UPDATE room_reports SET resolved=TRUE WHERE id=$1', [id]);
        res.json({ success: true });
    } catch(err) { res.status(500).json({ error: 'Server error.' }); }
});

// ─── Delete a Room (owner or staff) ───────────────────────────────────────────
app.delete('/api/room/:roomCode', requireAuth, async (req, res) => {
    const caller   = req.session.username;
    const roomCode = req.params.roomCode.toUpperCase();
    try {
        const staffRes = await pool.query('SELECT 1 FROM staff WHERE username = $1', [caller]);
        const ownerRes = await pool.query('SELECT owner_username FROM room_owners WHERE room_code = $1', [roomCode]);
        const isOwner  = ownerRes.rows.length && ownerRes.rows[0].owner_username === caller;
        const isStaff  = staffRes.rows.length > 0;
        if (!isOwner && !isStaff) return res.status(403).json({ error: 'Not authorised.' });

        await pool.query('DELETE FROM chat_messages WHERE room_code = $1', [roomCode]);
        await pool.query('DELETE FROM room_bans    WHERE room_code = $1', [roomCode]);
        await pool.query('DELETE FROM room_reports WHERE room_code = $1', [roomCode]);
        await pool.query('DELETE FROM room_owners  WHERE room_code = $1', [roomCode]);

        res.json({ success: true });
    } catch(err) { console.error(err); res.status(500).json({ error: 'Server error.' }); }
});

// ─── Report a User ────────────────────────────────────────────────────────────
app.post('/api/user/:username/report', requireAuth, async (req, res) => {
    const reporter  = req.session.username;
    const reported  = req.params.username.trim().slice(0, 30);
    const reason    = (req.body.reason || '').trim().slice(0, 500);
    if (!reason) return res.status(400).json({ error: 'Reason required.' });
    if (reporter === reported) return res.status(400).json({ error: 'Cannot report yourself.' });
    try {
        const exists = await pool.query('SELECT 1 FROM users WHERE username=$1', [reported]);
        if (!exists.rows.length) return res.status(404).json({ error: 'User not found.' });
        await pool.query(
            'INSERT INTO user_reports (reported_username, reporter_username, reason) VALUES ($1, $2, $3)',
            [reported, reporter, reason]
        );
        res.json({ success: true });
    } catch(err) { console.error(err); res.status(500).json({ error: 'Server error.' }); }
});

// ─── Get User Reports (staff only) ────────────────────────────────────────────
app.get('/api/user-reports', requireAuth, async (req, res) => {
    const caller = req.session.username;
    try {
        const staffRes = await pool.query('SELECT 1 FROM staff WHERE username = $1', [caller]);
        if (!staffRes.rows.length) return res.status(403).json({ error: 'Staff only.' });
        const result = await pool.query(
            `SELECT id, reported_username, reporter_username, reason, resolved, created_at
             FROM user_reports ORDER BY resolved ASC, created_at DESC LIMIT 100`
        );
        res.json(result.rows);
    } catch(err) { console.error(err); res.status(500).json({ error: 'Server error.' }); }
});

// ─── Resolve User Report (staff only) ─────────────────────────────────────────
app.post('/api/user-reports/:id/resolve', requireAuth, async (req, res) => {
    const caller = req.session.username;
    const id = parseInt(req.params.id, 10);
    try {
        const staffRes = await pool.query('SELECT 1 FROM staff WHERE username = $1', [caller]);
        if (!staffRes.rows.length) return res.status(403).json({ error: 'Staff only.' });
        await pool.query('UPDATE user_reports SET resolved=TRUE WHERE id=$1', [id]);
        res.json({ success: true });
    } catch(err) { res.status(500).json({ error: 'Server error.' }); }
});

// ─── Delete a User Account (staff only) ───────────────────────────────────────
app.delete('/api/user/:username', requireAuth, async (req, res) => {
    const caller   = req.session.username;
    const target   = req.params.username.trim().slice(0, 30);
    try {
        const staffRes = await pool.query('SELECT 1 FROM staff WHERE username = $1', [caller]);
        if (!staffRes.rows.length) return res.status(403).json({ error: 'Staff only.' });
        if (target === caller) return res.status(400).json({ error: 'Cannot delete your own account.' });
        const userRes = await pool.query('SELECT 1 FROM users WHERE username=$1', [target]);
        if (!userRes.rows.length) return res.status(404).json({ error: 'User not found.' });
        // Clean up all user data
        await pool.query('DELETE FROM chat_messages    WHERE username = $1', [target]);
        await pool.query('DELETE FROM direct_messages  WHERE from_username=$1 OR to_username=$1', [target]);
        await pool.query('DELETE FROM user_blocks      WHERE blocker_username=$1 OR blocked_username=$1', [target]);
        await pool.query('DELETE FROM room_bans        WHERE banned_username=$1', [target]);
        await pool.query('DELETE FROM room_owners      WHERE owner_username=$1', [target]);
        await pool.query('DELETE FROM user_reports     WHERE reported_username=$1 OR reporter_username=$1', [target]);
        await pool.query('DELETE FROM room_reports     WHERE reporter_username=$1', [target]);
        await pool.query('DELETE FROM users            WHERE username=$1', [target]);
        res.json({ success: true });
    } catch(err) { console.error(err); res.status(500).json({ error: 'Server error.' }); }
});

// ─── Delete a Message (staff or message author) ───────────────────────────────
app.delete('/api/message/:messageId', requireAuth, async (req, res) => {
    const caller    = req.session.username;
    const messageId = parseInt(req.params.messageId, 10);
    try {
        const msgRes = await pool.query('SELECT username, room_code FROM chat_messages WHERE id = $1', [messageId]);
        if (!msgRes.rows.length) return res.status(404).json({ error: 'Message not found.' });
        const msg = msgRes.rows[0];

        const staffRes = await pool.query('SELECT 1 FROM staff WHERE username = $1', [caller]);
        const isStaff  = staffRes.rows.length > 0;
        const isAuthor = msg.username === caller;
        if (!isStaff && !isAuthor) return res.status(403).json({ error: 'Not authorised.' });

        await pool.query('DELETE FROM chat_messages WHERE id = $1', [messageId]);
        res.json({ success: true, roomCode: msg.room_code, messageId });
    } catch(err) { console.error(err); res.status(500).json({ error: 'Server error.' }); }
});

// ─── HTML File Fallback ───────────────────────────────────────────────────────
app.get('/:file', (req, res) => {
    const filePath = path.join(__dirname, req.params.file);
    if (fs.existsSync(filePath) && filePath.endsWith('.html')) res.sendFile(filePath);
    else res.status(404).send('Not found');
});

// ─── Staff Helper ─────────────────────────────────────────────────────────────
async function checkIsStaff(username) {
    try {
        const res = await pool.query('SELECT 1 FROM staff WHERE username = $1', [username]);
        return res.rows.length > 0;
    } catch { return false; }
}

// ─── DB Init ──────────────────────────────────────────────────────────────────
async function initDB() {
    await pool.query(`
        CREATE TABLE IF NOT EXISTS direct_messages (
            id SERIAL PRIMARY KEY,
            from_username VARCHAR(30) NOT NULL,
            to_username   VARCHAR(30) NOT NULL,
            message       TEXT,
            media_url     TEXT,
            media_type    VARCHAR(20),
            is_read       BOOLEAN DEFAULT FALSE,
            created_at    TIMESTAMP DEFAULT NOW()
        )
    `);
    await pool.query(`
        CREATE TABLE IF NOT EXISTS user_blocks (
            blocker_username VARCHAR(30) NOT NULL,
            blocked_username VARCHAR(30) NOT NULL,
            created_at       TIMESTAMP DEFAULT NOW(),
            PRIMARY KEY (blocker_username, blocked_username)
        )
    `);
    await pool.query(`
        CREATE TABLE IF NOT EXISTS room_reports (
            id               SERIAL PRIMARY KEY,
            room_code        VARCHAR(20) NOT NULL,
            reporter_username VARCHAR(30) NOT NULL,
            reason           TEXT NOT NULL,
            resolved         BOOLEAN DEFAULT FALSE,
            created_at       TIMESTAMP DEFAULT NOW()
        )
    `);
    await pool.query(`
        CREATE TABLE IF NOT EXISTS user_reports (
            id                SERIAL PRIMARY KEY,
            reported_username VARCHAR(30) NOT NULL,
            reporter_username VARCHAR(30) NOT NULL,
            reason            TEXT NOT NULL,
            resolved          BOOLEAN DEFAULT FALSE,
            created_at        TIMESTAMP DEFAULT NOW()
        )
    `);
}
initDB().catch(console.error);

// ─── WebSocket Chat ───────────────────────────────────────────────────────────
// rooms: roomCode -> { clients: Map<ws, username>, owner: username }
const rooms = new Map();
// online users: username -> Set<ws>  (multiple tabs support)
const onlineUsers = new Map();

function getRoom(roomCode) {
    if (!rooms.has(roomCode)) rooms.set(roomCode, { clients: new Map(), owner: null });
    return rooms.get(roomCode);
}

function broadcastRoom(roomCode, data, excludeWs = null) {
    const room = rooms.get(roomCode);
    if (!room) return;
    const msg = JSON.stringify(data);
    room.clients.forEach((uname, client) => {
        if (client !== excludeWs && client.readyState === WebSocket.OPEN) {
            client.send(msg);
        }
    });
}

function getMemberList(roomCode) {
    const room = rooms.get(roomCode);
    if (!room) return [];
    return Array.from(room.clients.values());
}

wss.on('connection', (ws) => {
    let currentRoom = null;
    let currentUsername = null;
    let currentIsStaff = false;

    ws.on('message', async (rawData) => {
        let data;
        try { data = JSON.parse(rawData); } catch { return; }

        // ── Presence (lobby DM tracking) ─────────────────────────────────────
        if (data.type === 'presence') {
            const username = (data.username || '').trim().slice(0, 30);
            if (!username) return;
            currentUsername = username;
            if (!onlineUsers.has(username)) onlineUsers.set(username, new Set());
            onlineUsers.get(username).add(ws);
            ws.send(JSON.stringify({ type: 'presence_ack' }));
            return;

        // ── Join ──────────────────────────────────────────────────────────────
        } else if (data.type === 'join') {
            const roomCode = (data.roomCode || '').trim().toUpperCase();
            const username = (data.username || '').trim().slice(0, 30);
            if (!roomCode || !username) {
                ws.send(JSON.stringify({ type: 'error', message: 'Invalid room or username.' }));
                return;
            }

            // Check ban
            try {
                const banCheck = await pool.query(
                    'SELECT 1 FROM room_bans WHERE room_code = $1 AND banned_username = $2',
                    [roomCode, username]
                );
                if (banCheck.rows.length > 0) {
                    ws.send(JSON.stringify({ type: 'error', message: 'You are banned from this room.' }));
                    return;
                }
            } catch (err) { console.error(err); }

            const room = getRoom(roomCode);

            // Always look up ownership from DB — never assign by join order
            try {
                const ownerRes = await pool.query('SELECT owner_username FROM room_owners WHERE room_code = $1', [roomCode]);
                room.owner = ownerRes.rows[0]?.owner_username || null;
            } catch (err) { console.error(err); }

            currentIsStaff = await checkIsStaff(username);
            room.clients.set(ws, username);
            currentRoom = roomCode;
            currentUsername = username;

            // Track online presence for DM delivery
            if (!onlineUsers.has(username)) onlineUsers.set(username, new Set());
            onlineUsers.get(username).add(ws);

            ws.send(JSON.stringify({
                type: 'joined',
                roomCode,
                username,
                isOwner: room.owner === username,
                isStaff: currentIsStaff,
                members: getMemberList(roomCode)
            }));

            broadcastRoom(roomCode, {
                type: 'system',
                message: `${username} joined the room.`,
                members: getMemberList(roomCode)
            }, ws);

        // ── Text / Media Message ──────────────────────────────────────────────
        } else if (data.type === 'message') {
            if (!currentRoom || !currentUsername) return;
            const message = (data.message || '').trim().slice(0, 500);
            const mediaUrl = data.mediaUrl || null;
            const mediaType = data.mediaType || null;
            const replyToUsername = (data.replyToUsername || '').trim().slice(0, 30) || null;
            const replyToMessage = (data.replyToMessage || '').trim().slice(0, 200) || null;
            if (!message && !mediaUrl) return;

            let messageId = null;
            try {
                const ins = await pool.query(
                    'INSERT INTO chat_messages (room_code, username, message, media_url, media_type, reply_to_username, reply_to_message) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id',
                    [currentRoom, currentUsername, message || '', mediaUrl, mediaType, replyToUsername, replyToMessage]
                );
                messageId = ins.rows[0].id;
            } catch (err) { console.error(err); }

            const payload = {
                type: 'message',
                id: messageId,
                username: currentUsername,
                message,
                mediaUrl,
                mediaType,
                replyToUsername,
                replyToMessage,
                time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
            };

            ws.send(JSON.stringify(payload));
            broadcastRoom(currentRoom, payload, ws);

        // ── Kick ─────────────────────────────────────────────────────────────
        } else if (data.type === 'kick') {
            if (!currentRoom || !currentUsername) return;
            const room = rooms.get(currentRoom);
            if (!room || (room.owner !== currentUsername && !currentIsStaff)) return;

            const target = (data.target || '').trim();
            if (!target || target === currentUsername) return;

            room.clients.forEach((uname, client) => {
                if (uname === target) {
                    client.send(JSON.stringify({ type: 'kicked', message: 'You were kicked by the room owner.' }));
                    client.close();
                }
            });

        // ── Unban ─────────────────────────────────────────────────────────────
        } else if (data.type === 'unban') {
            if (!currentRoom || !currentUsername) return;
            const room = rooms.get(currentRoom);
            if (!room || (room.owner !== currentUsername && !currentIsStaff)) return;

            const target = (data.target || '').trim();
            if (!target) return;

            try {
                await pool.query(
                    'DELETE FROM room_bans WHERE room_code = $1 AND banned_username = $2',
                    [currentRoom, target]
                );
            } catch (err) { console.error(err); }

            ws.send(JSON.stringify({
                type: 'unban_success',
                target,
                message: `${target} has been unbanned.`
            }));

        // ── Ban ───────────────────────────────────────────────────────────────
        } else if (data.type === 'ban') {
            if (!currentRoom || !currentUsername) return;
            const room = rooms.get(currentRoom);
            if (!room || (room.owner !== currentUsername && !currentIsStaff)) return;

            const target = (data.target || '').trim();
            if (!target || target === currentUsername) return;

            try {
                await pool.query(
                    'INSERT INTO room_bans (room_code, banned_username) VALUES ($1, $2) ON CONFLICT DO NOTHING',
                    [currentRoom, target]
                );
            } catch (err) { console.error(err); }

            room.clients.forEach((uname, client) => {
                if (uname === target) {
                    client.send(JSON.stringify({ type: 'kicked', message: 'You were banned from this room.' }));
                    client.close();
                }
            });

            broadcastRoom(currentRoom, {
                type: 'system',
                message: `${target} was banned from the room.`,
                members: getMemberList(currentRoom)
            });

        // ── Direct Message ────────────────────────────────────────────────────
        } else if (data.type === 'dm') {
            if (!currentUsername) return;
            const dmTarget  = (data.target  || '').trim().slice(0, 30);
            const dmMessage = (data.message || '').trim().slice(0, 1000);
            if (!dmTarget || !dmMessage || dmTarget === currentUsername) return;

            try {
                const blockRes = await pool.query(
                    'SELECT 1 FROM user_blocks WHERE (blocker_username=$1 AND blocked_username=$2) OR (blocker_username=$2 AND blocked_username=$1)',
                    [currentUsername, dmTarget]
                );
                if (blockRes.rows.length > 0) {
                    ws.send(JSON.stringify({ type: 'dm_error', target: dmTarget, message: 'Cannot send — one of you has blocked the other.' }));
                    return;
                }

                const inserted = await pool.query(
                    'INSERT INTO direct_messages (from_username, to_username, message) VALUES ($1, $2, $3) RETURNING id, created_at',
                    [currentUsername, dmTarget, dmMessage]
                );
                const row = inserted.rows[0];

                const dmPayload = {
                    type: 'dm',
                    id: row.id,
                    from: currentUsername,
                    to: dmTarget,
                    message: dmMessage,
                    time: new Date(row.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
                };

                ws.send(JSON.stringify(dmPayload));

                const targetSockets = onlineUsers.get(dmTarget);
                if (targetSockets) {
                    targetSockets.forEach(sock => {
                        if (sock.readyState === WebSocket.OPEN) sock.send(JSON.stringify(dmPayload));
                    });
                }
            } catch(err) { console.error(err); }

        // ── Delete Message (staff or author via WS) ───────────────────────────
        } else if (data.type === 'delete_message') {
            if (!currentUsername) return;
            const msgId = parseInt(data.messageId, 10);
            if (!msgId) return;
            try {
                const msgRes = await pool.query('SELECT username, room_code FROM chat_messages WHERE id=$1', [msgId]);
                if (!msgRes.rows.length) return;
                const msg = msgRes.rows[0];
                if (msg.username !== currentUsername && !currentIsStaff) return;
                await pool.query('DELETE FROM chat_messages WHERE id=$1', [msgId]);
                const delPayload = { type: 'message_deleted', messageId: msgId };
                ws.send(JSON.stringify(delPayload));
                if (msg.room_code) broadcastRoom(msg.room_code, delPayload, ws);
            } catch(err) { console.error(err); }
        }
    });

    ws.on('close', () => {
        // Remove from online presence
        if (currentUsername) {
            const socks = onlineUsers.get(currentUsername);
            if (socks) {
                socks.delete(ws);
                if (socks.size === 0) onlineUsers.delete(currentUsername);
            }
        }
        if (currentRoom) {
            const room = rooms.get(currentRoom);
            if (room) {
                room.clients.delete(ws);
                if (room.clients.size === 0) {
                    rooms.delete(currentRoom);
                } else {
                    broadcastRoom(currentRoom, {
                        type: 'system',
                        message: `${currentUsername} left the room.`,
                        members: getMemberList(currentRoom)
                    });
                }
            }
        }
    });
});

// ─── Start Server ─────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 5000;
const HOST = '0.0.0.0';

server.listen(PORT, HOST, () => {
    console.log(`Server is running on http://${HOST}:${PORT}`);
    process.on('SIGTERM', () => server.close(() => process.exit(0)));
});
