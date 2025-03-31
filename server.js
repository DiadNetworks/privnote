const express = require('express');
const router = express.Router();
const pool = require('./db');
const bcrypt = require('bcryptjs');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const { v4: uuidv4 } = require('uuid');
const nodemailer = require('nodemailer');
const { logger, securityLogger } = require('./logger');
const { Readable } = require('stream');

// Helper function to get client IP
const getClientIp = (req) => {
    return req.headers['x-forwarded-for'] || req.connection.remoteAddress;
};

// AdSense script (replace with your actual publisher ID)
const adSenseScript = `
    <script async src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=ca-pub-8136699511765059"
            crossorigin="anonymous"></script>
`;

// Regular Site: Serve the main page
router.get('/', (req, res) => {
    const ip = getClientIp(req);
    logger.info(`Main page accessed`, { ip });
    res.sendFile('index.html', { root: 'public' });
});

// Regular Site: Get dropdown options
router.get('/api/options', async (req, res) => {
    const ip = getClientIp(req);
    try {
        const [destructionOpts] = await pool.query('SELECT value FROM options WHERE type = "destruction"');
        const [expirationOpts] = await pool.query('SELECT value FROM options WHERE type = "expiration"');
        logger.info(`Dropdown options retrieved`, { ip });
        res.json({
            destruction: destructionOpts.map(opt => opt.value),
            expiration: expirationOpts.map(opt => opt.value),
        });
    } catch (err) {
        logger.error(`Error fetching options: ${err.message}`, { ip });
        res.status(500).json({ error: 'Database error' });
    }
});

// Regular Site: Create a note
router.post('/api/create-note', async (req, res) => {
    const ip = getClientIp(req);
    const { content, destroyAfterRead, expiry, password } = req.body;
    const noteId = uuidv4();
    let passwordHash = null;

    if (password) {
        passwordHash = await bcrypt.hash(password, 10);
    }

    try {
        await pool.query(
            'INSERT INTO notes (id, content, destroy_after_read, expiry, password_hash) VALUES (?, ?, ?, ?, ?)',
            [noteId, content, destroyAfterRead === 'Destroy immediately after reading', expiry, passwordHash]
        );
        logger.info(`Note created with ID ${noteId}`, { ip });
        res.json({ link: `/note/${noteId}` });
    } catch (err) {
        logger.error(`Note creation failed: ${err.message}`, { ip });
        res.status(500).json({ error: 'Note creation failed' });
    }
});

// Regular Site: View a note
router.get('/note/:id', async (req, res) => {
    const ip = getClientIp(req);
    const { id } = req.params;

    try {
        const [notes] = await pool.query('SELECT * FROM notes WHERE id = ?', [id]);
        if (notes.length === 0) {
            logger.warn(`Note not found: ${id}`, { ip });
            return res.send(`
                <!DOCTYPE html>
                <html>
                <head>
                    <link rel="stylesheet" href="/styles.css">
                    ${adSenseScript}
                </head>
                <body>
                    <div class="note-container">
                        <h1 class="note-title">Note Not Found</h1>
                        <p class="note-content">This note does not exist or has been destroyed.</p>
                    </div>
                </body>
                </html>
            `);
        }

        const note = notes[0];
        if (note.destroyed_at) {
            logger.warn(`Note already destroyed: ${id}`, { ip });
            return res.send(`
                <!DOCTYPE html>
                <html>
                <head>
                    <link rel="stylesheet" href="/styles.css">
                    ${adSenseScript}
                </head>
                <body>
                    <div class="note-container">
                        <h1 class="note-title">Note Destroyed</h1>
                        <p class="note-content">This note has been destroyed.</p>
                    </div>
                </body>
                </html>
            `);
        }

        if (note.password_hash && (!req.session.verifiedNotes || !req.session.verifiedNotes.includes(id))) {
            logger.info(`Password required for note ${id}`, { ip });
            return res.send(`
                <!DOCTYPE html>
                <html>
                <head>
                    <link rel="stylesheet" href="/styles.css">
                    ${adSenseScript}
                </head>
                <body>
                    <div class="note-container">
                        <h1 class="note-title">Enter Password</h1>
                        <form action="/note/${id}/verify" method="POST">
                            <input type="password" name="password" placeholder="Enter password" required>
                            <button type="submit">View Note</button>
                        </form>
                    </div>
                </body>
                </html>
            `);
        }

        let destroyMessage = note.destroy_after_read
            ? 'This note will be destroyed after you close this page.'
            : `This note will expire at ${new Date(note.expiry).toLocaleString()}.`;

        logger.info(`Note viewed: ${id}`, { ip });
        res.send(`
            <!DOCTYPE html>
            <html>
            <head>
                <link rel="stylesheet" href="/styles.css">
                ${adSenseScript}
                <script>
                    window.onunload = function() {
                        fetch('/note/${id}/destroy', { method: 'POST' });
                    };
                </script>
            </head>
            <body>
                <div class="note-container">
                    <h1 class="note-title">Your Note</h1>
                    <p class="note-content">${note.content}</p>
                    <p class="note-message">${destroyMessage}</p>
                    <a href="/note/${id}/download" class="note-download-btn" download="note-${id}.txt">Download</a>
                </div>
            </body>
            </html>
        `);
    } catch (err) {
        logger.error(`Error viewing note ${id}: ${err.message}`, { ip });
        res.status(500).send('Error retrieving note');
    }
});

// Regular Site: Verify password for a note
router.post('/note/:id/verify', async (req, res) => {
    const ip = getClientIp(req);
    const { id } = req.params;
    const { password } = req.body;

    try {
        const [notes] = await pool.query('SELECT * FROM notes WHERE id = ?', [id]);
        if (notes.length === 0) {
            logger.warn(`Note not found for verification: ${id}`, { ip });
            return res.send(`
                <!DOCTYPE html>
                <html>
                <head>
                    <link rel="stylesheet" href="/styles.css">
                    ${adSenseScript}
                </head>
                <body>
                    <div class="note-container">
                        <h1 class="note-title">Note Not Found</h1>
                        <p class="note-content">This note does not exist or has been destroyed.</p>
                    </div>
                </body>
                </html>
            `);
        }

        const note = notes[0];
        if (note.destroyed_at) {
            logger.warn(`Note already destroyed: ${id}`, { ip });
            return res.send(`
                <!DOCTYPE html>
                <html>
                <head>
                    <link rel="stylesheet" href="/styles.css">
                    ${adSenseScript}
                </head>
                <body>
                    <div class="note-container">
                        <h1 class="note-title">Note Destroyed</h1>
                        <p class="note-content">This note has been destroyed.</p>
                    </div>
                </body>
                </html>
            `);
        }

        const isMatch = await bcrypt.compare(password, note.password_hash);
        if (!isMatch) {
            logger.warn(`Invalid password for note ${id}`, { ip });
            return res.send(`
                <!DOCTYPE html>
                <html>
                <head>
                    <link rel="stylesheet" href="/styles.css">
                    ${adSenseScript}
                </head>
                <body>
                    <div class="note-container">
                        <h1 class="note-title">Incorrect Password</h1>
                        <p class="note-content">The password you entered is incorrect.</p>
                        <a href="/note/${id}">Try again</a>
                    </div>
                </body>
                </html>
            `);
        }

        if (!req.session.verifiedNotes) req.session.verifiedNotes = [];
        req.session.verifiedNotes.push(id);

        let destroyMessage = note.destroy_after_read
            ? 'This note will be destroyed after you close this page.'
            : `This note will expire at ${new Date(note.expiry).toLocaleString()}.`;

        logger.info(`Note verified and viewed: ${id}`, { ip });
        res.send(`
            <!DOCTYPE html>
            <html>
            <head>
                <link rel="stylesheet" href="/styles.css">
                ${adSenseScript}
                <script>
                    window.onunload = function() {
                        fetch('/note/${id}/destroy', { method: 'POST' });
                    };
                </script>
            </head>
            <body>
                <div class="note-container">
                    <h1 class="note-title">Your Note</h1>
                    <p class="note-content">${note.content}</p>
                    <p class="note-message">${destroyMessage}</p>
                    <a href="/note/${id}/download" class="note-download-btn" download="note-${id}.txt">Download</a>
                </div>
            </body>
            </html>
        `);
    } catch (err) {
        logger.error(`Error verifying note ${id}: ${err.message}`, { ip });
        res.status(500).send('Error verifying password');
    }
});

// Regular Site: Download note as TXT
router.get('/note/:id/download', async (req, res) => {
    const ip = getClientIp(req);
    const { id } = req.params;

    try {
        const [notes] = await pool.query('SELECT * FROM notes WHERE id = ?', [id]);
        if (notes.length === 0) {
            logger.warn(`Note not found for download: ${id}`, { ip });
            return res.status(404).send(`
                <!DOCTYPE html>
                <html>
                <head>
                    <link rel="stylesheet" href="/styles.css">
                    ${adSenseScript}
                </head>
                <body>
                    <div class="note-container">
                        <h1 class="note-title">Note Not Found</h1>
                        <p class="note-content">This note does not exist or has been destroyed.</p>
                    </div>
                </body>
                </html>
            `);
        }

        const note = notes[0];
        if (note.destroyed_at) {
            logger.warn(`Note already destroyed for download: ${id}`, { ip });
            return res.status(410).send(`
                <!DOCTYPE html>
                <html>
                <head>
                    <link rel="stylesheet" href="/styles.css">
                    ${adSenseScript}
                </head>
                <body>
                    <div class="note-container">
                        <h1 class="note-title">Note Destroyed</h1>
                        <p class="note-content">This note has been destroyed.</p>
                    </div>
                </body>
                </html>
            `);
        }

        if (note.password_hash && (!req.session.verifiedNotes || !req.session.verifiedNotes.includes(id))) {
            logger.info(`Password required before download: ${id}`, { ip });
            return res.redirect(`/note/${id}`);
        }

        const content = note.content; // Only the note content
        
        res.setHeader('Content-Type', 'text/plain');
        res.setHeader('Content-Disposition', `attachment; filename="note-${id}.txt"`);
        res.send(content);

        logger.info(`Note ${id} downloaded as TXT`, { ip });
    } catch (err) {
        logger.error(`Error downloading note ${id}: ${err.message}`, { ip });
        res.status(500).send('Error downloading note');
    }
});

// Regular Site: Destroy note (called on page unload)
router.post('/note/:id/destroy', async (req, res) => {
    const ip = getClientIp(req);
    const { id } = req.params;

    try {
        const [notes] = await pool.query('SELECT * FROM notes WHERE id = ?', [id]);
        if (notes.length === 0 || notes[0].destroyed_at) {
            logger.info(`Note ${id} already destroyed or not found`, { ip });
            return res.status(200).send('Note already destroyed');
        }

        const note = notes[0];
        if (note.destroy_after_read) {
            await pool.query('UPDATE notes SET destroyed_at = NOW() WHERE id = ?', [id]);
            logger.info(`Note destroyed on unload: ${id}`, { ip });
        }
        res.status(200).send('Note marked for destruction');
    } catch (err) {
        logger.error(`Error destroying note ${id}: ${err.message}`, { ip });
        res.status(500).send('Error destroying note');
    }
});

// Admin Site: Serve admin page or check setup
router.get('/admin', async (req, res) => {
    const ip = getClientIp(req);
    try {
        const [users] = await pool.query('SELECT COUNT(*) as count FROM admin_users');
        if (users[0].count === 0) {
            logger.info(`No admin users, redirecting to setup`, { ip });
            return res.redirect('/admin/setup');
        }

        if (!req.session.user) {
            logger.info(`Admin login page served`, { ip });
            return res.sendFile('admin.html', { root: 'public' });
        }

        logger.info(`Admin dashboard accessed by ${req.session.user.email}`, { ip, user: req.session.user.email });
        res.sendFile('admin.html', { root: 'public' });
    } catch (err) {
        logger.error(`Error checking admin setup: ${err.message}`, { ip });
        res.status(500).send('Server error');
    }
});

// Admin Site: First-time setup page
router.get('/admin/setup', async (req, res) => {
    const ip = getClientIp(req);
    try {
        const [users] = await pool.query('SELECT COUNT(*) as count FROM admin_users');
        if (users[0].count > 0) {
            logger.info(`Admin already exists, redirecting to login`, { ip });
            return res.redirect('/admin');
        }

        logger.info(`Admin setup page served`, { ip });
        res.send(`
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Setup Admin - Privnote</title>
                <link rel="stylesheet" href="/styles.css">
                ${adSenseScript}
            </head>
            <body>
                <div class="setup-container">
                    <h2>Setup First Admin Account</h2>
                    <form action="/admin/setup" method="POST">
                        <input type="email" name="email" placeholder="Email" required>
                        <input type="password" name="password" placeholder="Password" required>
                        <button type="submit">Create Admin</button>
                    </form>
                </div>
            </body>
            </html>
        `);
    } catch (err) {
        logger.error(`Error serving setup page: ${err.message}`, { ip });
        res.status(500).send('Setup page error');
    }
});

// Admin Site: Process first-time setup
router.post('/admin/setup', async (req, res) => {
    const ip = getClientIp(req);
    const { email, password } = req.body;

    try {
        const passwordHash = await bcrypt.hash(password, 10);
        const secret = speakeasy.generateSecret({ name: 'Privnote Admin' });

        await pool.query(
            'INSERT INTO admin_users (email, password_hash, totp_secret, role, totp_setup, reset_password) VALUES (?, ?, ?, ?, ?, ?)',
            [email, passwordHash, secret.base32, 'admin', false, false]
        );

        logger.info(`Admin created: ${email}`, { ip });
        qrcode.toDataURL(secret.otpauth_url, (err, data_url) => {
            if (err) {
                logger.error(`QR code generation failed: ${err.message}`, { ip });
                return res.status(500).send('QR code error');
            }
            res.send(`
                <!DOCTYPE html>
                <html>
                <head>
                    ${adSenseScript}
                </head>
                <body>
                    <h2>Admin Created</h2>
                    <p>Scan this QR code with your authenticator app:</p>
                    <img src="${data_url}" alt="2FA QR Code">
                    <p>Then log in with your credentials.</p>
                    <a href="/admin">Go to Login</a>
                </body>
                </html>
            `);
        });
    } catch (err) {
        logger.error(`Admin setup failed: ${err.message}`, { ip });
        res.status(500).send('Admin creation error');
    }
});

// Admin Site: Login Step 1 - Email/Password
router.post('/admin/login/email-password', async (req, res) => {
    const ip = getClientIp(req);
    const { email, password } = req.body;

    try {
        const [users] = await pool.query('SELECT * FROM admin_users WHERE email = ?', [email]);
        if (users.length === 0 || !await bcrypt.compare(password, users[0].password_hash)) {
            securityLogger.warn(`Login failed for ${email}`, { ip, user: email });
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        req.session.tempUser = users[0];
        logger.info(`Email/password validated for ${email}`, { ip, user: email });
        res.json({ success: true, needs2FA: true, userId: users[0].id });
    } catch (err) {
        logger.error(`Login error: ${err.message}`, { ip });
        res.status(500).json({ error: 'Login failed' });
    }
});

// Admin Site: Login Step 2 - 2FA
router.post('/admin/login/totp', async (req, res) => {
    const ip = getClientIp(req);
    const { totp } = req.body;

    if (!req.session.tempUser) {
        securityLogger.warn(`2FA attempted without session`, { ip });
        return res.status(401).json({ error: 'Session expired' });
    }

    const user = req.session.tempUser;
    try {
        if (!user.totp_setup) {
            logger.info(`2FA setup required for ${user.email}`, { ip, user: user.email });
            return res.json({ needs2FASetup: true, userId: user.id });
        }

        const verified = speakeasy.totp.verify({
            secret: user.totp_secret,
            encoding: 'base32',
            token: totp,
        });

        if (!verified) {
            securityLogger.warn(`Invalid 2FA for ${user.email}`, { ip, user: user.email });
            return res.status(401).json({ error: 'Invalid 2FA code' });
        }

        if (user.reset_password) {
            logger.info(`Password reset required for ${user.email}`, { ip, user: user.email });
            return res.json({ needsPasswordReset: true });
        }

        req.session.user = user;
        delete req.session.tempUser;
        logger.info(`Login successful for ${user.email}`, { ip, user: user.email });
        res.json({ success: true });
    } catch (err) {
        logger.error(`2FA error: ${err.message}`, { ip });
        res.status(500).json({ error: '2FA failed' });
    }
});

// Admin Site: 2FA Setup
router.get('/admin/setup-2fa/:userId', async (req, res) => {
    const ip = getClientIp(req);
    const { userId } = req.params;

    try {
        const [users] = await pool.query('SELECT * FROM admin_users WHERE id = ?', [userId]);
        if (users.length === 0 || users[0].totp_setup) {
            logger.info(`Redirecting from 2FA setup for ${userId}`, { ip });
            return res.redirect('/admin');
        }

        const user = users[0];
        qrcode.toDataURL(`otpauth://totp/Privnote:${user.email}?secret=${user.totp_secret}&issuer=Privnote`, (err, data_url) => {
            if (err) {
                logger.error(`QR code error: ${err.message}`, { ip });
                return res.status(500).send('QR code generation failed');
            }
            res.send(`
                <!DOCTYPE html>
                <html>
                <head>
                    ${adSenseScript}
                </head>
                <body>
                    <h2>Setup 2FA</h2>
                    <p>Scan this QR code:</p>
                    <img src="${data_url}" alt="2FA QR Code">
                    <form action="/admin/setup-2fa/${userId}" method="POST">
                        <input type="text" name="totp" placeholder="Enter 2FA Code" required>
                        <button type="submit">Verify</button>
                    </form>
                </body>
                </html>
            `);
        });
    } catch (err) {
        logger.error(`2FA setup error: ${err.message}`, { ip });
        res.status(500).send('2FA setup failed');
    }
});

router.post('/admin/setup-2fa/:userId', async (req, res) => {
    const ip = getClientIp(req);
    const { userId } = req.params;
    const { totp } = req.body;

    try {
        const [users] = await pool.query('SELECT * FROM admin_users WHERE id = ?', [userId]);
        if (users.length === 0) {
            logger.warn(`User not found: ${userId}`, { ip });
            return res.status(404).send('User not found');
        }

        const user = users[0];
        const verified = speakeasy.totp.verify({
            secret: user.totp_secret,
            encoding: 'base32',
            token: totp,
        });

        if (!verified) {
            securityLogger.warn(`Invalid 2FA code for ${user.email}`, { ip, user: user.email });
            return res.send(`Invalid 2FA code. <a href="/admin/setup-2fa/${userId}">Try again</a>`);
        }

        await pool.query('UPDATE admin_users SET totp_setup = TRUE WHERE id = ?', [userId]);
        logger.info(`2FA setup completed for ${user.email}`, { ip, user: user.email });
        res.send('2FA setup complete. <a href="/admin">Go to Login</a>');
    } catch (err) {
        logger.error(`2FA verification error: ${err.message}`, { ip });
        res.status(500).send('2FA verification failed');
    }
});

// Admin Site: Password Reset
router.post('/admin/reset-password', async (req, res) => {
    const ip = getClientIp(req);
    if (!req.session.tempUser) {
        securityLogger.warn(`Password reset without session`, { ip });
        return res.status(401).json({ error: 'Session expired' });
    }

    const user = req.session.tempUser;
    const { newPassword, confirmPassword } = req.body;

    if (newPassword !== confirmPassword) {
        logger.warn(`Password mismatch for ${user.email}`, { ip, user: user.email });
        return res.status(400).json({ error: 'Passwords do not match' });
    }

    try {
        const passwordHash = await bcrypt.hash(newPassword, 10);
        await pool.query('UPDATE admin_users SET password_hash = ?, reset_password = FALSE WHERE id = ?', [passwordHash, user.id]);
        req.session.user = user;
        delete req.session.tempUser;
        logger.info(`Password reset for ${user.email}`, { ip, user: user.email });
        res.json({ success: true });
    } catch (err) {
        logger.error(`Password reset error: ${err.message}`, { ip });
        res.status(500).json({ error: 'Reset failed' });
    }
});

// Admin Site: Get notes (last 24 hours)
router.get('/admin/notes', async (req, res) => {
    const ip = getClientIp(req);
    if (!req.session.user) {
        securityLogger.warn(`Unauthorized notes access`, { ip });
        return res.status(401).json({ error: 'Unauthorized' });
    }

    try {
        const [roles] = await pool.query('SELECT * FROM roles WHERE name = ?', [req.session.user.role]);
        if (roles.length === 0 || !roles[0].can_view) {
            securityLogger.warn(`No view permission for ${req.session.user.email}`, { ip, user: req.session.user.email });
            return res.status(403).json({ error: 'Permission denied' });
        }

        const [notes] = await pool.query('SELECT * FROM notes WHERE created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)');
        logger.info(`Notes fetched by ${req.session.user.email}`, { ip, user: req.session.user.email });
        res.json(notes);
    } catch (err) {
        logger.error(`Notes fetch error: ${err.message}`, { ip });
        res.status(500).json({ error: 'Fetch failed' });
    }
});

// Admin Site: Delete a note
router.delete('/admin/note/:id', async (req, res) => {
    const ip = getClientIp(req);
    if (!req.session.user) {
        securityLogger.warn(`Unauthorized delete attempt`, { ip });
        return res.status(401).json({ error: 'Unauthorized' });
    }

    try {
        const [roles] = await pool.query('SELECT * FROM roles WHERE name = ?', [req.session.user.role]);
        if (roles.length === 0 || !roles[0].can_delete) {
            securityLogger.warn(`No delete permission for ${req.session.user.email}`, { ip, user: req.session.user.email });
            return res.status(403).json({ error: 'Permission denied' });
        }

        const { id } = req.params;
        await pool.query('DELETE FROM notes WHERE id = ?', [id]);
        logger.info(`Note ${id} deleted by ${req.session.user.email}`, { ip, user: req.session.user.email });
        res.json({ success: true });
    } catch (err) {
        logger.error(`Delete error: ${err.message}`, { ip });
        res.status(500).json({ error: 'Delete failed' });
    }
});

// Admin Site: Get options
router.get('/admin/options', async (req, res) => {
    const ip = getClientIp(req);
    if (!req.session.user) {
        securityLogger.warn(`Unauthorized options access`, { ip });
        return res.status(401).json({ error: 'Unauthorized' });
    }

    try {
        const [options] = await pool.query('SELECT * FROM options');
        logger.info(`Options fetched by ${req.session.user.email}`, { ip, user: req.session.user.email });
        res.json(options);
    } catch (err) {
        logger.error(`Options fetch error: ${err.message}`, { ip });
        res.status(500).json({ error: 'Fetch failed' });
    }
});

// Admin Site: Add option
router.post('/admin/add-option', async (req, res) => {
    const ip = getClientIp(req);
    if (!req.session.user) {
        securityLogger.warn(`Unauthorized option add`, { ip });
        return res.status(401).json({ error: 'Unauthorized' });
    }

    const { type, value } = req.body;
    try {
        await pool.query('INSERT INTO options (type, value) VALUES (?, ?)', [type, value]);
        logger.info(`Option ${type}:${value} added by ${req.session.user.email}`, { ip, user: req.session.user.email });
        res.json({ success: true });
    } catch (err) {
        logger.error(`Add option error: ${err.message}`, { ip });
        res.status(500).json({ error: 'Add failed' });
    }
});

// Admin Site: Get admin users
router.get('/admin/users', async (req, res) => {
    const ip = getClientIp(req);
    if (!req.session.user || req.session.user.role !== 'admin') {
        securityLogger.warn(`Unauthorized users access`, { ip });
        return res.status(403).json({ error: 'Permission denied' });
    }

    try {
        const [users] = await pool.query('SELECT id, email, role, force_2fa, totp_setup FROM admin_users');
        logger.info(`Users fetched by ${req.session.user.email}`, { ip, user: req.session.user.email });
        res.json(users);
    } catch (err) {
        logger.error(`Users fetch error: ${err.message}`, { ip });
        res.status(500).json({ error: 'Fetch failed' });
    }
});

// Admin Site: Update admin user
router.post('/admin/update-user', async (req, res) => {
    const ip = getClientIp(req);
    if (!req.session.user || req.session.user.role !== 'admin') {
        securityLogger.warn(`Unauthorized user update`, { ip });
        return res.status(403).json({ error: 'Permission denied' });
    }

    const { id, email, role, force_2fa } = req.body;
    try {
        await pool.query('UPDATE admin_users SET email = ?, role = ?, force_2fa = ? WHERE id = ?', [email, role, force_2fa === 'true', id]);
        logger.info(`User ${email} updated by ${req.session.user.email}`, { ip, user: req.session.user.email });
        res.json({ success: true });
    } catch (err) {
        logger.error(`Update user error: ${err.message}`, { ip });
        res.status(500).json({ error: 'Update failed' });
    }
});

// Admin Site: Get roles
router.get('/admin/roles', async (req, res) => {
    const ip = getClientIp(req);
    if (!req.session.user || req.session.user.role !== 'admin') {
        securityLogger.warn(`Unauthorized roles access`, { ip });
        return res.status(403).json({ error: 'Permission denied' });
    }

    try {
        const [roles] = await pool.query('SELECT * FROM roles');
        logger.info(`Roles fetched by ${req.session.user.email}`, { ip, user: req.session.user.email });
        res.json(roles);
    } catch (err) {
        logger.error(`Roles fetch error: ${err.message}`, { ip });
        res.status(500).json({ error: 'Fetch failed' });
    }
});

// Admin Site: Add role
router.post('/admin/add-role', async (req, res) => {
    const ip = getClientIp(req);
    if (!req.session.user || req.session.user.role !== 'admin') {
        securityLogger.warn(`Unauthorized role add`, { ip });
        return res.status(403).json({ error: 'Permission denied' });
    }

    const { name, can_view, can_delete } = req.body;
    try {
        await pool.query('INSERT INTO roles (name, can_view, can_delete) VALUES (?, ?, ?)', [name, can_view === 'true', can_delete === 'true']);
        logger.info(`Role ${name} added by ${req.session.user.email}`, { ip, user: req.session.user.email });
        res.json({ success: true });
    } catch (err) {
        logger.error(`Add role error: ${err.message}`, { ip });
        res.status(500).json({ error: 'Add failed' });
    }
});

// Admin Site: Update role
router.post('/admin/update-role', async (req, res) => {
    const ip = getClientIp(req);
    if (!req.session.user || req.session.user.role !== 'admin') {
        securityLogger.warn(`Unauthorized role update`, { ip });
        return res.status(403).json({ error: 'Permission denied' });
    }

    const { id, name, can_view, can_delete } = req.body;
    try {
        await pool.query('UPDATE roles SET name = ?, can_view = ?, can_delete = ? WHERE id = ?', [name, can_view === 'true', can_delete === 'true', id]);
        logger.info(`Role ${name} updated by ${req.session.user.email}`, { ip, user: req.session.user.email });
        res.json({ success: true });
    } catch (err) {
        logger.error(`Update role error: ${err.message}`, { ip });
        res.status(500).json({ error: 'Update failed' });
    }
});

// Admin Site: Get SMTP settings
router.get('/admin/smtp-settings', async (req, res) => {
    const ip = getClientIp(req);
    if (!req.session.user || req.session.user.role !== 'admin') {
        securityLogger.warn(`Unauthorized SMTP access`, { ip });
        return res.status(403).json({ error: 'Permission denied' });
    }

    try {
        const [settings] = await pool.query('SELECT * FROM smtp_settings LIMIT 1');
        logger.info(`SMTP settings fetched by ${req.session.user.email}`, { ip, user: req.session.user.email });
        res.json(settings[0] || {});
    } catch (err) {
        logger.error(`SMTP fetch error: ${err.message}`, { ip });
        res.status(500).json({ error: 'Fetch failed' });
    }
});

// Admin Site: Update SMTP settings
router.post('/admin/smtp-settings', async (req, res) => {
    const ip = getClientIp(req);
    if (!req.session.user || req.session.user.role !== 'admin') {
        securityLogger.warn(`Unauthorized SMTP update`, { ip });
        return res.status(403).json({ error: 'Permission denied' });
    }

    const { host, port, username, password, from_email } = req.body;
    try {
        const [existing] = await pool.query('SELECT COUNT(*) as count FROM smtp_settings');
        if (existing[0].count > 0) {
            await pool.query('UPDATE smtp_settings SET host = ?, port = ?, username = ?, password = ?, from_email = ? WHERE id = 1', [host, port, username, password, from_email]);
        } else {
            await pool.query('INSERT INTO smtp_settings (host, port, username, password, from_email) VALUES (?, ?, ?, ?, ?)', [host, port, username, password, from_email]);
        }
        logger.info(`SMTP settings updated by ${req.session.user.email}`, { ip, user: req.session.user.email });
        res.json({ success: true });
    } catch (err) {
        logger.error(`SMTP update error: ${err.message}`, { ip });
        res.status(500).json({ error: 'Update failed' });
    }
});

// Admin Site: Logout
router.get('/admin/logout', (req, res) => {
    const ip = getClientIp(req);
    if (req.session.user) {
        logger.info(`Logout by ${req.session.user.email}`, { ip, user: req.session.user.email });
        req.session.destroy(err => {
            if (err) {
                logger.error(`Logout error: ${err.message}`, { ip });
                return res.status(500).send('Logout failed');
            }
            res.redirect('/admin');
        });
    } else {
        res.redirect('/admin');
    }
});

module.exports = router;