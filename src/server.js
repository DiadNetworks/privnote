// src/server.js
const express = require('express');
const session = require('express-session');
const routes = require('./routes');
require('dotenv').config();

const app = express();

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(
    session({
        secret: process.env.SESSION_SECRET,
        resave: false,
        saveUninitialized: false,
        cookie: { secure: false }, // Set to true if using HTTPS
    })
);

// Routes
app.use('/', routes);

// Clean up old notes (run every hour)
const cleanUpNotes = async () => {
    const pool = require('./db');
    await pool.query(
        'DELETE FROM notes WHERE created_at < DATE_SUB(NOW(), INTERVAL 24 HOUR)'
    );
};
setInterval(cleanUpNotes, 60 * 60 * 1000); // Run every hour

// Start server
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
