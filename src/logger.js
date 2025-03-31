// src/logger.js
const winston = require('winston');

// Define log format
const logFormat = winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    winston.format.printf(({ timestamp, level, message, ip, user }) => {
        return `${timestamp} [${level.toUpperCase()}] ${ip ? `IP=${ip}` : ''} ${user ? `User=${user}` : ''} ${message}`;
    })
);

// Create logger for general application logs
const logger = winston.createLogger({
    level: 'debug',
    format: logFormat,
    transports: [
        new winston.transports.File({ filename: '/var/www/privnote/logs/app.log' }),
        new winston.transports.Console(),
    ],
});

// Create logger for security events (for fail2ban)
const securityLogger = winston.createLogger({
    level: 'debug',
    format: logFormat,
    transports: [
        new winston.transports.File({ filename: '/var/www/privnote/logs/security.log' }),
        new winston.transports.Console(),
    ],
});

module.exports = { logger, securityLogger };
