const winston = require('winston');
const path = require('path');
const { format } = winston;
const DailyRotateFile = require('winston-daily-rotate-file');

// Define custom log format
const logFormat = format.combine(
    format.timestamp(),
    format.printf(({ timestamp, level, message }) => {
        return `${timestamp} [${level}]: ${message}`;
    })
);

// Create the logger
const logger = winston.createLogger({
    level: 'info', // Default log level
    format: logFormat,
    transports: [
        // Console transport with colored output (for development)
        new winston.transports.Console({
            format: format.combine(
                format.colorize(),
                format.simple()
            ),
        }),
        // File transport for error logs
        new DailyRotateFile({
            filename: path.join(__dirname, 'logs/error-%DATE%.log'),
            level: 'error',
            format: format.json(),
            datePattern: 'YYYY-MM-DD',
            maxFiles: '14d',  // Retain error logs for 14 days
        }),
        // File transport for combined logs (all log levels)
        new DailyRotateFile({
            filename: path.join(__dirname, 'logs/combined-%DATE%.log'),
            format: format.json(),
            datePattern: 'YYYY-MM-DD',
            maxFiles: '14d',
        }),
    ],
});

// Optional: Add console transport in non-production environments
if (process.env.NODE_ENV !== 'production') {
    logger.add(new winston.transports.Console({
        format: format.combine(
            format.colorize(),
            format.simple()
        ),
    }));
}

// Error logging function with enhanced context
const logError = (error, req, additionalInfo = '') => {
    logger.error(`Error occurred during ${req.method} ${req.url}`);
    logger.error(`Request Body: ${JSON.stringify(req.body, null, 2)}`);
    logger.error(`Request Params: ${JSON.stringify(req.params, null, 2)}`);
    logger.error(`Request Query: ${JSON.stringify(req.query, null, 2)}`);
    logger.error(`Client IP: ${req.ip}`);
    logger.error(`User-Agent: ${req.headers['user-agent']}`);
    if (additionalInfo) {
        logger.error(`Additional Info: ${additionalInfo}`);
    }
    logger.error(`Error Message: ${error.message}`);
    logger.error(`Stack Trace: ${error.stack}`);
};

// Function to log warnings
const logWarning = (message) => {
    logger.warn(message);
};

// Function to log info messages
const logInfo = (message) => {
    logger.info(message);
};

// Function to log debug messages
const logDebug = (message) => {
    logger.debug(message);
};

// Export logger and log functions
module.exports = { logger, logError, logWarning, logInfo, logDebug };