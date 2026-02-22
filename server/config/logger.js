const winston = require('winston');

const { combine, timestamp, errors, json, colorize, printf } = winston.format;

// Custom dev format: colorized + readable
const devFormat = combine(
    colorize(),
    timestamp({ format: 'HH:mm:ss' }),
    errors({ stack: true }),
    printf(({ level, message, timestamp, stack, ...meta }) => {
        let log = `${timestamp} ${level}: ${message}`;
        if (stack) log += `\n${stack}`;
        if (Object.keys(meta).length > 0) {
            log += ` ${JSON.stringify(meta)}`;
        }
        return log;
    })
);

// Production format: structured JSON
const prodFormat = combine(
    timestamp(),
    errors({ stack: true }),
    json()
);

const logger = winston.createLogger({
    level: process.env.LOG_LEVEL || (process.env.NODE_ENV === 'production' ? 'info' : 'debug'),
    format: process.env.NODE_ENV === 'production' ? prodFormat : devFormat,
    defaultMeta: { service: 'trustmarket-api' },
    transports: [
        new winston.transports.Console()
    ]
});

// Add file transports in production
if (process.env.NODE_ENV === 'production') {
    logger.add(new winston.transports.File({
        filename: 'logs/error.log',
        level: 'error',
        maxsize: 5 * 1024 * 1024, // 5MB
        maxFiles: 5
    }));

    logger.add(new winston.transports.File({
        filename: 'logs/combined.log',
        maxsize: 10 * 1024 * 1024, // 10MB
        maxFiles: 5
    }));
}

// Morgan stream for HTTP request logging
logger.stream = {
    write: (message) => {
        logger.http(message.trim());
    }
};

module.exports = logger;
