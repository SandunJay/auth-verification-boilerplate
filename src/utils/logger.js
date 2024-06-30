import winston from 'winston';

const logger = winston.createLogger({
    transports:[
        new winston.transports.Console(),
        new winston.transports.File({ filename: process.env.LOG_PATH })
    ],
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
    )
});

export default logger;