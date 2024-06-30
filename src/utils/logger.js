import winston from 'winston';

const logger = winston.createLogger({
    transports:[
        new winston.transports.Console(),
        new winston.transports.File({__filename: 'combined.log'})
    ],
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
    )
});

export default logger;