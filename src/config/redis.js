import { createClient } from "redis";
import dotenv from 'dotenv';

dotenv.config();

const redisClient = createClient({
    url: process.env.REDIS_URL || 'redis://localhost:6379'
})

redisClient.on('error', (err)=> console.log('Redis client error', err));

redisClient.connect();

export default redisClient;