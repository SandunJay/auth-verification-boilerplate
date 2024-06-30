import jwt from 'jsonwebtoken';
import User from '../models/User';
import dotenv from 'dotenv';
import logger from '../utils/logger';
import Token from '../models/Token';

dotenv.config();

export const protect = async(req, res, next) => {
    let token;

    if(
        req.headers.authorization &&
        req.headers.authorization.startsWith('Bearer')
    ){
        try {
            token = req.headers.authorization.split(' ')[1];
            const decoded = jwt.verify(token, process.env.JWT_SECRET);

            const storedToken = await Token.findOne({ token });
            if (!storedToken || storedToken.revoked) {
                logger.error(`Access token ${token} is revoked or expired`)
                return res.status(401).json({ message: 'Unauthorized - Access token is revoked or expired.' });
            }

            req.user = await User.findById(decoded.id).select('-password');
            next();
        } catch (error) {
            logger.error("Not authorized. Token failed")
            res.status(401).json({message: "Not authorized. Token failed"})
        }
    }

    if(!token){
        logger.error("No token available")
        res.status(401).json({message: "No token available"});
    }
}