import jwt from "jsonwebtoken";
import User from "../models/User";
import Token from "../models/Token";
import sendEmail from "../utils/sendEmail";
import dotenv from 'dotenv';
import redisClient from "../config/redis";
import speakeasy from 'speakeasy';
import logger from "../utils/logger";
import { validationResult } from "express-validator";

dotenv.config();

const generateToken = (id, secret, expiresIn) => {
    return jwt.sign({ id }, secret, { expiresIn });
}

const createToken = async (userId, type, secret, expiresIn) => {
    const token = generateToken(userId, secret, expiresIn);
    const expiresAt = new Date(Date.now() + parseInt(expiresIn) * 1000);
    await Token.create({ userId, token, type, expiresAt });
    return token;
}

export const register = async (req, res) => {

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        logger.warn(`Validation errors: ${JSON.stringify(errors.array())}`);
        return res.status(400).json({ errors: errors.array() });
    }

    const {name, email, password} = req.body;

    try {
        const userExists = await User.findOne({email});

        if (userExists){
            logger.warn(`Registration attempt failed - User ${email} already exists.`);
            return res.status(400).json({message: "User already exists."})
        }

        const user = await User.create({name, email, password});

        const token = await createToken(user._id, 'verification', process.env.JWT_SECRET, process.env.JWT_EXPIRES_IN);

        const verificationLink = `http://localhost:${process.env.PORT}/api/auth/verify/${token}`;

        await sendEmail({
            email: user.email,
            subject: "Account Verification",
            text: `Please verify your email by clicking the following link: ${verificationLink}`,
        })

        logger.info(`User ${email} registered successfully.`);
        res.status(201).json({message: "User registerd. Please verify your email"});
    } catch (error) {
        logger.error('Error during registration:', error);
        res.status(500).json({message: 'server error'})
    }
};

export const verifyEmail = async (req , res) => {
    const {token} = req.params;

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(decoded.id);

        if (!user){
            logger.warn(`Verification attempt failed - Invalid token ${token}.`);
            return res.status(400).json({message:"Invalid token"})
        }

        const storedToken = await Token.findOne({ userId: decoded.id, token, type: 'verification' });
        if (!storedToken || storedToken.revoked) {
            logger.warn(`Verification attempt failed - Token not found or revoked for user ${user.email}.`);
            return res.status(400).json({ message: "Invalid or expired token" });
        }

        user.isVerified = true;
        await user.save();

        storedToken.revoked = true;
        await storedToken.save();

        logger.info(`User ${user.email} account verified successfully.`);
        res.status(200).json({message:"Account verified successfully"});
    } catch (error) {
        logger.error('Error in verifyEmail:', error);
        res.status(500).json({message:"Server error"});
    }
};

export const login = async (req, res) => {
    const error = validationResult(req);
    if (!error.isEmpty()) {
        logger.warn(`Validation errors: ${JSON.stringify(error.array())}`);
        return res.status(400).json({ errors: error.array() });
    }

    const { email, password } = req.body;

    if (!email || !password) {
        logger.warn(`User ${email} attempted to log in (Email or passowrd not available).`);
        return res.status(400).json({ message: "Email and password are required." });
    }

    try {
        let user;

        try {
            const cachedUser = await redisClient.get(email);
            if (cachedUser) {
                user = new User(JSON.parse(cachedUser));
            }else{
                logger.warn(`User ${email} attempted to log in (User not found in redis).`)
            }
        } catch (err) {
            logger.error('Error fetching from Redis:', err);
            return res.status(500).json({ message: "Server error." });
        }

        if (!user) {
            try {
                user = await User.findOne({ email });
                if (!user) {
                    logger.warn(`User ${email} attempted to log in (User not found ).`)
                }
            } catch (err) {
                logger.error('Error querying database:', err);
                return res.status(500).json({ message: "Server error." });
            }
        }

        if (!user || !(await user.matchPassword(password))) {
            logger.warn(`Login attempt failed - Invalid email or password for ${email}.`);
            return res.status(401).json({ message: "Invalid email or password." });
        }

        if (!user.isVerified) {
            logger.warn(`Login attempt failed - Account not verified for ${email}.`);           
            return res.status(400).json({ message: "Account not verified." });
        }

        const otp = speakeasy.totp({
            secret: user._id.toString(),
            encoding: 'base32'
        });

        logger.info(`Generated OTP for ${email}: ${otp}`);


        try {
            await sendEmail({
                email: user.email,
                subject: "OTP for login",
                text: `Use the following OTP: ${otp}`
            });

            logger.info(`OTP sent to ${email}.`);
            res.status(200).json({ message: "OTP sent to email" });
        } catch (err) {
            logger.error('Error sending email:', err);
            return res.status(500).json({ message: "Server error." });
        }

    } catch (error) {
        logger.error('Unexpected server error:', error);
        res.status(500).json({ message: "Server error." });
    }
}

export const verifyOTP = async (req, res) => {
    const {email, otp} = req.body;

    try {
        const user = await User.findOne({email});

        if (!user){
            logger.warn(`OTP verification failed - User not found for ${email}.`);
            return res.status(400).json({message: "Invalid email"});
        }

        const isValid = speakeasy.totp.verify({
            secret: user._id.toString(),
            encoding: 'base32',
            token: otp,
            window: 1 
        });

        if(!isValid){
            logger.warn(`OTP verification failed - Invalid OTP for ${email}.`);
            return res.status(400).json({message: "Invalid OTP"});
        }

        const accessToken = await createToken(user._id, 'access', process.env.JWT_SECRET, process.env.JWT_EXPIRES_IN);
        const refreshToken = await createToken(user._id, 'refresh', process.env.JWT_REFRESH_SECRET, process.env.JWT_REFRESH_EXPIRES_IN);

        await redisClient.set(email, JSON.stringify(user), 'EX', process.env.JWT_EXPIRES_IN); // Set user data in Redis with expiration
        await redisClient.set(`accessToken:${user._id}`, accessToken, 'EX', process.env.JWT_EXPIRES_IN); // Set access token in Redis with expiration
        await redisClient.set(`refreshToken:${user._id}`, refreshToken, 'EX', process.env.JWT_REFRESH_EXPIRES_IN); // Set refresh token in Redis with expiration

        logger.info(`User ${email} logged in successfully.`);
        res.status(200).json({AccessToken: accessToken, RefreshToken: refreshToken});
    } catch (error) {
        logger.error('Error in verifyOTP:', error);
        res.status(500).json({message: 'Server error'});
    }
}

export const forgotPassword = async (req, res) => {
    try {
        const user = req.user;

        if(!user){
            logger.warn(`Forgot password attempt failed - User not found for ${user.email}.`);
            return res.status(400).json({message: "User not found"});
        }

        const expiresAt = new Date();
        expiresAt.setMinutes(expiresAt.getMinutes() + parseInt(process.env.JWT_EXPIRES_IN));

        const resetToken = createToken(user._id ,"verification", process.env.JWT_SECRET, expiresAt);
        const resetLink = `http://localhost:${process.env.PORT}/api/auth/reset-password/${resetToken}`;
        const email = user.email;

        await sendEmail({
            email: email,
            subject: 'Reset Password',
            text:  `You are receiving this email because you (or someone else) has requested the reset of the password for your account. Please click on the following link, or paste this into your browser to complete the process: ${resetLink}`,
        });

        logger.info(`Password reset link sent to ${email}.`);
        res.status(200).json({message: 'Password reset link sent to your email'});
    } catch (error) {
        logger.error('Error in forgotPassword:', error);
        res.status(500).json({message: "Server error"})
    }
}

export const resetPassword = async(req, res) => {
    const { token } = req.params;
    const { newPassword} = req.body;

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(decoded.id);

        if(!user){
            logger.warn(`Password reset attempt failed - User not found for token ${token}.`);
            return res.status(404).json({message: "User not found"});
        }

        user.password = newPassword;
        await user.save();

        await Token.updateMany({ userId: user._id }, { revoked: true });
        await redisClient.del(user.email);
        await redisClient.del(`accessToken:${user._id}`);
        await redisClient.del(`refreshToken:${user._id}`);

        logger.info(`Password reset successfully for user ${user.email}.`);
        res.status(200).json({message: "Password reset successfully"});
    } catch (error) {
        console.log(error);
        res.status(500).json({message: "Server error"});
    }
}

export const refreshToken = async (req, res) => {
    const { refreshToken } = req.body;

    if(!refreshToken){
        logger.warn(`Refresh token request failed - Refresh token is required.`);
        return res.status(400).json({message: "Refresh token is required"});
    }

    try {
        const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);

        const storedRefreshToken = await Token.findOne({ userId: decoded.id, token: refreshToken, type: 'refresh' });
        if (!storedRefreshToken || storedRefreshToken.revoked) {
            logger.warn(`Refresh token invalid for user ${decoded.id}.`);
            return res.status(401).json({ message: "Invalid refresh token." });
        }

        await Token.updateMany({ userId: decoded.id, type: 'access' }, { revoked: true });
        await redisClient.del(`accessToken:${decoded.id}`);

        const accessToken = await createToken(decoded.id, 'access', process.env.JWT_SECRET, process.env.JWT_EXPIRES_IN);
        await redisClient.set(`accessToken:${decoded.id}`, accessToken, 'EX', process.env.JWT_EXPIRES_IN);

        logger.info(`Access token refreshed successfully.`);
        res.status(200).json({accessToken});
    } catch (error) {
        logger.error('Error in refreshToken:', error);
        res.status(500).json({message: "Server error"});
    }

}

export const deleteAccount = async(req, res) => {
    const userId = req.user._id;

    try {
        await User.findByIdAndDelete(userId);
        await Token.deleteMany({ userId });
        await redisClient.del(req.user.email);
        await redisClient.del(`accessToken:${userId}`);
        await redisClient.del(`refreshToken:${userId}`);

        logger.info(`Account deleted successfully for user ${req.user.email}.`);
        res.status(200).json({message: "Account deleted successfully"});
    } catch (error) {
        logger.error('Error in deleteAccount:', error);
        res.status(500).json({message: "Server error"});
    }
}