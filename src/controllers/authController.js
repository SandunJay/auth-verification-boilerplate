import jwt from "jsonwebtoken";
import User from "../models/User";
import sendEmail from "../utils/sendEmail";
import dotenv from 'dotenv';
import redisClient from "../config/redis";
import speakeasy from 'speakeasy';
import logger from "../utils/logger";

dotenv.config();

const generateAccessToken = (id) => {
    return jwt.sign({ id }, process.env.JWT_SECRET, {
        expiresIn: process.env.JWT_EXPIRES_IN,
    });
}

const generateRefreshToken = (id) => {
    return jwt.sign({ id }, process.env.JWT_REFRESH_SECRET, { 
        expiresIn: process.env.JWT_REFRESH_EXPIRES_IN,
    });
}

export const register = async (req, res) => {
    const {name, email, password} = req.body;

    try {
        const userExists = await User.findOne({email});

        if (userExists){
            logger.warn(`Registration attempt failed - User ${email} already exists.`);
            return res.status(400).json({message: "User already exists."})
        }

        const user = await User.create({name, email, password});

        const token = generateAccessToken(user._id);

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

        user.isVerified = true;
        await user.save();

        logger.info(`User ${user.email} account verified successfully.`);
        res.status(200).json({message:"Account verified successfully"});
    } catch (error) {
        logger.error('Error in verifyEmail:', error);
        res.status(500).json({message:"Server error"});
    }
};

export const login = async (req, res) => {
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
            }
        } catch (err) {
            logger.error('Error fetching from Redis:', err);
            return res.status(500).json({ message: "Server error." });
        }

        if (!user) {
            try {
                user = await User.findOne({ email });
                if (user) {
                    await redisClient.set(email, JSON.stringify(user));
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

        const accessToken = generateAccessToken(user._id);
        const refreshToken = generateRefreshToken(user._id);

        logger.info(`User ${email} logged in successfully.`);
        res.status(200).json({AccessToken: accessToken, RefreshToken: refreshToken});
    } catch (error) {
        logger.error('Error in verifyOTP:', error);
        res.status(500).json({message: 'Server error'});
    }
}

export const forgotPassword = async (req, res) => {
    const {email} = req.body;

    try {
        const user = await User.findOne({email});

        if(!user){
            logger.warn(`Forgot password attempt failed - User not found for ${email}.`);
            return res.status(400).json({message: "User not found"});
        }

        const resetToken = generateAccessToken(user._id, '10m');

        const resetLink = `http://localhost:${process.env.PORT}/api/auth/reset-password/${resetToken}`;

        await sendEmail({
            to: user.email,
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
        
        const accessToken = generateAccessToken(decoded.id);
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
        logger.info(`Account deleted successfully for user ${req.user.email}.`);
        res.status(200).json({message: "Account deleted successfully"});
    } catch (error) {
        logger.error('Error in deleteAccount:', error);
        res.status(500).json({message: "Server error"});
    }
}