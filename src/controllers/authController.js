import jwt from "jsonwebtoken";
import User from "../models/User";
import sendEmail from "../utils/sendEmail";
import dotenv from 'dotenv';
import redisClient from "../config/redis";
import speakeasy from 'speakeasy';

dotenv.config();

const generateToken = (id) => {
    return jwt.sign({ id }, process.env.JWT_SECRET, {
        expiresIn: process.env.JWT_EXPIRES_IN,
    });
}

export const register = async (req, res) => {
    const {name, email, password} = req.body;

    try {
        const userExists = await User.findOne({email});

        if (userExists){
            return res.status(400).json({message: "User already exists."})
        }

        const user = await User.create({name, email, password});

        const token = generateToken(user._id);

        const verificationLink = `http://localhost:${process.env.PORT}/api/auth/verify/${token}`;

        await sendEmail({
            email: user.email,
            subject: "Account Verification",
            text: `Please verify your email by clicking the following link: ${verificationLink}`,
        })

        res.status(201).json({message: "User registerd. Please verify your email"});
    } catch (error) {
        res.status(500).json({message: 'server error'})
    }
};

export const verifyEmail = async (req , res) => {
    const {token} = req.params;

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(decoded.id);

        if (!user){
            return res.status(400).json({message:"Invalid token"})
        }

        user.isVerified = true;
        await user.save();

        res.status(200).json({message:"Account verified successfully"});
    } catch (error) {
        res.status(500).json({message:"Server error"});
    }
};

export const login = async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: "Email and password are required." });
    }

    try {
        let user;

        // Attempt to get the user from the cache
        try {
            const cachedUser = await redisClient.get(email);
            if (cachedUser) {
                user = new User(JSON.parse(cachedUser));
            }
        } catch (err) {
            console.error('Error fetching from Redis:', err);
            return res.status(500).json({ message: "Server error." });
        }

        // If the user is not in the cache, query the database
        if (!user) {
            try {
                user = await User.findOne({ email });
                if (user) {
                    await redisClient.set(email, JSON.stringify(user));
                }
            } catch (err) {
                console.error('Error querying database:', err);
                return res.status(500).json({ message: "Server error." });
            }
        }

        // Validate the user and password
        if (!user || !(await user.matchPassword(password))) {
            return res.status(401).json({ message: "Invalid email or password." });
        }

        // Check if the user is verified
        if (!user.isVerified) {
            return res.status(400).json({ message: "Account not verified." });
        }

        // Generate the OTP
        const otp = speakeasy.totp({
            secret: user._id.toString(),
            encoding: 'base32'
        });

        // Send the OTP to the user's email
        try {
            await sendEmail({
                email: user.email,
                subject: "OTP for login",
                text: `Use the following OTP: ${otp}`
            });
        } catch (err) {
            console.error('Error sending email:', err);
            return res.status(500).json({ message: "Server error." });
        }

        res.status(200).json({ message: "OTP sent to email" });
    } catch (error) {
        console.error('Unexpected server error:', error);
        res.status(500).json({ message: "Server error." });
    }
}

export const verifyOTP = async (req, res) => {
    const {email, otp} = req.body;

    try {
        const user = await User.findOne({email});

        if (!user){
            return res.status(400).json({message: "Invalid email"});
        }

        const isValid = speakeasy.totp.verify({
            secret: user._id.toString(),
            encoding: 'base32',
            token: otp,
            window: 1
        });

        if(!isValid){
            return res.status(400).json({message: "Invalid OTP"});
        }

        const token = generateToken(user._id);

        res.status(200).json(token);
    } catch (error) {
        res.status(500).json({message: 'Server error'});
    }
}

export const forgotPassword = async (req, res) => {
    const {email} = req.body;

    try {
        const user = await User.findOne({email});

        if(!user){
            return res.status(400).json({message: "User not found"});
        }

        const resetToken = generateToken(user._id, '10m');

        const resetLink = `http://localhost:${process.env.PORT}/api/auth/reset-password/${resetToken}`;

        await sendEmail({
            to: user.email,
            subject: 'Reset Password',
            text:  `You are receiving this email because you (or someone else) has requested the reset of the password for your account. Please click on the following link, or paste this into your browser to complete the process: ${resetLink}`,
        });

        res.status(200).json({message: 'Password reset link sent to your email'});
    } catch (error) {
        res.status(500).json({message: "Server error"})
    }
}

export const resetPassword = async(req, res) => {
    const { token } = req.params;
    const { newPassword} = req.params;

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(decoded.id);

        if(!user){
            return res.status(404).json({message: "User not found"});
        }

        user.password = newPassword;
        await user.save();

        res.status(200).json({message: "Password reset successfully"});
    } catch (error) {
        console.log(error);
        res.status(500).json({message: "Server error"});
    }
}

export const refreshToken = async (req, res) => {
    const { refreshToken } = req.body.refreshToken;

    if(!refreshToken){
        return res.status(400).json({message: "Refresh token is required"});
    }

    try {
        const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
        
        const accessToken = generateAccessToken(decoded.id);
        res.status(200).json({accessToken});
    } catch (error) {
        console.log(error);
        res.status(500).json({message: "Server error"});
    }

}

export const deleteAccount = async(req, res) => {
    const userId = req.user._id;

    try {
        await User.findByIdAndDelete(userId);
        res.status(200).json({message: "Account deleted successfully"});
    } catch (error) {
        console.log(error);
        res.status(500).json({message: "Server error"});
    }
}