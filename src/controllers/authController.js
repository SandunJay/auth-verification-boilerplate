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
    // const {email, password} = req.body;

    // try {
    //     const cachedUser = await redisClient.get(email);
    //     let user;

    //     if (cachedUser){
    //         user = JSON.parse(cachedUser);
    //     }else{
    //         user = await User.findOne({email});
    //         if(user){
    //             await redisClient.set(email, JSON.stringify(user));
    //         }
    //     }

    //     if (!user || !(await user.matchPassword(password))){
    //         return res.status(401).json({message:"Invalid email or password"});
    //     }

    //     if(!user.isVerified){
    //         return res.status(400).json({message: "Account not verified"});
    //     }

    //     // const token = generateToken(user._id);

    //     const otp = speakeasy.totp({
    //         secret: user._id.toString(),
    //         encoding: 'base32'
    //     });

    //     await sendEmail({
    //         to: email,
    //         subject: "OTP for login",
    //         text: `Use below OTP ${otp}`
    //     });

    //     res.status(200).json({message: "OTP sent to email"});
    // } catch (error) {
    //     res.status(500).json({message:"Server error"});
    // }
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