import jwt from "jsonwebtoken";
import User from "../models/User";
import sendEmail from "../utils/sendEmail";
import dotenv from 'dotenv';
import redisClient from "../config/redis";

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
    const {email, password} = req.body;

    try {
        const cachedUser = await redisClient.get(email);
        let user;

        if (cachedUser){
            user = JSON.parse(cachedUser);
        }else{
            user = await User.findOne({email});
            if(user){
                await redisClient.set(email, JSON.stringify(user));
            }
        }

        if (!user || !(await user.matchPassword(password))){
            return res.status(401).json({message:"Invalid email or password"});
        }

        if(!user.isVerified){
            return res.status(400).json({message: "Account not verified"});
        }

        const token = generateToken(user._id);

        res.status(200).json({token});
    } catch (error) {
        res.status(500).json({message:"Server error"});
    }
}