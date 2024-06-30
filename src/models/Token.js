import mongoose from "mongoose";

const tokenShema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        required: true,
        ref: 'User'
    },
    token: {
        type: String,
        required: true
    },
    type: {
        type: String,
        enum: ['access', 'refresh', 'verification'],
        required: true
    },
    expiresAt: {
        type: Date,
        required: true
    },
    revoked: {
        type: Boolean,
        default: false
    }
},{timestamps: true});

const Token = mongoose.model('Token', tokenShema);

export default Token;