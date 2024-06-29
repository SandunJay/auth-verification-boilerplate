import User from "../models/User";

export const getProfile = async(req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        res.status(200).json(user);
        
    } catch (error) {
        res.status(500).json({message: "Server error"})
    }
}