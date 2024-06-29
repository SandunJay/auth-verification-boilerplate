import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import User from "../models/User";
import dotenv from 'dotenv';

dotenv.config();

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "/api/auth/google/callback"
}, async(accessToken, refreshToken, profile, done) => {
    const {id, displayName, emails} = profile;

    try {
        let user = await User.findOne({email: emails[0].value});

        if(!user){
            user = await User.create({
                googleId: id,
                name: displayName,
                email: emails[0].value,
                password: null,
                isVerified: true
            });
        }

        done(null, user);
    }catch(error){
        done(error, null)
    }
}));

passport.serializeUser((user, done) => {
    done(null, user.id);
})

passport.deserializeUser( async(id, done) => {
    try{
        const user = await User.findById(id);
        done(null, user);
    }catch(error){
        done(error, null);
    }
});

export default passport;