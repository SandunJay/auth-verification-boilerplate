import { Router } from 'express';
import { register, verifyEmail, login, verifyOTP, forgotPassword, resetPassword, refreshToken, deleteAccount } from '../controllers/authController';
import passport from 'passport';


const router = Router();

router.post('/register', register);
router.get('/verify/:token', verifyEmail);
router.post('/login', login);
router.post('/otp', verifyOTP);
router.post('/forgot', forgotPassword);
router.post('/reset', resetPassword);
router.post('/refresh', refreshToken);
router.delete('/delete', passport.authenticate('jwt', {session: false}), deleteAccount);

router.get('/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
router.get('/google/callback', passport.authenticate('google', { failureRedirect: '/' }), (req, res) => {
  const token = generateToken(req.user._id);
  res.redirect(`/auth-success?token=${token}`);
});

export default router;
