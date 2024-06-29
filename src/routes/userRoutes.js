import express from 'express';
import { protect } from '../middleware/authMiddleware';
import { getProfile } from '../controllers/userController';

const router = express.Router();

router.get('/profile', protect, getProfile);

export default router;