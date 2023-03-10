import express from 'express';
import { auth } from '../middlewares/auth';
import {
  registerUser,
  logUserIn,
  generate2FAKey,
  verify2FA,
  send2FAVerificationEmail,
  disable2FA,
} from '../controllers/user.controller';

export const router = express.Router();

router.post('/api/register', registerUser);
router.post('/api/login', logUserIn);
router.post('/api/2fa/generate', auth, generate2FAKey);
router.post('/api/2fa/verify', auth, verify2FA);
router.post('/api/2fa/send-email', auth, send2FAVerificationEmail);
router.post('/api/2fa/disable', auth, disable2FA);
