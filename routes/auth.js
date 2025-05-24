const express = require('express');
const router = express.Router();
const authController = require('../controllers/auth.controller');
const rateLimit = require('express-rate-limit');

// Rate limiter middleware
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: 'Too many login attempts from this IP, please try again after 15 minutes',
  standardHeaders: true,
  legacyHeaders: false,
});

// GET routes
router.get('/register', authController.getRegister);
router.get('/login', authController.getLogin);
router.get('/profile', authController.getProfile);
router.get('/logout', authController.logout);

// POST routes
router.post('/register', authController.postRegister);
router.post('/login', loginLimiter, authController.postLogin);

module.exports = router;
