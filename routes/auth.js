const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const pool = require('../db');
const router = express.Router();

router.get('/register', (req, res) => res.render('register'));
router.post('/register', async (req, res) => {
    const { username, email, password } = req.body;

    if (!email.match(/^[^@\s]+@[^@\s]+\.[^@\s]+$/)) return res.send('Invalid email');
    if (password.length < 8) return res.send('Password must be at least 8 characters');

    const userExists = await pool.query(
        'SELECT * FROM users WHERE email=$1 OR username=$2',
        [email, username]
    );
    if (userExists.rows.length > 0) return res.send('Username or Email already exists');

    const hashedPassword = await bcrypt.hash(password, 10);

    await pool.query(
        'INSERT INTO users (username, email, password, created_at) VALUES ($1, $2, $3, NOW())',
        [username, email, hashedPassword]
    );

    res.send('Registration successful. Please <a href="/login">log in</a>.');
});

router.get('/login', (req, res) => res.render('login'));

router.post('/login', async (req, res) => {
    const { username, password, token } = req.body;
  
    try {
      // Verify reCAPTCHA
      const captchaRes = await axios.post(
        `https://www.google.com/recaptcha/api/siteverify`,
        new URLSearchParams({
          secret: process.env.RECAPTCHA_SECRET_KEY,
          response: token,
        })
      );
  
      const captchaData = captchaRes.data;
  
      if (!captchaData.success || captchaData.score < 0.5) {
        return res.render('login', { errorMessage: 'Failed reCAPTCHA verification.' });
      }
  
      // Lookup user
      const userRes = await pool.query(
        'SELECT * FROM users WHERE username=$1 OR email=$1',
        [username]
      );
  
      const user = userRes.rows[0];
      if (!user) return res.render('login', { errorMessage: 'User not found.' });
  
      // Check password
      const isValidPassword = await bcrypt.compare(password, user.password);
      if (!isValidPassword) return res.render('login', { errorMessage: 'Incorrect password.' });
  
      // Sign JWT and send cookie
      const jwtToken = jwt.sign(
        { id: user.id, username: user.username, email: user.email },
        process.env.JWT_SECRET,
        { expiresIn: '15m' }
      );
  
      res.cookie('token', jwtToken, {
        httpOnly: true,
        sameSite: 'strict',
        secure: process.env.NODE_ENV === 'production',
      });
  
      res.redirect('/profile');
  
    } catch (err) {
      console.error('Login error:', err.message);
      res.render('login', { errorMessage: 'Internal Server Error' });
    }
  });
  

router.get('/profile', async (req, res) => {
    const token = req.cookies.token;
    if (!token) return res.redirect('/login?error=notoken');

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const result = await pool.query('SELECT id, username, email, created_at FROM users WHERE id=$1', [decoded.id]);
        res.render('profile', { user: result.rows[0] });
    } catch (err) {
        res.redirect('/login?error=expired');
    }
});

router.get('/logout', (req, res) => {
    res.clearCookie('token');
    res.redirect('/login');
});

module.exports = router;
