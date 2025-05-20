const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const path = require('path');
const authRoutes = require('./routes/auth.js');

dotenv.config();

const app = express();

app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static('public'));
app.set('view engine', 'ejs');

// app.get('/', (req, res) => {
//     res.redirect('/login');  
//   });
  
app.use('/', authRoutes);

app.listen(3000, () => console.log('Server running on port 3000'));
