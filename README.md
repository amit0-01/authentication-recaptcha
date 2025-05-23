# Node.js Authentication System with Google reCAPTCHA v3

This is a simple user authentication system built with **Node.js**, **Express.js**, **PostgreSQL**, and **EJS**. It includes login and registration functionality, password hashing using bcrypt, JWT-based authentication, and protection with **Google reCAPTCHA v3**.

## Features

- User Registration & Login
- Password hashing with bcrypt
- JWT-based session handling (via cookies)
- Google reCAPTCHA v3 integration for bot protection
- Form validation (frontend and backend)
- Styled using Tailwind CSS
- EJS template engine for rendering pages

---

## Technologies Used

- Node.js
- Express.js
- PostgreSQL (with `pg` and `pg-pool`)
- EJS
- bcrypt
- jsonwebtoken
- axios (for reCAPTCHA validation)
- Tailwind CSS

---

## Setup Instructions

### 1. Clone the repository

```bash
git clone https://github.com/your-username/node-auth-recaptcha.git
cd node-auth-recaptcha


Install dependencies

npm install


Create PostgreSQL Database
Create a new database (e.g., auth_system)

Create a users table:

CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  username VARCHAR(100) NOT NULL,
  email VARCHAR(100) NOT NULL UNIQUE,
  password VARCHAR(255) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

Configure Environment Variables
Create a .env file in the root folder and add

DATABASE_URL=postgres://username:password@localhost:5432/auth_system
JWT_SECRET=your_jwt_secret_key
RECAPTCHA_SECRET_KEY=your_recaptcha_secret_key

Run the server

node server.js:

Server will run at: http://localhost:3000
