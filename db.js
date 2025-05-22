const { Pool } = require('pg');
const dotenv = require('dotenv');
dotenv.config();

const pool = new Pool({ connectionString: process.env.DB_URL });

pool.connect()
  .then(client => {
    console.log('✅ Database connected successfully.');
    client.release(); 
  })
  .catch(err => {
    console.error('❌ Database connection failed:', err.stack);
  });

module.exports = pool;
