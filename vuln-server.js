// secure-server.js
// Secure JWT server with environment config, claims, refresh tokens, and frontend compatibility

require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

// === ENV CONFIG ===
const PORT = process.env.PORT;
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET;
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN;
const JWT_REFRESH_EXPIRES_IN = process.env.JWT_REFRESH_EXPIRES_IN;
const JWT_ISSUER = process.env.JWT_ISSUER;
const JWT_AUDIENCE = process.env.JWT_AUDIENCE;
const JWT_ALGORITHM = process.env.JWT_ALGORITHM;

if (!JWT_SECRET || !JWT_REFRESH_SECRET) {
  console.error('❌ FATAL: Missing JWT_SECRET or JWT_REFRESH_SECRET in .env');
  process.exit(1);
}

const DB = new sqlite3.Database(DB_PATH);

// Temporary in-memory store for issued refresh tokens (demo only)
const refreshStore = {};

// === LOGIN ===
app.post('/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

  DB.get('SELECT * FROM users WHERE username = ?', [username], (err, row) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!row || !bcrypt.compareSync(password, row.password)) return res.status(401).json({ error: 'Invalid credentials' });

    // JWT payload + claims
    const payload = { sub: row.username, role: row.role };

    const accessToken = jwt.sign(payload, JWT_SECRET, {
      algorithm: JWT_ALGORITHM,
      expiresIn: JWT_EXPIRES_IN,
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE,
    });

    const refreshToken = jwt.sign({ sub: row.username }, JWT_REFRESH_SECRET, {
      algorithm: JWT_ALGORITHM,
      expiresIn: JWT_REFRESH_EXPIRES_IN,
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE,
    });

    // Save refresh token (in memory)
    refreshStore[refreshToken] = row.username;

    // Set tokens in HTTP-only cookies
    res.cookie('accessToken', accessToken, {
      httpOnly: true,
      secure: true, // Set to true in production (requires HTTPS)
      sameSite: 'Strict',
      maxAge: 15 * 60 * 1000, // 15 minutes
    });

    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: true, // Set to true in production (requires HTTPS)
      sameSite: 'Strict',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    res.json({ message: 'Login successful' });
  });
});

// === REFRESH TOKEN ENDPOINT ===
app.post('/refresh', (req, res) => {
  const refreshToken = req.cookies.refreshToken; // Retrieve from HTTP-only cookie
  if (!refreshToken) return res.status(400).json({ error: 'Missing refresh token' });

  try {
    const decoded = jwt.verify(refreshToken, JWT_REFRESH_SECRET, {
      algorithms: [JWT_ALGORITHM],
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE,
    });

    if (!refreshStore[refreshToken]) {
      return res.status(403).json({ error: 'Refresh token not recognized or revoked' });
    }

    const username = decoded.sub;

    const newAccessToken = jwt.sign({ sub: username, role: 'user' }, JWT_SECRET, {
      algorithm: JWT_ALGORITHM,
      expiresIn: JWT_EXPIRES_IN,
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE,
    });

    // Set new access token in HTTP-only cookie
    res.cookie('accessToken', newAccessToken, {
      httpOnly: true,
      secure: true, // Set to true in production (requires HTTPS)
      sameSite: 'Strict',
      maxAge: 15 * 60 * 1000, // 15 minutes
    });

    res.json({ message: 'Token refreshed successfully' });
  } catch (err) {
    res.status(401).json({ error: 'Invalid or expired refresh token' });
  }
});

// === LOGOUT (invalidate refresh token) ===
app.post('/logout', (req, res) => {
  const refreshToken = req.cookies.refreshToken; // Retrieve from HTTP-only cookie
  if (refreshToken && refreshStore[refreshToken]) {
    delete refreshStore[refreshToken];
  }

  // Clear cookies
  res.clearCookie('accessToken');
  res.clearCookie('refreshToken');

  res.json({ message: 'Logged out successfully' });
});

// === PROTECTED /ADMIN ===
app.get('/admin', (req, res) => {
  const auth = req.headers.authorization || '';
  const token = auth.replace(/^Bearer\s+/i, '').trim();
  if (!token) return res.status(401).json({ error: 'No token provided' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET, {
      algorithms: [JWT_ALGORITHM],
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE,
    });

    if (decoded.role === 'admin') {
      res.json({ secret: '🔥 VERY SENSITIVE ADMIN DATA 🔥' });
    } else {
      res.status(403).json({ error: 'Forbidden (not admin)' });
    }
  } catch (err) {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
});

// === WHOAMI ===
app.get('/whoami', (req, res) => {
  const auth = req.headers.authorization || '';
  const token = auth.replace(/^Bearer\s+/i, '').trim();
  if (!token) return res.json({ msg: 'no token' });

  try {
    const decoded = jwt.decode(token, { complete: true });
    res.json({ decoded });
  } catch {
    res.json({ error: 'Invalid token' });
  }
});


app.listen(PORT, () => {
  console.log(`✅ Secure server running on http://localhost:${PORT}`);
});
