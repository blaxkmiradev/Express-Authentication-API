const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const { run, get, all } = require('../database');
const { authenticate } = require('../middleware/auth');
const { validateRegister, validateLogin } = require('../middleware/validate');

const router = express.Router();

// ─── Helper: generate tokens ──────────────────────────────────────────────────
function generateAccessToken(userId) {
  return jwt.sign({ userId, jti: uuidv4() }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN || '15m',
  });
}

function generateRefreshToken(userId) {
  return jwt.sign({ userId, jti: uuidv4() }, process.env.JWT_REFRESH_SECRET, {
    expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d',
  });
}

// ─── POST /auth/register ──────────────────────────────────────────────────────
/**
 * @route   POST /auth/register
 * @desc    Register a new user
 * @access  Public
 * @body    { username, email, password }
 */
router.post('/register', validateRegister, async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // Check for existing user
    const existingEmail = get('SELECT id FROM users WHERE email = ?', [email.toLowerCase()]);
    if (existingEmail) {
      return res.status(409).json({ error: 'Email already registered' });
    }

    const existingUsername = get('SELECT id FROM users WHERE username = ?', [username.toLowerCase()]);
    if (existingUsername) {
      return res.status(409).json({ error: 'Username already taken' });
    }

    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(password, salt);
    const userId = uuidv4();

    run(
      `INSERT INTO users (id, username, email, password_hash) VALUES (?, ?, ?, ?)`,
      [userId, username.toLowerCase(), email.toLowerCase(), passwordHash]
    );

    const accessToken = generateAccessToken(userId);
    const refreshToken = generateRefreshToken(userId);

    // Store refresh token
    const refreshId = uuidv4();
    const refreshExpiry = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
    run(
      `INSERT INTO refresh_tokens (id, user_id, token, expires_at) VALUES (?, ?, ?, ?)`,
      [refreshId, userId, refreshToken, refreshExpiry]
    );

    res.status(201).json({
      message: 'Registration successful',
      user: { id: userId, username: username.toLowerCase(), email: email.toLowerCase(), role: 'user' },
      tokens: { accessToken, refreshToken },
    });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ─── POST /auth/login ─────────────────────────────────────────────────────────
/**
 * @route   POST /auth/login
 * @desc    Login with email and password
 * @access  Public
 * @body    { email, password }
 */
router.post('/login', validateLogin, async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = get('SELECT * FROM users WHERE email = ?', [email.toLowerCase()]);
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    if (!user.is_active) {
      return res.status(403).json({ error: 'Account is deactivated' });
    }

    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const accessToken = generateAccessToken(user.id);
    const refreshToken = generateRefreshToken(user.id);

    // Store refresh token (clean old ones for this user first — keep last 5)
    const oldTokens = all('SELECT id FROM refresh_tokens WHERE user_id = ? ORDER BY created_at DESC', [user.id]);
    if (oldTokens.length >= 5) {
      const toDelete = oldTokens.slice(4).map(t => t.id);
      toDelete.forEach(id => run('DELETE FROM refresh_tokens WHERE id = ?', [id]));
    }

    const refreshId = uuidv4();
    const refreshExpiry = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
    run(
      `INSERT INTO refresh_tokens (id, user_id, token, expires_at) VALUES (?, ?, ?, ?)`,
      [refreshId, user.id, refreshToken, refreshExpiry]
    );

    res.json({
      message: 'Login successful',
      user: { id: user.id, username: user.username, email: user.email, role: user.role },
      tokens: { accessToken, refreshToken },
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ─── POST /auth/refresh ───────────────────────────────────────────────────────
/**
 * @route   POST /auth/refresh
 * @desc    Refresh access token using refresh token
 * @access  Public
 * @body    { refreshToken }
 */
router.post('/refresh', (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(400).json({ error: 'Refresh token required' });
  }

  try {
    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);

    const stored = get(
      `SELECT * FROM refresh_tokens WHERE token = ? AND user_id = ? AND expires_at > datetime('now')`,
      [refreshToken, decoded.userId]
    );

    if (!stored) {
      return res.status(401).json({ error: 'Invalid or expired refresh token' });
    }

    const user = get('SELECT * FROM users WHERE id = ? AND is_active = 1', [decoded.userId]);
    if (!user) {
      return res.status(401).json({ error: 'User not found or inactive' });
    }

    // Rotate refresh token
    run('DELETE FROM refresh_tokens WHERE id = ?', [stored.id]);
    const newAccessToken = generateAccessToken(user.id);
    const newRefreshToken = generateRefreshToken(user.id);

    const newRefreshId = uuidv4();
    const refreshExpiry = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
    run(
      `INSERT INTO refresh_tokens (id, user_id, token, expires_at) VALUES (?, ?, ?, ?)`,
      [newRefreshId, user.id, newRefreshToken, refreshExpiry]
    );

    res.json({
      message: 'Tokens refreshed',
      tokens: { accessToken: newAccessToken, refreshToken: newRefreshToken },
    });
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Refresh token expired, please log in again' });
    }
    return res.status(403).json({ error: 'Invalid refresh token' });
  }
});

// ─── POST /auth/logout ────────────────────────────────────────────────────────
/**
 * @route   POST /auth/logout
 * @desc    Logout and invalidate refresh token
 * @access  Private
 * @body    { refreshToken }
 */
router.post('/logout', authenticate, (req, res) => {
  const { refreshToken } = req.body;

  if (refreshToken) {
    run('DELETE FROM refresh_tokens WHERE token = ? AND user_id = ?', [refreshToken, req.user.id]);
  }

  res.json({ message: 'Logged out successfully' });
});

// ─── POST /auth/logout-all ────────────────────────────────────────────────────
/**
 * @route   POST /auth/logout-all
 * @desc    Logout from all devices
 * @access  Private
 */
router.post('/logout-all', authenticate, (req, res) => {
  run('DELETE FROM refresh_tokens WHERE user_id = ?', [req.user.id]);
  res.json({ message: 'Logged out from all devices' });
});

// ─── GET /auth/me ─────────────────────────────────────────────────────────────
/**
 * @route   GET /auth/me
 * @desc    Get current authenticated user's profile
 * @access  Private
 */
router.get('/me', authenticate, (req, res) => {
  const user = get(
    'SELECT id, username, email, role, is_active, created_at, updated_at FROM users WHERE id = ?',
    [req.user.id]
  );

  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  res.json({ user });
});

// ─── PUT /auth/change-password ────────────────────────────────────────────────
/**
 * @route   PUT /auth/change-password
 * @desc    Change authenticated user's password
 * @access  Private
 * @body    { currentPassword, newPassword }
 */
router.put('/change-password', authenticate, async (req, res) => {
  const { currentPassword, newPassword } = req.body;

  if (!currentPassword || !newPassword) {
    return res.status(400).json({ error: 'Current password and new password are required' });
  }

  if (newPassword.length < 8 || !/(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/.test(newPassword)) {
    return res.status(400).json({
      error: 'New password must be at least 8 characters with uppercase, lowercase, and number',
    });
  }

  try {
    const user = get('SELECT * FROM users WHERE id = ?', [req.user.id]);
    const isMatch = await bcrypt.compare(currentPassword, user.password_hash);
    if (!isMatch) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }

    const salt = await bcrypt.genSalt(12);
    const newHash = await bcrypt.hash(newPassword, salt);

    run(
      `UPDATE users SET password_hash = ?, updated_at = datetime('now') WHERE id = ?`,
      [newHash, req.user.id]
    );

    // Invalidate all refresh tokens
    run('DELETE FROM refresh_tokens WHERE user_id = ?', [req.user.id]);

    res.json({ message: 'Password changed successfully. Please log in again.' });
  } catch (err) {
    console.error('Change password error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;
