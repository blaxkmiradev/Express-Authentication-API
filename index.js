require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { getDb } = require('./src/database');

const authRoutes = require('./src/routes/auth');
const usersRoutes = require('./src/routes/users');

const app = express();
const PORT = process.env.PORT || 3000;

// ─── Security Middleware ──────────────────────────────────────────────────────
app.use(helmet());
app.use(cors({
  origin: process.env.CORS_ORIGIN || '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

// ─── Rate Limiting ────────────────────────────────────────────────────────────
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later' },
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10, // strict limit for auth routes
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many auth attempts, please try again in 15 minutes' },
});

app.use(globalLimiter);

// ─── Body Parsing ─────────────────────────────────────────────────────────────
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// ─── Health Check ─────────────────────────────────────────────────────────────
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    uptime: Math.floor(process.uptime()),
  });
});

// ─── API Info ─────────────────────────────────────────────────────────────────
app.get('/', (req, res) => {
  res.json({
    name: 'Express Auth API',
    version: '1.0.0',
    endpoints: {
      auth: {
        'POST /auth/register': 'Register a new user',
        'POST /auth/login': 'Login with email & password',
        'POST /auth/refresh': 'Refresh access token',
        'POST /auth/logout': 'Logout (invalidate refresh token)',
        'POST /auth/logout-all': 'Logout from all devices',
        'GET  /auth/me': 'Get current user profile',
        'PUT  /auth/change-password': 'Change password',
      },
      users: {
        'GET    /users': 'List all users [admin]',
        'GET    /users/:id': 'Get user by ID [admin|self]',
        'PUT    /users/:id/role': 'Update user role [admin]',
        'PUT    /users/:id/status': 'Activate/deactivate user [admin]',
        'DELETE /users/:id': 'Delete user [admin]',
      },
    },
  });
});

// ─── Routes ───────────────────────────────────────────────────────────────────
app.use('/auth', authLimiter, authRoutes);
app.use('/users', usersRoutes);

// ─── 404 Handler ──────────────────────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ error: `Route ${req.method} ${req.path} not found` });
});

// ─── Global Error Handler ─────────────────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// ─── Boot ─────────────────────────────────────────────────────────────────────
async function start() {
  await getDb(); // Initialize SQLite
  app.listen(PORT, () => {
    console.log(`\n🚀 Auth API running on http://localhost:${PORT}`);
    console.log(`📚 API docs at http://localhost:${PORT}/`);
    console.log(`❤️  Health check at http://localhost:${PORT}/health\n`);
  });
}

start().catch(err => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
