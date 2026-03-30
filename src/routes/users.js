const express = require('express');
const { get, all, run } = require('../database');
const { authenticate, authorize } = require('../middleware/auth');

const router = express.Router();

// All routes require authentication
router.use(authenticate);

// ─── GET /users ───────────────────────────────────────────────────────────────
/**
 * @route   GET /users
 * @desc    List all users (admin only)
 * @access  Admin
 */
router.get('/', authorize('admin'), (req, res) => {
  const { page = 1, limit = 20, search } = req.query;
  const offset = (parseInt(page) - 1) * parseInt(limit);

  let query = 'SELECT id, username, email, role, is_active, created_at FROM users';
  let countQuery = 'SELECT COUNT(*) as total FROM users';
  const params = [];

  if (search) {
    query += ' WHERE username LIKE ? OR email LIKE ?';
    countQuery += ' WHERE username LIKE ? OR email LIKE ?';
    params.push(`%${search}%`, `%${search}%`);
  }

  query += ` ORDER BY created_at DESC LIMIT ? OFFSET ?`;
  const users = all(query, [...params, parseInt(limit), offset]);
  const totalRow = get(countQuery, params);

  res.json({
    users,
    pagination: {
      page: parseInt(page),
      limit: parseInt(limit),
      total: totalRow.total,
      pages: Math.ceil(totalRow.total / parseInt(limit)),
    },
  });
});

// ─── GET /users/:id ───────────────────────────────────────────────────────────
/**
 * @route   GET /users/:id
 * @desc    Get a user by ID (admin or self)
 * @access  Admin | Self
 */
router.get('/:id', (req, res) => {
  const { id } = req.params;

  if (req.user.role !== 'admin' && req.user.id !== id) {
    return res.status(403).json({ error: 'Access denied' });
  }

  const user = get(
    'SELECT id, username, email, role, is_active, created_at, updated_at FROM users WHERE id = ?',
    [id]
  );

  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  res.json({ user });
});

// ─── PUT /users/:id/role ──────────────────────────────────────────────────────
/**
 * @route   PUT /users/:id/role
 * @desc    Update a user's role (admin only)
 * @access  Admin
 * @body    { role }
 */
router.put('/:id/role', authorize('admin'), (req, res) => {
  const { id } = req.params;
  const { role } = req.body;

  if (!['user', 'admin', 'moderator'].includes(role)) {
    return res.status(400).json({ error: 'Invalid role. Must be: user, admin, or moderator' });
  }

  const user = get('SELECT id FROM users WHERE id = ?', [id]);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  run(`UPDATE users SET role = ?, updated_at = datetime('now') WHERE id = ?`, [role, id]);

  res.json({ message: `User role updated to "${role}"` });
});

// ─── PUT /users/:id/status ────────────────────────────────────────────────────
/**
 * @route   PUT /users/:id/status
 * @desc    Activate or deactivate a user (admin only)
 * @access  Admin
 * @body    { is_active }
 */
router.put('/:id/status', authorize('admin'), (req, res) => {
  const { id } = req.params;
  const { is_active } = req.body;

  if (typeof is_active !== 'boolean') {
    return res.status(400).json({ error: 'is_active must be a boolean' });
  }

  if (id === req.user.id) {
    return res.status(400).json({ error: 'Cannot change your own account status' });
  }

  const user = get('SELECT id FROM users WHERE id = ?', [id]);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  run(`UPDATE users SET is_active = ?, updated_at = datetime('now') WHERE id = ?`, [
    is_active ? 1 : 0,
    id,
  ]);

  // If deactivating, revoke all refresh tokens
  if (!is_active) {
    run('DELETE FROM refresh_tokens WHERE user_id = ?', [id]);
  }

  res.json({ message: `User ${is_active ? 'activated' : 'deactivated'} successfully` });
});

// ─── DELETE /users/:id ────────────────────────────────────────────────────────
/**
 * @route   DELETE /users/:id
 * @desc    Delete a user (admin only)
 * @access  Admin
 */
router.delete('/:id', authorize('admin'), (req, res) => {
  const { id } = req.params;

  if (id === req.user.id) {
    return res.status(400).json({ error: 'Cannot delete your own account' });
  }

  const user = get('SELECT id FROM users WHERE id = ?', [id]);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  run('DELETE FROM users WHERE id = ?', [id]);

  res.json({ message: 'User deleted successfully' });
});

module.exports = router;
