/**
 * User Management Controller for SECURITY GUARD (Phase 9)
 * Handles CRUD operations, status toggling, and role changes by Admin users.
 */

const bcrypt = require('bcryptjs');
const db = require('../services/database');

const userController = {
  /**
   * GET /api/users
   * Lists all users in the system (Admin only)
   */
  listUsers: async (req, res) => {
    try {
      const users = await db.getAllUsers();
      return res.status(200).json({
        status: 'success',
        users
      });
    } catch (err) {
      console.error('[USER CONTROLLER] listUsers error:', err.message);
      return res.status(500).json({
        status: 'error',
        error: 'Internal Server Error',
        message: 'Failed to retrieve users'
      });
    }
  },

  /**
   * POST /api/users
   * Creates a new user account (Admin only)
   */
  createUser: async (req, res) => {
    try {
      const { username, email, password, role } = req.body || {};

      const cleanUsername = String(username || '').trim();
      const cleanEmail = String(email || '').trim().toLowerCase();
      const cleanPassword = typeof password === 'string' ? password : '';
      const cleanRole = String(role || 'ANALYST').trim().toUpperCase();

      // 1. Validate username
      if (!cleanUsername || cleanUsername.length < 3 || !/^[a-zA-Z0-9_-]+$/.test(cleanUsername)) {
        return res.status(400).json({
          status: 'error',
          error: 'Bad Request',
          message: 'Username must be at least 3 characters and contain only letters, numbers, underscores, and dashes'
        });
      }

      // 2. Validate email
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!cleanEmail || !emailRegex.test(cleanEmail)) {
        return res.status(400).json({
          status: 'error',
          error: 'Bad Request',
          message: 'A valid email address is required'
        });
      }

      // 3. Validate password
      if (!cleanPassword || cleanPassword.length < 6) {
        return res.status(400).json({
          status: 'error',
          error: 'Bad Request',
          message: 'Password must be at least 6 characters long'
        });
      }

      // 4. Validate role
      if (!['ADMIN', 'ANALYST'].includes(cleanRole)) {
        return res.status(400).json({
          status: 'error',
          error: 'Bad Request',
          message: "Role must be either 'ADMIN' or 'ANALYST'"
        });
      }

      // 5. Check duplicate username or email
      const existingUser = await db.findUserByUsernameOrEmail(cleanUsername);
      if (existingUser) {
        return res.status(400).json({
          status: 'error',
          error: 'Bad Request',
          message: 'Username is already taken'
        });
      }

      const existingEmail = await db.findUserByUsernameOrEmail(cleanEmail);
      if (existingEmail) {
        return res.status(400).json({
          status: 'error',
          error: 'Bad Request',
          message: 'Email address is already in use'
        });
      }

      // 6. Hash password with bcrypt
      const passwordHash = await bcrypt.hash(cleanPassword, 10);

      // 7. Save to PostgreSQL
      const newUser = await db.createUser({
        username: cleanUsername,
        email: cleanEmail,
        passwordHash,
        role: cleanRole
      });

      return res.status(201).json({
        status: 'success',
        message: `User '${cleanUsername}' created successfully`,
        user: newUser
      });
    } catch (err) {
      console.error('[USER CONTROLLER] createUser error:', err.message);
      return res.status(500).json({
        status: 'error',
        error: 'Internal Server Error',
        message: 'Failed to create user'
      });
    }
  },

  /**
   * PATCH /api/users/:id/status
   * Toggles or sets user active status (Admin only)
   */
  updateUserStatus: async (req, res) => {
    try {
      const targetId = parseInt(req.params.id, 10);
      if (isNaN(targetId) || targetId <= 0) {
        return res.status(400).json({
          status: 'error',
          error: 'Bad Request',
          message: 'Invalid user ID'
        });
      }

      const { isActive } = req.body || {};
      if (typeof isActive !== 'boolean') {
        return res.status(400).json({
          status: 'error',
          error: 'Bad Request',
          message: 'isActive must be a boolean (true/false)'
        });
      }

      const targetUser = await db.findUserById(targetId);
      if (!targetUser) {
        return res.status(404).json({
          status: 'error',
          error: 'Not Found',
          message: `User #${targetId} not found`
        });
      }

      // Safety rule: Prevent deactivating the last active Admin account
      if (!isActive && String(targetUser.role).toUpperCase() === 'ADMIN' && targetUser.is_active) {
        const activeAdmins = await db.countActiveAdmins();
        if (activeAdmins <= 1) {
          return res.status(400).json({
            status: 'error',
            error: 'Bad Request',
            message: 'Cannot deactivate the last active Admin account'
          });
        }
      }

      const updated = await db.updateUserStatus(targetId, isActive);

      // If deactivated, invalidate all existing sessions immediately
      if (!isActive) {
        await db.deleteUserSessions(targetId);
      }

      return res.status(200).json({
        status: 'success',
        message: `User #${targetId} status updated to ${isActive ? 'active' : 'inactive'}`,
        user: updated
      });
    } catch (err) {
      console.error('[USER CONTROLLER] updateUserStatus error:', err.message);
      return res.status(500).json({
        status: 'error',
        error: 'Internal Server Error',
        message: 'Failed to update user status'
      });
    }
  },

  /**
   * PATCH /api/users/:id/role
   * Updates user role between ADMIN and ANALYST (Admin only)
   */
  updateUserRole: async (req, res) => {
    try {
      const targetId = parseInt(req.params.id, 10);
      if (isNaN(targetId) || targetId <= 0) {
        return res.status(400).json({
          status: 'error',
          error: 'Bad Request',
          message: 'Invalid user ID'
        });
      }

      const { role } = req.body || {};
      const cleanRole = String(role || '').trim().toUpperCase();

      if (!['ADMIN', 'ANALYST'].includes(cleanRole)) {
        return res.status(400).json({
          status: 'error',
          error: 'Bad Request',
          message: "Role must be either 'ADMIN' or 'ANALYST'"
        });
      }

      const targetUser = await db.findUserById(targetId);
      if (!targetUser) {
        return res.status(404).json({
          status: 'error',
          error: 'Not Found',
          message: `User #${targetId} not found`
        });
      }

      // Safety rule: Prevent demoting the last active Admin to Analyst
      if (String(targetUser.role).toUpperCase() === 'ADMIN' && cleanRole !== 'ADMIN' && targetUser.is_active) {
        const activeAdmins = await db.countActiveAdmins();
        if (activeAdmins <= 1) {
          return res.status(400).json({
            status: 'error',
            error: 'Bad Request',
            message: 'Cannot demote the last active Admin account'
          });
        }
      }

      const updated = await db.updateUserRole(targetId, cleanRole);

      return res.status(200).json({
        status: 'success',
        message: `User #${targetId} role updated to ${cleanRole}`,
        user: updated
      });
    } catch (err) {
      console.error('[USER CONTROLLER] updateUserRole error:', err.message);
      return res.status(500).json({
        status: 'error',
        error: 'Internal Server Error',
        message: 'Failed to update user role'
      });
    }
  }
};

module.exports = userController;
