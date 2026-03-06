const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const morgan = require('morgan');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3003;

// Middleware
app.use(morgan('combined'));
app.use(cors());
app.use(express.json());

// Database connection pool
const pool = new Pool({
  host: process.env.DB_HOST || 'localhost',
  port: process.env.DB_PORT || 5432,
  user: process.env.DB_USER || 'secure_user',
  password: process.env.DB_PASSWORD || 'secure_password',
  database: process.env.DB_NAME || 'securepay_db',
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'Audit Logs Service is running' });
});

// Log audit event - Immutable audit trail
app.post('/audit/log', async (req, res) => {
  try {
    const { userId, action, details, status = 'success' } = req.body;

    if (!userId || !action) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // Get IP address from request
    const ipAddress = 
      req.headers['x-forwarded-for']?.split(',')[0] ||
      req.socket.remoteAddress ||
      req.ip ||
      'unknown';

    // Insert audit log - Immutable with timestamp
    const result = await pool.query(
      `INSERT INTO audit_logs (user_id, action, details, status, ip_address)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, created_at`,
      [userId, action, details || null, status, ipAddress]
    );

    console.log(`[AUDIT] Event logged: ${action} by user ${userId}`);

    res.status(201).json({
      message: 'Audit event logged successfully',
      auditId: result.rows[0].id,
      timestamp: result.rows[0].created_at,
    });
  } catch (error) {
    console.error('[AUDIT] Logging error:', error);
    // Don't expose error details in response
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get audit logs for user
app.get('/audit/logs/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const limit = Math.min(parseInt(req.query.limit) || 100, 500);
    const offset = Math.max(parseInt(req.query.offset) || 0, 0);

    // Input validation
    if (isNaN(userId)) {
      return res.status(400).json({ error: 'Invalid user ID' });
    }

    // Parameterized query - Anti-SQLi
    const result = await pool.query(
      `SELECT id, user_id, action, details, status, ip_address, created_at
       FROM audit_logs
       WHERE user_id = $1
       ORDER BY created_at DESC
       LIMIT $2 OFFSET $3`,
      [userId, limit, offset]
    );

    console.log(`[AUDIT] Retrieved ${result.rows.length} logs for user ${userId}`);

    res.json({
      logs: result.rows,
      limit,
      offset,
      count: result.rows.length,
    });
  } catch (error) {
    console.error('[AUDIT] Retrieval error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get all audit logs by action type (admin endpoint)
app.get('/audit/action/:action', async (req, res) => {
  try {
    const { action } = req.params;
    const limit = Math.min(parseInt(req.query.limit) || 50, 500);
    const offset = Math.max(parseInt(req.query.offset) || 0, 0);

    // Input validation
    if (!action || action.length < 3 || action.length > 100) {
      return res.status(400).json({ error: 'Invalid action' });
    }

    // Parameterized query - Anti-SQLi
    const result = await pool.query(
      `SELECT id, user_id, action, details, status, ip_address, created_at
       FROM audit_logs
       WHERE action = $1
       ORDER BY created_at DESC
       LIMIT $2 OFFSET $3`,
      [action, limit, offset]
    );

    console.log(`[AUDIT] Retrieved ${result.rows.length} logs for action: ${action}`);

    res.json({
      logs: result.rows,
      action,
      limit,
      offset,
      count: result.rows.length,
    });
  } catch (error) {
    console.error('[AUDIT] Retrieval error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get audit logs by status (failed attempts, etc.)
app.get('/audit/status/:status', async (req, res) => {
  try {
    const { status } = req.params;
    const limit = Math.min(parseInt(req.query.limit) || 50, 500);
    const offset = Math.max(parseInt(req.query.offset) || 0, 0);

    // Validate status
    const validStatuses = ['success', 'failed', 'error', 'warning'];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({ error: 'Invalid status' });
    }

    // Parameterized query - Anti-SQLi
    const result = await pool.query(
      `SELECT id, user_id, action, details, status, ip_address, created_at
       FROM audit_logs
       WHERE status = $1
       ORDER BY created_at DESC
       LIMIT $2 OFFSET $3`,
      [status, limit, offset]
    );

    console.log(`[AUDIT] Retrieved ${result.rows.length} logs with status: ${status}`);

    res.json({
      logs: result.rows,
      status,
      limit,
      offset,
      count: result.rows.length,
    });
  } catch (error) {
    console.error('[AUDIT] Retrieval error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get failed login attempts
app.get('/audit/failed-logins/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const hoursBack = Math.min(parseInt(req.query.hours) || 24, 720);

    if (isNaN(userId)) {
      return res.status(400).json({ error: 'Invalid user ID' });
    }

    // Parameterized query
    const result = await pool.query(
      `SELECT id, user_id, action, details, ip_address, created_at
       FROM audit_logs
       WHERE user_id = $1 
       AND status = 'failed'
       AND action LIKE '%LOGIN%'
       AND created_at >= NOW() - INTERVAL '1 hour' * $2
       ORDER BY created_at DESC`,
      [userId, hoursBack]
    );

    console.log(`[AUDIT] Retrieved ${result.rows.length} failed login attempts for user ${userId}`);

    res.json({
      failedAttempts: result.rows,
      count: result.rows.length,
      timeframeHours: hoursBack,
    });
  } catch (error) {
    console.error('[AUDIT] Retrieval error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Statistics endpoint
app.get('/audit/statistics', async (req, res) => {
  try {
    const hoursBack = Math.min(parseInt(req.query.hours) || 24, 720);

    const stats = await pool.query(
      `SELECT 
        COUNT(*) as total_events,
        SUM(CASE WHEN status = 'success' THEN 1 ELSE 0 END) as successful_events,
        SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failed_events,
        SUM(CASE WHEN status = 'error' THEN 1 ELSE 0 END) as error_events,
        COUNT(DISTINCT user_id) as unique_users
       FROM audit_logs
       WHERE created_at >= NOW() - INTERVAL '1 hour' * $1`,
      [hoursBack]
    );

    console.log('[AUDIT] Statistics retrieved');

    res.json({
      statistics: stats.rows[0],
      timeframeHours: hoursBack,
    });
  } catch (error) {
    console.error('[AUDIT] Statistics error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('[AUDIT] Error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// Start server
app.listen(PORT, () => {
  console.log(`Audit Logs Service running on port ${PORT}`);
  console.log('Implementing immutable audit trail for compliance and forensics');
  console.log('Features:');
  console.log('- User activity logging');
  console.log('- Timestamp-based trails');
  console.log('- IP address tracking');
  console.log('- Failed attempt monitoring');
  console.log('- Statistical analysis');
  console.log('- Anti-SQLi parameterized queries');
});

process.on('SIGTERM', () => {
  console.log('SIGTERM received, closing connections...');
  pool.end();
  process.exit(0);
});
