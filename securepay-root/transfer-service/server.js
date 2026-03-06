const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const axios = require('axios');
const Joi = require('joi');
const morgan = require('morgan');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3002;
const AUTH_SERVICE_URL = process.env.AUTH_SERVICE_URL || 'http://localhost:3001';
const AUDIT_SERVICE_URL = process.env.AUDIT_SERVICE_URL || 'http://localhost:3003';

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

const JWT_SECRET = process.env.JWT_SECRET || 'change-me-in-production';

// Validation schemas with Joi - Prevención de SQLi
const transferSchema = Joi.object({
  fromAccountId: Joi.number().integer().required(),
  toAccountId: Joi.number().integer().required(),
  amount: Joi.number().positive().precision(2).required(),
  description: Joi.string().max(500).allow('').optional(),
});

// Middleware to verify JWT and extract user info
const verifyToken = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    const userId = req.headers['x-user-id'];

    if (!token || !userId) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const response = await axios.post(
      `${AUTH_SERVICE_URL}/auth/verify`,
      {},
      { headers: { Authorization: `Bearer ${token}` } }
    );

    if (response.data.valid) {
      req.user = response.data.user;
      req.token = token;
      next();
    } else {
      res.status(401).json({ error: 'Invalid token' });
    }
  } catch (error) {
    console.error('[TRANSFER] Token verification error:', error.message);
    res.status(401).json({ error: 'Unauthorized' });
  }
};

app.use(verifyToken);

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'Transfer Service is running' });
});

// Helper function to log audit events
async function logAuditEvent(userId, action, details, status = 'success') {
  try {
    await axios.post(`${AUDIT_SERVICE_URL}/audit/log`, {
      userId,
      action,
      details,
      status,
    });
  } catch (error) {
    console.error('[TRANSFER] Audit logging error:', error.message);
  }
}

// Get user accounts - Integrity & Availability
app.get('/transfers/accounts', async (req, res) => {
  try {
    // Parameterized query - Anti-SQLi protection
    const result = await pool.query(
      'SELECT id, account_number, balance, account_type, created_at FROM accounts WHERE user_id = $1 ORDER BY created_at DESC',
      [req.user.id]
    );

    console.log(`[TRANSFER] Retrieved accounts for user: ${req.user.id}`);

    res.json({
      accounts: result.rows,
      count: result.rows.length,
    });
  } catch (error) {
    console.error('[TRANSFER] Get accounts error:', error);
    logAuditEvent(req.user.id, 'GET_ACCOUNTS', 'Failed to retrieve accounts', 'error');
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Create transfer - CIA Triad Implementation
app.post('/transfers/create', async (req, res) => {
  const client = await pool.connect();

  try {
    // Input validation using Joi - Prevención de SQLi
    const { error, value } = transferSchema.validate(req.body);

    if (error) {
      await logAuditEvent(req.user.id, 'CREATE_TRANSFER', `Validation error: ${error.message}`, 'failed');
      return res.status(400).json({ error: 'Invalid input', details: error.message });
    }

    const { fromAccountId, toAccountId, amount, description } = value;

    // Verify accounts are different
    if (fromAccountId === toAccountId) {
      await logAuditEvent(req.user.id, 'CREATE_TRANSFER', 'Same source and destination account', 'failed');
      return res.status(400).json({ error: 'Source and destination accounts must be different' });
    }

    // Begin transaction for ACID compliance - Integrity & Availability
    await client.query('BEGIN');

    // Verify from account belongs to user with row-level lock
    const fromAccountCheck = await client.query(
      'SELECT id, balance FROM accounts WHERE id = $1 AND user_id = $2 FOR UPDATE',
      [fromAccountId, req.user.id]
    );

    if (fromAccountCheck.rows.length === 0) {
      await client.query('ROLLBACK');
      await logAuditEvent(req.user.id, 'CREATE_TRANSFER', `Source account not found: ${fromAccountId}`, 'failed');
      return res.status(400).json({ error: 'Source account not found or unauthorized' });
    }

    const fromAccount = fromAccountCheck.rows[0];

    // Check balance - Integrity validation
    if (fromAccount.balance < amount) {
      await client.query('ROLLBACK');
      await logAuditEvent(req.user.id, 'CREATE_TRANSFER', `Insufficient funds. Required: ${amount}, Available: ${fromAccount.balance}`, 'failed');
      return res.status(400).json({ error: 'Insufficient funds' });
    }

    // Verify destination account exists with row-level lock
    const toAccountCheck = await client.query(
      'SELECT id FROM accounts WHERE id = $1 FOR UPDATE',
      [toAccountId]
    );

    if (toAccountCheck.rows.length === 0) {
      await client.query('ROLLBACK');
      await logAuditEvent(req.user.id, 'CREATE_TRANSFER', `Destination account not found: ${toAccountId}`, 'failed');
      return res.status(400).json({ error: 'Destination account not found' });
    }

    // Create transaction record - Confidentiality & Integrity
    const transactionResult = await client.query(
      'INSERT INTO transactions (from_account_id, to_account_id, amount, description, status) VALUES ($1, $2, $3, $4, $5) RETURNING id, created_at',
      [fromAccountId, toAccountId, amount, description || null, 'completed']
    );

    // Update source account balance
    await client.query(
      'UPDATE accounts SET balance = balance - $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2',
      [amount, fromAccountId]
    );

    // Update destination account balance
    await client.query(
      'UPDATE accounts SET balance = balance + $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2',
      [amount, toAccountId]
    );

    // Commit transaction
    await client.query('COMMIT');

    const transactionId = transactionResult.rows[0].id;

    console.log(`[TRANSFER] Transfer completed. ID: ${transactionId}, Amount: ${amount}`);

    // Log successful transfer
    await logAuditEvent(
      req.user.id,
      'CREATE_TRANSFER',
      `Transfer ID: ${transactionId}, From: ${fromAccountId}, To: ${toAccountId}, Amount: ${amount}`,
      'success'
    );

    res.status(201).json({
      message: 'Transfer completed successfully',
      transaction: {
        id: transactionId,
        amount,
        fromAccountId,
        toAccountId,
        status: 'completed',
        timestamp: transactionResult.rows[0].created_at,
      },
    });
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('[TRANSFER] Transfer error:', error);
    await logAuditEvent(req.user.id, 'CREATE_TRANSFER', `Error: ${error.message}`, 'error');
    res.status(500).json({ error: 'Internal server error' });
  } finally {
    client.release();
  }
});

// Get transfer history - Availability
app.get('/transfers/history', async (req, res) => {
  try {
    // Parameterized queries - Anti-SQLi
    const limit = Math.min(parseInt(req.query.limit) || 50, 100);
    const offset = Math.max(parseInt(req.query.offset) || 0, 0);

    const result = await pool.query(
      `SELECT t.id, t.from_account_id, t.to_account_id, t.amount, t.status, t.description, t.created_at
       FROM transactions t
       JOIN accounts a ON (t.from_account_id = a.id OR t.to_account_id = a.id)
       WHERE a.user_id = $1
       ORDER BY t.created_at DESC
       LIMIT $2 OFFSET $3`,
      [req.user.id, limit, offset]
    );

    console.log(`[TRANSFER] Retrieved ${result.rows.length} transactions for user: ${req.user.id}`);

    res.json({
      transactions: result.rows,
      limit,
      offset,
      count: result.rows.length,
    });
  } catch (error) {
    console.error('[TRANSFER] Get history error:', error);
    await logAuditEvent(req.user.id, 'GET_HISTORY', 'Failed to retrieve history', 'error');
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get transaction details - Confidentiality
app.get('/transfers/transaction/:id', async (req, res) => {
  try {
    const { id } = req.params;

    // Parameterized query - Anti-SQLi
    const result = await pool.query(
      `SELECT t.id, t.from_account_id, t.to_account_id, t.amount, t.status, t.description, t.created_at
       FROM transactions t
       JOIN accounts a ON (t.from_account_id = a.id OR t.to_account_id = a.id)
       WHERE t.id = $1 AND a.user_id = $2`,
      [id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Transaction not found' });
    }

    res.json({ transaction: result.rows[0] });
  } catch (error) {
    console.error('[TRANSFER] Get transaction error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('[TRANSFER] Error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// Start server
app.listen(PORT, () => {
  console.log(`Transfer Service running on port ${PORT}`);
  console.log('Implementing CIA Triad:');
  console.log('- Confidentiality: JWT tokens, encrypted data');
  console.log('- Integrity: ACID transactions, parameterized queries');
  console.log('- Availability: Connection pooling, proper error handling');
  console.log('Anti-SQLi Protection: All queries are parameterized');
});

process.on('SIGTERM', () => {
  console.log('SIGTERM received, closing connections...');
  pool.end();
  process.exit(0);
});
