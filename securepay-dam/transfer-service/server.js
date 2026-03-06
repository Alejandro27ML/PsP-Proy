const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const axios = require('axios');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3002;
const AUTH_SERVICE_URL = process.env.AUTH_SERVICE_URL || 'http://localhost:3001';

// Middleware
app.use(cors());
app.use(express.json());

// Database connection pool
const pool = new Pool({
  host: process.env.DB_HOST || 'localhost',
  port: process.env.DB_PORT || 5432,
  user: process.env.DB_USER || 'secure_user',
  password: process.env.DB_PASSWORD || 'secure_password',
  database: process.env.DB_NAME || 'securepay_db',
});

// Middleware to verify JWT token
const verifyToken = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];

    if (!token) {
      return res.status(401).json({ error: 'No token provided' });
    }

    const response = await axios.post(`${AUTH_SERVICE_URL}/auth/verify`, {}, {
      headers: { Authorization: `Bearer ${token}` },
    });

    if (response.data.valid) {
      req.user = response.data.user;
      next();
    } else {
      res.status(401).json({ error: 'Invalid token' });
    }
  } catch (error) {
    console.error('Token verification error:', error.message);
    res.status(401).json({ error: 'Unauthorized' });
  }
};

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'Transfer Service is running' });
});

// Get user accounts
app.get('/transfers/accounts', verifyToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, account_number, balance, account_type FROM accounts WHERE user_id = $1',
      [req.user.id]
    );

    res.json({ accounts: result.rows });
  } catch (error) {
    console.error('Get accounts error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Create transfer
app.post('/transfers/create', verifyToken, async (req, res) => {
  const client = await pool.connect();

  try {
    const { fromAccountId, toAccountId, amount, description } = req.body;

    if (!fromAccountId || !toAccountId || !amount) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    if (amount <= 0) {
      return res.status(400).json({ error: 'Amount must be greater than 0' });
    }

    // Begin transaction
    await client.query('BEGIN');

    // Verify from account belongs to user
    const fromAccountCheck = await client.query(
      'SELECT balance FROM accounts WHERE id = $1 AND user_id = $2',
      [fromAccountId, req.user.id]
    );

    if (fromAccountCheck.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Source account not found' });
    }

    if (fromAccountCheck.rows[0].balance < amount) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Insufficient funds' });
    }

    // Verify to account exists
    const toAccountCheck = await client.query(
      'SELECT id FROM accounts WHERE id = $1',
      [toAccountId]
    );

    if (toAccountCheck.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Destination account not found' });
    }

    // Create transaction record
    const transactionResult = await client.query(
      'INSERT INTO transactions (from_account_id, to_account_id, amount, description, status) VALUES ($1, $2, $3, $4, $5) RETURNING id',
      [fromAccountId, toAccountId, amount, description, 'completed']
    );

    // Update from account balance
    await client.query(
      'UPDATE accounts SET balance = balance - $1 WHERE id = $2',
      [amount, fromAccountId]
    );

    // Update to account balance
    await client.query(
      'UPDATE accounts SET balance = balance + $1 WHERE id = $2',
      [amount, toAccountId]
    );

    // Commit transaction
    await client.query('COMMIT');

    res.status(201).json({
      message: 'Transfer completed successfully',
      transactionId: transactionResult.rows[0].id,
    });
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Transfer error:', error);
    res.status(500).json({ error: 'Internal server error' });
  } finally {
    client.release();
  }
});

// Get transfer history
app.get('/transfers/history', verifyToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT t.id, t.from_account_id, t.to_account_id, t.amount, t.status, t.description, t.created_at
       FROM transactions t
       JOIN accounts a ON (t.from_account_id = a.id OR t.to_account_id = a.id)
       WHERE a.user_id = $1
       ORDER BY t.created_at DESC
       LIMIT 50`,
      [req.user.id]
    );

    res.json({ transactions: result.rows });
  } catch (error) {
    console.error('Get history error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// Start server
app.listen(PORT, () => {
  console.log(`Transfer Service running on port ${PORT}`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM signal received: closing HTTP server');
  pool.end();
  process.exit(0);
});
