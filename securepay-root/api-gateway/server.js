const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const axios = require('axios');
const morgan = require('morgan');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Service URLs
const AUTH_SERVICE_URL = process.env.AUTH_SERVICE_URL || 'http://localhost:3001';
const TRANSFER_SERVICE_URL = process.env.TRANSFER_SERVICE_URL || 'http://localhost:3002';
const AUDIT_SERVICE_URL = process.env.AUDIT_SERVICE_URL || 'http://localhost:3003';

// Middleware
app.use(morgan('combined'));
app.use(cors());
app.use(express.json());

// Rate Limiting
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW) || 15 * 60 * 1000,
  max: parseInt(process.env.RATE_LIMIT) || 100,
  message: 'Too many requests, please try again later',
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(limiter);

// Verificación de token JWT
const verifyToken = async (req, res, next) => {
  const publicRoutes = ['/health', '/auth/register', '/auth/login'];

  if (publicRoutes.includes(req.path)) {
    return next();
  }

  try {
    const token = req.headers.authorization?.split(' ')[1];

    if (!token) {
      return res.status(401).json({ error: 'No token provided' });
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
    console.error('Token verification error:', error.message);
    res.status(401).json({ error: 'Unauthorized' });
  }
};

// Health check
app.get('/health', (req, res) => {
  res.json({
    status: 'API Gateway is running',
    timestamp: new Date().toISOString(),
  });
});

// Public routes - Auth Service
app.post('/auth/register', (req, res, next) => {
  createProxyMiddleware({
    target: AUTH_SERVICE_URL,
    changeOrigin: true,
    pathRewrite: { '^/auth': '/auth' },
  })(req, res, next);
});

app.post('/auth/login', (req, res, next) => {
  createProxyMiddleware({
    target: AUTH_SERVICE_URL,
    changeOrigin: true,
    pathRewrite: { '^/auth': '/auth' },
  })(req, res, next);
});

// Apply token verification to protected routes
app.use(verifyToken);

// Protected routes - Auth Service
app.post('/auth/verify', (req, res, next) => {
  createProxyMiddleware({
    target: AUTH_SERVICE_URL,
    changeOrigin: true,
    pathRewrite: { '^/auth': '/auth' },
  })(req, res, next);
});

// Routes - Transfer Service
app.use('/transfers', (req, res, next) => {
  // Add user context to request
  req.headers['x-user-id'] = req.user.id;
  req.headers['x-user-email'] = req.user.email;

  createProxyMiddleware({
    target: TRANSFER_SERVICE_URL,
    changeOrigin: true,
    pathRewrite: { '^/transfers': '/transfers' },
  })(req, res, next);
});

// Routes - Audit Logs
app.use('/audit', (req, res, next) => {
  req.headers['x-user-id'] = req.user.id;

  createProxyMiddleware({
    target: AUDIT_SERVICE_URL,
    changeOrigin: true,
    pathRewrite: { '^/audit': '/audit' },
  })(req, res, next);
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).json({
    error: 'Internal server error',
    timestamp: new Date().toISOString(),
  });
});

// 404 Not Found
app.use((req, res) => {
  res.status(404).json({
    error: 'Not found',
    path: req.path,
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`API Gateway running on port ${PORT}`);
  console.log(`Auth Service: ${AUTH_SERVICE_URL}`);
  console.log(`Transfer Service: ${TRANSFER_SERVICE_URL}`);
  console.log(`Audit Service: ${AUDIT_SERVICE_URL}`);
});

process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully...');
  process.exit(0);
});
