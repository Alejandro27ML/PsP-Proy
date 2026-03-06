const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');

const app = express();
app.use(helmet()); // Oculta cabeceras de Express

// 🛡️ Hardening: Rate Limiting (Protección contra DoS/Fuerza bruta)
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutos
    max: 100, // Límite de 100 peticiones por IP
    message: "Demasiadas peticiones. Bloqueo temporal activado por seguridad."
});
app.use(limiter);

// Enrutamiento a microservicios internos (Proxy)
app.use('/auth', createProxyMiddleware({ target: 'http://auth-service:4000', changeOrigin: true }));
app.use('/api/transfer', createProxyMiddleware({ target: 'http://transfer-service:3000', changeOrigin: true }));

app.listen(8080, () => console.log('🛡️ API Gateway en puerto 8080 (Punto de entrada único)'));