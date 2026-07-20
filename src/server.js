/**
 * ProxyAks — HTTP/HTTPS прокси с обходом блокировок и защитой данных.
 *
 * Функционал:
 *   • HTTP CONNECT туннелирование (поддержка HTTPS-сайтов)
 *   • Прямое HTTP проксирование
 *   • TLS-шифрование входящих соединений (self-signed cert)
 *   • Ротация User-Agent и рандомизация заголовков
 *   • Белый/чёрный список доменов
 *   • Защита от data leakage (удаление идентифицирующих заголовков)
 *   • Быстрая активация через config.local.json или env vars
 */

const http = require('node:http');
const https = require('node:https');
const fs = require('node:fs');
const path = require('node:path');
const net = require('node:net');
const { applyBypassHeaders } = require('./bypass');
const { loadConfig, isDomainAllowed } = require('./config');

// --- Config ---
const config = loadConfig();

// --- Logging ---
function log(...args) {
  if (!config.logging.enabled) return;
  const timestamp = config.logging.logTimestamps ? new Date().toISOString() : '';
  console.log(timestamp, ...args);
}

// --- Stats ---
const stats = {
  requests: 0,
  bytesIn: 0,
  bytesOut: 0,
  connections: new Map(),
};

// --- Certificate loading ---
let tlsOptions = null;
const CERT_PATH = path.join(__dirname, '..', 'certs', 'cert.pem');
const KEY_PATH = path.join(__dirname, '..', 'certs', 'key.pem');

if (config.enableTls) {
  try {
    if (fs.existsSync(CERT_PATH) && fs.existsSync(KEY_PATH)) {
      tlsOptions = {
        key: fs.readFileSync(KEY_PATH),
        cert: fs.readFileSync(CERT_PATH),
        // Strong cipher suites only
        ciphers: [
          'TLS_AES_256_GCM_SHA384',
          'TLS_CHACHA20_POLY1305_SHA256',
          'TLS_AES_128_GCM_SHA256',
          'ECDHE-ECDSA-AES256-GCM-SHA384',
          'ECDHE-RSA-AES256-GCM-SHA384',
        ].join(':'),
        honorCipherOrder: true,
      };
      log('[✓] TLS сертификаты загружены');
    } else {
      warn('TLS сертификаты не найдены. Запустите: npm run generate-cert');
      config.enableTls = false;
    }
  } catch (err) {
    warn(`Ошибка загрузки TLS: ${err.message}`);
    config.enableTls = false;
  }
}

function warn(msg) {
  console.warn(`[!] ${msg}`);
}

// --- HTTP Agent pools ---
const httpAgents = { keepAliveAgent: new http.Agent({ keepAlive: true, maxSockets: 50 }) };
const httpsAgents = { keepAliveAgent: new https.Agent({ keepAlive: true, maxSockets: 50, rejectUnauthorized: false }) };

// --- Handle HTTP CONNECT (HTTPS tunneling) ---
function handleConnect(req, socket) {
  const url = req.url; // "host:port"
  log(`[CONNECT] ${url}`);

  if (!isDomainAllowed(url.split(':')[0], config.whitelist, config.blacklist)) {
    socket.write('HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
    socket.destroy();
    return;
  }

  const [hostname, port = '443'] = url.split(':');
  const host = hostname.replace(/^https?:\/\//, '').replace(/\/$/, '');

  // Connect to target
  const targetSocket = net.connect({ host, port: parseInt(port, 10) }, () => {
    socket.write('HTTP/1.1 200 Connection Established\r\n' +
      `Proxy-agent: ${process.env.PROXY_NAME || 'ProxyAks/1.0'}\r\n\r\n`);
    targetSocket.write('');
  });

  // Relay data between client and target
  socket.pipe(targetSocket);
  targetSocket.pipe(socket);

  const connId = `${hostname}:${port}`;
  stats.connections.set(connId, (stats.connections.get(connId) || 0) + 1);

  targetSocket.on('error', (err) => {
    log(`[!] Tunnel error ${connId}: ${err.message}`);
    socket.destroy();
  });

  socket.on('error', (err) => {
    log(`[!] Client error ${connId}: ${err.message}`);
    targetSocket.destroy();
  });
}

// --- Handle regular HTTP requests ---
function handleHttpRequest(req, res) {
  stats.requests++;
  const parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);

  if (!isDomainAllowed(parsedUrl.hostname, config.whitelist, config.blacklist)) {
    res.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Доступ к домену запрещён конфигурацией.\n');
    return;
  }

  // Apply bypass headers
  const modifiedHeaders = applyBypassHeaders(req.headers, config.bypass);

  // Ensure Host header is correct
  modifiedHeaders.host = parsedUrl.host;

  // Build agent options (keep-alive connections to targets)
  const agentOptions = { keepAlive: true };

  const protocol = parsedUrl.protocol === 'https:' ? https : http;
  const agent = parsedUrl.protocol === 'https:'
    ? new https.Agent({ ...agentOptions, rejectUnauthorized: false })
    : new http.Agent(agentOptions);

  const proxyReq = protocol.request({
    method: req.method,
    hostname: parsedUrl.hostname,
    port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
    path: parsedUrl.pathname + parsedUrl.search,
    headers: modifiedHeaders,
    agent,
  });

  // Track bytes
  req.on('data', chunk => stats.bytesIn += chunk.length);

  proxyReq.on('response', proxRes => {
    // Forward response to client
    res.writeHead(proxRes.statusCode, proxRes.headers);

    let size = 0;
    proxRes.on('data', chunk => {
      size += chunk.length;
      res.write(chunk);
    });

    proxRes.on('end', () => {
      stats.bytesOut += size;
      if (config.logging.logRequests) {
        log(`[RESPONSE] ${req.method} ${parsedUrl.hostname}${parsedUrl.pathname} → ${proxRes.statusCode} (${size} bytes)`);
      }
      res.end();
    });
  });

  proxyReq.on('error', err => {
    log(`[!] Proxy error: ${err.message}`);
    res.writeHead(502, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end(`Ошибка проксирования: ${err.message}\n`);
  });

  // Pipe request body (for POST/PUT etc)
  req.pipe(proxyReq);
}

// --- Status endpoint ---
function handleStatus(req, res) {
  const mb = (b) => `${(b / 1024 / 1024).toFixed(2)} MB`;
  const response = {
    uptime: process.uptime(),
    requests: stats.requests,
    bytesIn: mb(stats.bytesIn),
    bytesOut: mb(stats.bytesOut),
    activeConnections: stats.connections.size,
    config: {
      host: config.host,
      port: config.port,
      tlsPort: config.tlsPort,
      enableTls: config.enableTls,
      bypassActive: Object.values(config.bypass).some(Boolean),
    },
  };

  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(response, null, 2));
}

// --- Create HTTP server ---
const httpServer = http.createServer((req, res) => {
  // Status endpoint (local only)
  if (req.url === '/status' && req.headers.host?.includes('127.0.0.1')) {
    return handleStatus(req, res);
  }

  return handleHttpRequest(req, res);
});

// Intercept CONNECT requests via dedicated event
httpServer.on('connect', (req, socket) => {
  handleConnect(req, socket);
});

// --- Create HTTPS server (TLS for incoming connections) ---
let httpsServer = null;
if (config.enableTls && tlsOptions) {
  httpsServer = https.createServer(tlsOptions, (req, res) => {
    // For HTTPS, client sends CONNECT to tunnel through us
    handleHttpRequest(req, res);
  });

  httpsServer.on('connect', (req, socket) => {
    handleConnect(req, socket);
  });
}

// --- Graceful shutdown ---
function gracefulShutdown(signal) {
  log(`\n[✓] Получен сигнал ${signal}. Остановка...`);

  httpServer.close(() => {
    log('[✓] HTTP сервер остановлен');
    if (httpsServer) {
      httpsServer.close(() => {
        log('[✓] HTTPS сервер остановлен');
        process.exit(0);
      });
    } else {
      process.exit(0);
    }
  });

  // Force kill after 5s
  setTimeout(() => {
    warn('Принудительное завершение.');
    process.exit(1);
  }, 5000);
}

process.on('SIGINT', gracefulShutdown);
process.on('SIGTERM', gracefulShutdown);

// --- Start servers ---
function start() {
  httpServer.listen(config.port, config.host, () => {
    log(`[✓] HTTP прокси работает:   http://${config.host}:${config.port}`);
    log(`    → Статистика:          http://127.0.0.1:${config.port}/status`);
  });

  if (httpsServer) {
    httpsServer.listen(config.tlsPort, config.host, () => {
      log(`[✓] HTTPS прокси работает: https://${config.host}:${config.tlsPort}`);
      log(`    🔒 TLS шифрование активно (self-signed cert)`);
    });
  } else {
    log(`[i] HTTPS сервер отключён (enableTls=false или нет сертификатов)`);
  }

  if (Object.values(config.bypass).some(Boolean)) {
    log('[★] Обход блокировок: активен');
  }

  if (config.whitelist.length > 0) {
    log(`[★] Белый список: ${config.whitelist.join(', ')}`);
  }
  if (config.blacklist.length > 0) {
    log(`[★] Чёрный список: ${config.blacklist.join(', ')}`);
  }
}

// Handle HTTP errors
httpServer.on('error', err => {
  if (err.code === 'EADDRINUSE') {
    warn(`Порт ${config.port} занят. Смените PORT в config или env.`);
    process.exit(1);
  }
  throw err;
});

httpsServer?.on('error', err => {
  if (err.code === 'EADDRINUSE') {
    warn(`TLS-порт ${config.tlsPort} занят.`);
  }
  throw err;
});

// Periodic stats logging
setInterval(() => {
  if (stats.requests > 0) {
    log(`[i] Stats: ${stats.requests} requests, ${(stats.bytesIn / 1024).toFixed(1)} KB in, ${(stats.bytesOut / 1024).toFixed(1)} KB out`);
  }
}, 60000);

console.log('╔══════════════════════════════════╗');
console.log('║     ProxyAks v1.0 — Запуск      ║');
console.log('╚══════════════════════════════════╝\n');

start();
