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

// --- Globals — exposed for management API -------------------------
let _config = null;
let _httpServer = null;
let _httpsServer = null;
let _running = false;

const stats = {
  requests: 0,
  bytesIn: 0,
  bytesOut: 0,
  connections: new Map(),
  errors: 0,
  startTime: null,
};

const logBuffer = []; // recent log lines for UI
const MAX_LOG_LINES = 500;

// --- Logging ---
function log(...args) {
  const timestamp = _config && _config.logging.logTimestamps ? new Date().toISOString() : '';
  const line = `${timestamp} ${args.join(' ')}`;
  if (_config && _config.logging.enabled) console.log(line);
  // keep buffer
  logBuffer.push({ time: Date.now(), msg: line });
  if (logBuffer.length > MAX_LOG_LINES) logBuffer.shift();
}

// --- Certificate loading ---
let tlsOptions = null;
const CERT_PATH = path.join(__dirname, '..', 'certs', 'cert.pem');
const KEY_PATH = path.join(__dirname, '..', 'certs', 'key.pem');

function loadCerts(cfg) {
  if (!cfg.enableTls) return false;
  try {
    if (fs.existsSync(CERT_PATH) && fs.existsSync(KEY_PATH)) {
      tlsOptions = {
        key: fs.readFileSync(KEY_PATH),
        cert: fs.readFileSync(CERT_PATH),
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
      return true;
    } else {
      warn('TLS сертификаты не найдены. Запустите: npm run generate-cert');
      return false;
    }
  } catch (err) {
    warn(`Ошибка загрузки TLS: ${err.message}`);
    return false;
  }
}

function warn(msg) {
  console.warn(`[!] ${msg}`);
  log(`[!] ${msg}`);
}

// --- HTTP CONNECT handler ----------------------------------------
function handleConnect(req, socket) {
  const url = req.url; // "host:port"
  log(`[CONNECT] ${url}`);

  if (!isDomainAllowed(url.split(':')[0], _config.whitelist, _config.blacklist)) {
    socket.write('HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
    socket.destroy();
    return;
  }

  const [hostname, port = '443'] = url.split(':');
  const host = hostname.replace(/^https?:\/\//, '').replace(/\/$/, '');

  const targetSocket = net.connect({ host, port: parseInt(port, 10) }, () => {
    socket.write('HTTP/1.1 200 Connection Established\r\n' +
      `Proxy-agent: ${process.env.PROXY_NAME || 'ProxyAks/1.0'}\r\n\r\n`);
  });

  socket.pipe(targetSocket);
  targetSocket.pipe(socket);

  const connId = `${hostname}:${port}`;
  stats.connections.set(connId, (stats.connections.get(connId) || 0) + 1);

  targetSocket.on('error', () => { stats.errors++; });
  socket.on('error', () => { targetSocket.destroy(); });
}

// --- HTTP request handler ----------------------------------------
function handleHttpRequest(req, res) {
  // Status API — always serve from http server
  if (req.url === '/api/stats' && req.method === 'GET') {
    return handleStatsApi(req, res);
  }
  if (req.url === '/api/logs' && req.method === 'GET') {
    return handleLogsApi(req, res);
  }

  stats.requests++;
  const parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);

  if (!isDomainAllowed(parsedUrl.hostname, _config.whitelist, _config.blacklist)) {
    res.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Доступ к домену запрещён конфигурацией.\n');
    return;
  }

  const modifiedHeaders = applyBypassHeaders(req.headers, _config.bypass);
  modifiedHeaders.host = parsedUrl.host;

  const protocol = parsedUrl.protocol === 'https:' ? https : http;
  const agent = parsedUrl.protocol === 'https:'
    ? new https.Agent({ keepAlive: true, rejectUnauthorized: false })
    : new http.Agent({ keepAlive: true });

  const proxyReq = protocol.request({
    method: req.method,
    hostname: parsedUrl.hostname,
    port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
    path: parsedUrl.pathname + parsedUrl.search,
    headers: modifiedHeaders,
    agent,
  });

  req.on('data', chunk => stats.bytesIn += chunk.length);

  proxyReq.on('response', proxRes => {
    res.writeHead(proxRes.statusCode, proxRes.headers);
    let size = 0;
    proxRes.on('data', chunk => { size += chunk.length; res.write(chunk); });
    proxRes.on('end', () => {
      stats.bytesOut += size;
      if (_config.logging.logRequests) {
        log(`[RESPONSE] ${req.method} ${parsedUrl.hostname}${parsedUrl.pathname} → ${proxRes.statusCode} (${size} bytes)`);
      }
      res.end();
    });
  });

  proxyReq.on('error', err => {
    stats.errors++;
    log(`[!] Proxy error: ${err.message}`);
    res.writeHead(502, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end(`Ошибка проксирования: ${err.message}\n`);
  });

  req.pipe(proxyReq);
}

// --- Management API ----------------------------------------------
function handleStatsApi(req, res) {
  const mb = b => `${(b / 1024 / 1024).toFixed(2)}`;
  const connectionsArr = [];
  stats.connections.forEach((count, key) => connectionsArr.push({ host: key, count }));

  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({
    uptime: process.uptime(),
    requests: stats.requests,
    bytesIn: mb(stats.bytesIn),
    bytesOut: mb(stats.bytesOut),
    bytesInRaw: stats.bytesIn,
    bytesOutRaw: stats.bytesOut,
    activeConnections: stats.connections.size,
    totalConnections: connectionsArr,
    errors: stats.errors,
    startTime: stats.startTime,
    running: _running,
  }));
}

function handleLogsApi(req, res) {
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(logBuffer.slice(-100)));
}

// --- Server creation ---------------------------------------------
let _statsInterval = null;

function startServer() {
  return new Promise((resolve, reject) => {
    if (_running) return resolve();

    // Reload config every start
    _config = loadConfig();
    stats.startTime = Date.now();

    const hasTls = loadCerts(_config);

    // HTTP server
    _httpServer = http.createServer((req, res) => {
      if (req.url === '/api/stats') return handleStatsApi(req, res);
      if (req.url === '/api/logs') return handleLogsApi(req, res);
      return handleHttpRequest(req, res);
    });
    _httpServer.on('connect', handleConnect);

    // HTTPS server
    _httpsServer = null;
    if (hasTls && tlsOptions) {
      _httpsServer = https.createServer(tlsOptions, (req, res) => handleHttpRequest(req, res));
      _httpsServer.on('connect', handleConnect);
    }

    const errHandled = {};

    _httpServer.on('error', err => {
      if (!errHandled.http) { errHandled.http = true; reject(err); }
    });

    // Start HTTP
    _httpServer.listen(_config.port, _config.host, () => {
      log(`[✓] HTTP прокси работает:   http://${_config.host}:${_config.port}`);
      _running = true;

      if (_httpsServer) {
        _httpsServer.listen(_config.tlsPort, _config.host, () => {
          log(`[✓] HTTPS прокси работает: https://${_config.host}:${_config.tlsPort}`);
          resolve();
        });
        _httpsServer.on('error', err => { if (!errHandled.https) { errHandled.https = true; reject(err); } });
      } else {
        log('[i] HTTPS сервер отключён');
        resolve();
      }
    });

    // Periodic stats logging
    _statsInterval = setInterval(() => {
      if (stats.requests > 0) {
        log(`[i] Stats: ${stats.requests} requests, ${(stats.bytesIn / 1024).toFixed(1)} KB in, ${(stats.bytesOut / 1024).toFixed(1)} KB out`);
      }
    }, 60000);
  });
}

function stopServer() {
  return new Promise((resolve) => {
    if (_statsInterval) clearInterval(_statsInterval);
    if (!_running) { _running = false; resolve(); return; }

    const closeHttp = () => {
      if (_httpServer) _httpServer.close(() => { log('[✓] HTTP сервер остановлен'); });
      else resolve();
    };

    if (_httpsServer) {
      _httpsServer.close(() => {
        log('[✓] HTTPS сервер остановлен');
        closeHttp();
      });
    } else {
      closeHttp();
    }

    _running = false;
    // Give servers time to close
    setTimeout(resolve, 1500);
  });
}

function getStats() {
  return JSON.parse(JSON.stringify({ ...stats, connections: stats.connections.size, running: _running }));
}

function getConfig() {
  return _config;
}

function setConfig(newConfig) {
  if (_config) Object.assign(_config, newConfig);
}

function getLogs() {
  return logBuffer.slice(-200).map(l => ({ time: l.time, msg: l.msg }));
}

// --- Exports for Electron / management ---------------------------
module.exports = { startServer, stopServer, getStats, getConfig, setConfig, getLogs };

// --- Run standalone ---------------------------------------------
if (!module.parent) {
  console.log('╔══════════════════════════════════╗');
  console.log('║     ProxyAks v1.0 — Запуск      ║');
  console.log('╚══════════════════════════════════╝\n');

  (async () => {
    try {
      await startServer();
      if (Object.values(_config.bypass).some(Boolean)) log('[★] Обход блокировок: активен');
      if (_config.whitelist.length > 0) log(`[★] Белый список: ${_config.whitelist.join(', ')}`);
      if (_config.blacklist.length > 0) log(`[★] Чёрный список: ${_config.blacklist.join(', ')}`);
    } catch (err) {
      if (err.code === 'EADDRINUSE') warn(`Порт занят. Смените PORT.`);
      else console.error(err);
      process.exit(1);
    }
  })();

  ['SIGINT', 'SIGTERM'].forEach(sig => process.on(sig, async () => {
    log(`\n[✓] Получен сигнал ${sig}. Остановка...`);
    await stopServer();
    process.exit(0);
  }));
}
