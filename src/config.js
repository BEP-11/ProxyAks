/**
 * Загрузка и валидация конфигурации.
 * Приоритет: .env > config.local.json > env vars > default
 */

const fs = require('node:fs');
const path = require('node:path');

// Default configuration
const DEFAULTS = {
  host: '0.0.0.0',
  port: 8080,
  tlsPort: 8443,
  enableTls: true,
  bypass: {
    rotateUserAgent: true,
    randomizeHeaders: true,
    addBrowserHeaders: true,
    removeIdentifyingHeaders: true,
  },
  whitelist: [],
  blacklist: [],
  logging: {
    enabled: true,
    logRequests: true,
    logTimestamps: true,
  },
};

const CONFIG_PATHS = [
  path.join(__dirname, '..', 'config.local.json'),
  path.join(process.cwd(), 'config.local.json'),
  path.join(__dirname, '..', 'config.default.json'),
];

function loadEnvVars() {
  const envConfig = {};

  if (process.env.PROXY_HOST) envConfig.host = process.env.PROXY_HOST;
  if (process.env.PROXY_PORT) envConfig.port = parseInt(process.env.PROXY_PORT, 10);
  if (process.env.PROXY_TLS_PORT) envConfig.tlsPort = parseInt(process.env.PROXY_TLS_PORT, 10);
  if (process.env.PROXY_ENABLE_TLS !== undefined) {
    envConfig.enableTls = process.env.PROXY_ENABLE_TLS.toLowerCase() === 'true';
  }

  // Parse blacklist/whitelist from comma-separated env vars
  if (process.env.PROXY_WHITELIST) {
    envConfig.whitelist = process.env.PROXY_WHITELIST.split(',').map(s => s.trim()).filter(Boolean);
  }
  if (process.env.PROXY_BLACKLIST) {
    envConfig.blacklist = process.env.PROXY_BLACKLIST.split(',').map(s => s.trim()).filter(Boolean);
  }

  return envConfig;
}

function deepMerge(target, source) {
  const result = Object.assign({}, target);
  for (const key of Object.keys(source)) {
    if (source[key] && typeof source[key] === 'object' && !Array.isArray(source[key])) {
      result[key] = deepMerge(result[key] || {}, source[key]);
    } else {
      result[key] = source[key];
    }
  }
  return result;
}

/**
 * Загрузить конфиг: объединяет default, local и env-переменные.
 */
function loadConfig() {
  let config = JSON.parse(JSON.stringify(DEFAULTS)); // deep copy

  // Load from JSON files (first available wins)
  for (const p of CONFIG_PATHS) {
    try {
      if (fs.existsSync(p)) {
        const fileConfig = JSON.parse(fs.readFileSync(p, 'utf-8'));
        config = deepMerge(config, fileConfig);
        break; // first found wins
      }
    } catch (err) {
      console.error(`[!] Ошибка чтения ${p}: ${err.message}`);
    }
  }

  // Overlay environment variables
  const envVars = loadEnvVars();
  config = deepMerge(config, envVars);

  return config;
}

/**
 * Проверка домена против списков.
 */
function isDomainAllowed(domain, whitelist, blacklist) {
  const normalized = domain.toLowerCase();

  // Blacklist check (priority)
  for (const pattern of blacklist) {
    if (normalized === pattern || normalized.endsWith(`.${pattern}`)) return false;
  }

  // If whitelist is defined, domain must be in it
  if (whitelist.length > 0) {
    for (const pattern of whitelist) {
      if (normalized === pattern || normalized.startsWith(`${pattern}.`)) return true;
    }
    return false;
  }

  // No restrictions
  return true;
}

module.exports = { loadConfig, isDomainAllowed };
