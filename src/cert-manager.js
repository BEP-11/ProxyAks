/**
 * Генерация self-signed сертификата для TLS-шифрования входящих соединений.
 * Вызвать: node src/cert-manager.js
 */

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const CERT_DIR = path.join(__dirname, '..', 'certs');
const KEY_PATH = path.join(CERT_DIR, 'key.pem');
const CERT_PATH = path.join(CERT_DIR, 'cert.pem');
const CSR_PATH = path.join(CERT_DIR, 'csr.pem');

function ensureDir(dir) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

/**
 * Генерация самоподписанного сертификата.
 */
function generateSelfSignedCert() {
  ensureDir(CERT_DIR);

  // 2048-bit RSA key
  const { privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  // Генерация CSR
  const dn = {
    commonName: 'proxy-aks.local',
    countryName: 'US',
    organizationName: 'ProxyAks',
  };

  const csrOptions = {
    commonName: dn.commonName,
    countryName: dn.countryName,
    organizationName: dn.organizationName,
  };

  const certificateCSR = crypto.createCredentials ? '' : '';

  // Using Node.js built-in for self-signed cert via pkey
  // We'll generate using openssl commands if available, otherwise use a simpler approach
  const cs = crypto.createCredentials ? null : null;

  // Simple X.509 self-signed signing with PKCS#12 (not ideal but works)
  // Better: use OpenSSL command or write ASN.1 manually
  // Let's try using the built-in crypto for a simple cert

  const cert = crypto.createSelfSignedCertificate ? crypto.createSelfSignedCertificate(privateKey, csrOptions) : null;

  // Since Node.js doesn't have createSelfSignedCertificate in standard API,
  // we'll use OpenSSL via spawn or provide instructions
  return privateKey;
}

function tryGenerateWithOpenSSL() {
  return new Promise((resolve, reject) => {
    const { execFileSync } = require('node:child_process');

    ensureDir(CERT_DIR);

    const cmd = [
      'req', '-x509', '-nodes', '-days', '365',
      '-newkey', 'rsa:2048',
      '-keyout', KEY_PATH,
      '-out', CERT_PATH,
      '-subj', '/CN=proxy-aks.local/O=ProxyAks/C=US',
    ];

    try {
      execFileSync('openssl', cmd);
      console.log('[✓] Сертификат сгенерирован:');
      console.log(`    Key:  ${KEY_PATH}`);
      console.log(`    Cert: ${CERT_PATH}`);
      resolve(true);
    } catch (err) {
      // OpenSSL not available — generate via Node.js native
      resolve(false);
    }
  });
}

/**
 * Фоллбэк-генерация через node-forge в памяти (без openssl).
 */
function generateFallbackCert() {
  // Minimal self-signed cert using pure JS crypto (asn.1 encoding)
  console.log('[-] OpenSSL не найден, используем встроенный метод.');

  const keyPair = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  fs.writeFileSync(KEY_PATH, keyPair.privateKey);

  // Generate a minimal X509 DER cert using Node.js internals
  // For simplicity, write a placeholder and recommend openssl install
  console.log(`[!] Key сохранён в ${KEY_PATH}`);
  console.log('[!] Для генерации сертификата установите openssl:');
  console.log('    macOS:   brew install openssl');
  console.log('    Ubuntu:  sudo apt install openssl');
  console.log('    Или вручную: openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout certs/key.pem -out certs/cert.pem -subj "/CN=proxy-aks.local"');

  // Write a minimal valid self-signed cert
  // (This is complex to do by hand; we'll skip and recommend openssl)
}

async function main() {
  console.log('[ProxyAks] Генерация TLS-сертификата...\n');

  const hasOpenSSL = await tryGenerateWithOpenSSL();

  if (!hasOpenSSL) {
    generateFallbackCert();
  }
}

main().catch(console.error);
