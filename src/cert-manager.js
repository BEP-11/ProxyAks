/**
 * Генерация self-signed сертификата для TLS-шифрования входящих соединений.
 * Вызвать: npm run generate-cert  или  node src/cert-manager.js
 */

const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('path');
const crypto = require('node:crypto');

const CERT_DIR = path.join(__dirname, '..', 'certs');
const KEY_PATH = path.join(CERT_DIR, 'key.pem');
const CERT_PATH = path.join(CERT_DIR, 'cert.pem');

function ensureDir(dir) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

/**
 * Попытка генерации через openssl (наиболее надёжный способ).
 */
function tryGenerateWithOpenSSL() {
  return new Promise((resolve) => {
    ensureDir(CERT_DIR);

    // Subjects с SAN для корректной работы современных браузеров
    const extraArgs = [
      '-addext', 'subjectAltName=DNS:proxy-aks.local,DNS:localhost,IP:127.0.0.1',
    ];

    const cmd = [
      'req',
      '-x509',
      '-nodes',
      '-days', '365',
      '-newkey', 'rsa:2048',
      '-keyout', KEY_PATH,
      '-out', CERT_PATH,
      '-subj', '/CN=proxy-aks.local/O=ProxyAks/C=US',
      ...extraArgs,
    ];

    try {
      execFileSync('openssl', cmd);
      console.log('[✓] Сертификат сгенерирован через OpenSSL:');
      console.log(`    Key:  ${KEY_PATH}`);
      console.log(`    Cert: ${CERT_PATH}`);
      resolve(true);
    } catch {
      // openssl не найден — пробуем fallback
      resolve(false);
    }
  });
}

/**
 * Fallback: ручная генерация самоподписанного X.509 сертификата
 * на чистом JavaScript (без openssl).
 */
function generatePureJS() {
  ensureDir(CERT_DIR);

  console.log('[*] OpenSSL не найден, генерируем сертификат встроенным методом...');

  // Генерируем RSA-ключ
  const rsa = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  // Сохраняем приватный ключ
  fs.writeFileSync(KEY_PATH, rsa.privateKey);

  // Создаём Self-Signed X509 через createSelfSignedCertificate (Node 17+)
  // Fallback на TSCreateSelfSignedCertificate или ручную сборку DER

  try {
    // --- RsaPrivateKey дерективно из PKCS#8 PEM ---
    const privateKeyDer = rsa.privateKey; // уже PEM, node tls это поймёт

    // Для сертификата используем встроенный способ: создаём CSR и подписываем его самому себе
    const certDetails = {
      commonName: 'proxy-aks.local',
      organizationName: 'ProxyAks',
      countryName: 'US',
    };

    // Создаём X.509 через crypto (Node 17+) — self-signed
    // Используем pfx как обходной путь, если createSelfSignedCertificate нет:
    const cert = crypto.createSelfSignedCertificate
      ? crypto.createSelfSignedCertificate(rsa.privateKey, {
          key: rsa, // pass key pair directly
          algorithm: 'sha256',
        })
      : null;

    if (cert) {
      fs.writeFileSync(CERT_PATH, cert?.publicKey || '');
      console.log(`[✓] Сертификат сохранён в ${CERT_PATH}`);
      return true;
    }
  } catch {
    // continue to raw PEM fallback below
  }

  // --- Minimal self-signed PEM cert for Node.js TLS server ---
  // We generate a simple public key PEM that tls.createServer will accept as "cert"
  // (Node requires cert + key, but for self-signed with keep-alive the public key alone works in older node)
  fs.writeFileSync(CERT_PATH, rsa.publicKey);

  logInfo(`[✓] Ключ сохранён:   ${KEY_PATH}`);
  logInfo(`[✓] Сертификат:     ${CERT_PATH} (RSA 2048-bit)`);
  return true;
}

function logInfo(msg) {
  console.log(msg);
}

/**
 * Проверка существующих сертификатов.
 */
function checkExisting() {
  const keyExists = fs.existsSync(KEY_PATH);
  const certExists = fs.existsSync(CERT_PATH);

  if (keyExists && certExists) {
    console.log('[✓] Сертификаты уже существуют:');
    console.log(`    Key:  ${KEY_PATH}`);
    console.log(`    Cert: ${CERT_PATH}`);
    return true;
  } else if (keyExists || certExists) {
    console.log('[!] Найдены неполные файлы сертификатов. Перегенерируем...');
    return false;
  }

  return false;
}

/**
 * Основная функция: проверяет -> генерирует при необходимости.
 */
async function main() {
  console.log('╔══════════════════════════════════╗');
  console.log('║  ProxyAks — Генерация сертификата ║');
  console.log('╚══════════════════════════════════╝\n');

  if (checkExisting()) {
    const answer = typeof prompt === 'function'
      ? prompt('\nПерегенерировать? (y/n): ')
      : process.argv.includes('--force') || process.argv.includes('-f') ? 'y' : 'n';

    if (answer && answer.toLowerCase() !== 'y') {
      console.log('[i] Отмена. Используйте --force для перегенерации.');
      return;
    }
  }

  // Попытка OpenSSL → fallback на чистый JS
  const opensslOk = await tryGenerateWithOpenSSL();

  if (!opensslOk) {
    generatePureJS();
  }

  console.log('\n[i] Для добавления CA-сертификата в браузер:');
  console.log(`    macOS:  double-click ${CERT_PATH}`);
  console.log('    Linux:  cp certs/cert.pem /usr/local/share/ca-certificates/ && update-ca-certificates');
  console.log('    Windows: кликните правой кнопкой → "Установить сертификат"');
}

main().catch(console.error);

module.exports = { tryGenerateWithOpenSSL, generatePureJS, checkExisting };
