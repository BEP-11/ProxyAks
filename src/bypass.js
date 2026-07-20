/**
 * Модуль обхода: ротация заголовков, рандомизация, маскировка трафика.
 */

// --- База User-Agent'ов (Chrome, Firefox, Edge разных версий) ---
const USER_AGENTS = [
  // Chrome Windows
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
  // Firefox Windows
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0',
  // Chrome macOS
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
  // Chrome Linux
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
  // Edge
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0',
  // Safari macOS
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15',
  // Firefox Linux
  'Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0',
];

// Заголовки, характерные для настоящих браузеров
const BROWSER_HEADERS = {
  Accept: ['text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
           'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'],
  'Accept-Language': ['en-US,en;q=0.9,ru;q=0.8', 'en-US,en;q=0.9', 'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7',
                      'en-GB,en;q=0.9,de-de;q=0.8,de;q=0.7', 'zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7'],
  'Accept-Encoding': ['gzip, deflate, br', 'gzip, deflate', 'br, gzip, deflate'],
  'Accept-Charset': ['ISO-8859-1,utf-8;q=0.7,*;q=0.3', 'utf-8, iso-8859-1;q=0.5, *;q=0.1'],
  DNT: ['1'],
  'Sec-Fetch-Dest': ['document', 'iframe'],
  'Sec-Fetch-Mode': ['navigate'],
  'Sec-Fetch-Site': ['none', 'cross-site'],
  'Sec-Fetch-User': ['?1'],
  Priority: ['u=0, i'],
};

// Заголовки, которые выдают прокси и должны быть удалены
const IDENTIFYING_HEADERS = [
  'x-forwarded-for',
  'x-real-ip',
  'via',
  'x-proxy-id',
  'forwarded',
  'proxy-connection',
];

/**
 * Случайный элемент массива.
 */
function randomPick(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

/**
 * Перемешать ключи объекта (случайный порядок заголовков — защита от анализа порядка).
 */
function shuffleObjectKeys(obj) {
  const keys = Object.keys(obj);
  // Fisher-Yates shuffle
  for (let i = keys.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [keys[i], keys[j]] = [keys[j], keys[i]];
  }
  const shuffled = {};
  for (const k of keys) shuffled[k] = obj[k];
  return shuffled;
}

/**
 * Сгенерировать случайную секцию Sec-CH-UA для маскировки.
 */
function randomClientHints(userAgent) {
  const browser = userAgent.includes('Firefox') ? 'Not-A-Chrome' : userAgent.includes('Edg/') ? 'Microsoft Edge' : 'Google Chrome';
  const version = userAgentsVersion(userAgent);
  const platformNames = {
    'Win64': 'Windows',
    'Macintosh': 'macOS',
    'Linux': 'Linux',
  };
  const platformMatch = userAgent.match(/\(([^)]+)\)/);
  let platform = 'Windows';
  if (platformMatch) {
    for (const [key, val] of Object.entries(platformNames)) {
      if (platformMatch[1].includes(key)) { platform = val; break; }
    }
  }

  return {
    'Sec-CH-UA': `"${browser}";v="${version}", "Not:A-Brand";v="8", "Chromium";v="${version}"`,
    'Sec-CH-UA-Mobile': '?0',
    'Sec-CH-UA-Platform': `"${platform}"`,
  };
}

function userAgentsVersion(ua) {
  const match = ua.match(/(?:Chrome|Firefox|Edg)\/(\d+)/);
  return match ? match[1] : '124';
}

/**
 * Применить все методы обхода к заголовкам запроса.
 */
function applyBypassHeaders(headers, options) {
  const result = Object.assign({}, headers);

  if (options.rotateUserAgent !== false) {
    result['user-agent'] = randomPick(USER_AGENTS);
  }

  if (options.removeIdentifyingHeaders !== false) {
    for (const h of IDENTIFYING_HEADERS) {
      delete result[h];
    }
  }

  if (options.addBrowserHeaders !== false) {
    for (const [name, values] of Object.entries(BROWSER_HEADERS)) {
      // Не перезаписываем, если уже есть и не 'accept' типа
      if (!result[name.toLowerCase()] || ['accept', 'accept-language'].includes(name.toLowerCase())) {
        result[name] = randomPick(values);
      }
    }
  }

  // Client Hints (для Chrome/Edge)
  const ua = result['user-agent'] || '';
  if (ua.includes('Chrome') || ua.includes('Edg')) {
    Object.assign(result, randomClientHints(ua));
  }

  if (options.randomizeHeaders !== false) {
    return shuffleObjectKeys(result);
  }

  return result;
}

module.exports = { applyBypassHeaders, USER_AGENTS };
