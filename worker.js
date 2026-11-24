/**
 * Cloudflare Worker Proxy v3 PRO (سفارشی)
 *
 * ویژگی‌های اضافه‌شده نسبت به نسخه v2:
 *   ✦ احراز هویت چندکاربره با Workers KV
 *   ✦ آمار مصرف به تفکیک کاربر (upload/download/total) در KV
 *   ✦ XHTTP stream-up با Durable Object
 *   ✦ Shadowsocks 2022 با blake3 (پشتیبانی از کلاینت‌های 2022)
 *   ✦ پنل مدیریت /admin با احراز هویت با توکن
 *   ✦ بخش Clean IP: جستجو و تست IP تمیز برای سرویس‌های استریم و AI
 *
 * ساختار فایل‌ها:
 *   _worker.js     — این فایل (کد اصلی)
 *   blake3.js      — پیاده‌سازی Blake3 برای SS 2022
 *
 * منابع مورد نیاز در Cloudflare:
 *   KV Namespace: USERS_KV (برای احراز هویت)
 *   KV Namespace: STATS_KV (برای آمار مصرف)
 *   Durable Object: XHTTP_SESSION (برای stream-up)
 *
 * متغیرهای محیطی:
 *   UUID, TROJAN_PASSWORD, SS_PASSWORD — همان v2
 *   SS2022_PASSWORD                    — رمز SS 2022 (base64-encoded 32-byte key)
 *   ADMIN_TOKEN                        — توکن پنل مدیریت /admin
 *   SUB_PATH, PROXY_PATH, XHTTP_PATH, NAME
 *   CLEANIP_PATH                       — مسیر بخش Clean IP، پیش‌فرض: cleanip
 */

// وارد کردن blake3 از فایل مجاور
import { deriveSS2022Key, sha256Sync } from './blake3.js';

// ===== پیکربندی پیش‌فرض =====
const DEFAULTS = {
  UUID: 'd342d11e-d424-4583-b36e-524ab1f0afa4',
  TROJAN_PASSWORD: 'MyTrojanPass2025',
  SS_PASSWORD: 'MyShadowsocksPass2025',
  SS2022_PASSWORD: 'YWVzLTI1Ni1nY206YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnh5ejEyMzQ1Njc4', // مثال base64
  ADMIN_TOKEN: 'change-this-to-a-strong-token',
  SUB_PATH: 'sub',
  PROXY_PATH: 'ws',
  XHTTP_PATH: 'xhttp',
  ADMIN_PATH: 'admin',
  CLEANIP_PATH: 'cleanip',
  NAME: 'cf-worker-pro',
};

// ===== بخش Clean IP — منابع متعدد =====
// هر سرویس چندین endpoint تست دارد (parallel test) — افزایش دقت تشخیص
// منابع داده برای Clean IP:
//   ۱) رنج‌های IP معروف Cloudflare (محلی)
//   ۲) لیست‌های جامعه‌محور در GitHub (فچ در زمان درخواست)
//   ۳) API های geolocation (ip-api, ipinfo, ipapi.co)
//   ۴) تست مستقیم endpoint هر سرویس

const CLEAN_IP_SERVICES = [
  {
    name: 'Netflix',
    icon: '🎬',
    endpoints: [
      { url: 'https://www.netflix.com/title/81215567', method: 'GET', desc: 'Netflix Originals page' },
      { url: 'https://www.netflix.com/title/70143836', method: 'GET', desc: 'Netflix test title' },
      { url: 'https://netflix.com/cdn-cgi/trace', method: 'GET', desc: 'Netflix CF trace' },
    ],
    test: async (ip) => {
      // تست چند endpoint به‌صورت موازی
      const results = await Promise.allSettled([
        fetch('https://www.netflix.com/title/81215567', {
          headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' },
          signal: AbortSignal.timeout(8000),
        }).then((r) => ({ status: r.status, url: 'title/81215567' })),
        fetch('https://www.netflix.com/title/70143836', {
          headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' },
          signal: AbortSignal.timeout(8000),
        }).then((r) => ({ status: r.status, url: 'title/70143836' })),
      ]);
      const unlocked = results.some((r) => r.status === 'fulfilled' && r.value.status === 200);
      const blocked = results.some((r) => r.status === 'fulfilled' && (r.value.status === 403 || r.value.status === 429));
      if (unlocked) return { status: 'unlocked', detail: 'Netflix Unblocked (Originals可达)' };
      if (blocked) return { status: 'blocked', detail: 'Netflix Blocked (proxy detected)' };
      const statuses = results.filter((r) => r.status === 'fulfilled').map((r) => r.value.status).join(',');
      return { status: 'unknown', detail: `HTTP ${statuses || 'timeout'}` };
    },
  },
  {
    name: 'ChatGPT (OpenAI)',
    icon: '🤖',
    endpoints: [
      { url: 'https://chat.openai.com/cdn-cgi/trace', method: 'GET', desc: 'OpenAI CF trace' },
      { url: 'https://api.openai.com/v1/engines', method: 'GET', desc: 'OpenAI API status' },
      { url: 'https://chatgpt.com/cdn-cgi/trace', method: 'GET', desc: 'chatgpt.com CF trace' },
    ],
    test: async (ip) => {
      const results = await Promise.allSettled([
        fetch('https://chat.openai.com/cdn-cgi/trace', { signal: AbortSignal.timeout(8000) })
          .then((r) => r.text().then((t) => ({ status: r.status, text: t }))),
        fetch('https://chatgpt.com/cdn-cgi/trace', { signal: AbortSignal.timeout(8000) })
          .then((r) => r.text().then((t) => ({ status: r.status, text: t }))),
        fetch('https://api.openai.com/v1/engines', { signal: AbortSignal.timeout(8000) })
          .then((r) => ({ status: r.status })),
      ]);
      const ok = results.some((r) => r.status === 'fulfilled' && (r.value.status === 200 || r.value.status === 401));
      const blocked = results.some((r) => r.status === 'fulfilled' && r.value.status === 403);
      if (ok) {
        // استخراج لوکیشن از cdn-cgi/trace
        const traceText = results.find((r) => r.status === 'fulfilled' && r.value.text)?.value?.text || '';
        const loc = traceText.match(/^loc=(.+)$/m)?.[1] || '?';
        return { status: 'unlocked', detail: `OpenAI reachable | loc=${loc}` };
      }
      if (blocked) return { status: 'blocked', detail: 'OpenAI region blocked' };
      return { status: 'unknown', detail: 'Could not determine' };
    },
  },
  {
    name: 'Disney+',
    icon: '🏰',
    endpoints: [
      { url: 'https://www.disneyplus.com', method: 'GET', desc: 'Disney+ main' },
      { url: 'https://disneyplus.com', method: 'GET', desc: 'Disney+ root' },
      { url: 'https://www.disneyplus.com/unavailable', method: 'GET', desc: 'Disney+ unavailable check' },
    ],
    test: async (ip) => {
      const results = await Promise.allSettled([
        fetch('https://www.disneyplus.com', {
          headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' },
          signal: AbortSignal.timeout(8000),
        }).then((r) => ({ status: r.status, url: r.url })),
        fetch('https://www.disneyplus.com/unavailable', {
          headers: { 'User-Agent': 'Mozilla/5.0' },
          signal: AbortSignal.timeout(8000),
        }).then((r) => ({ status: r.status })),
      ]);
      const ok = results.some((r) => r.status === 'fulfilled' && r.value.status === 200);
      const blocked = results.some((r) => r.status === 'fulfilled' && r.value.status === 403);
      if (ok) return { status: 'unlocked', detail: 'Disney+ reachable' };
      if (blocked) return { status: 'blocked', detail: 'Disney+ region blocked' };
      return { status: 'unknown', detail: 'Status unknown' };
    },
  },
  {
    name: 'YouTube Premium',
    icon: '📺',
    endpoints: [
      { url: 'https://www.youtube.com/red', method: 'GET', desc: 'YouTube Premium check' },
      { url: 'https://www.youtube.com/premium', method: 'GET', desc: 'YouTube Premium page' },
    ],
    test: async (ip) => {
      const results = await Promise.allSettled([
        fetch('https://www.youtube.com/red', {
          headers: { 'User-Agent': 'Mozilla/5.0' },
          redirect: 'manual',
          signal: AbortSignal.timeout(8000),
        }).then((r) => ({ status: r.status, location: r.headers.get('location') })),
        fetch('https://www.youtube.com/premium', {
          headers: { 'User-Agent': 'Mozilla/5.0' },
          signal: AbortSignal.timeout(8000),
        }).then((r) => ({ status: r.status })),
      ]);
      // YouTube همیشه 200 برمی‌گرداند، اما redirect به unavailable صفحه می‌رود
      const ok = results.some((r) => r.status === 'fulfilled' && r.value.status === 200);
      if (ok) return { status: 'unlocked', detail: 'YouTube reachable' };
      return { status: 'unknown', detail: 'Status unknown' };
    },
  },
  {
    name: 'Spotify',
    icon: '🎵',
    endpoints: [
      { url: 'https://www.spotify.com', method: 'GET', desc: 'Spotify main' },
      { url: 'https://spclient.wg.spotify.com/signup/public/v1/account', method: 'GET', desc: 'Spotify signup API' },
    ],
    test: async (ip) => {
      const results = await Promise.allSettled([
        fetch('https://www.spotify.com', {
          headers: { 'User-Agent': 'Mozilla/5.0' },
          signal: AbortSignal.timeout(8000),
        }).then((r) => ({ status: r.status })),
        fetch('https://www.spotify.com/fr/', {
          headers: { 'User-Agent': 'Mozilla/5.0' },
          signal: AbortSignal.timeout(8000),
        }).then((r) => ({ status: r.status })),
      ]);
      const ok = results.some((r) => r.status === 'fulfilled' && r.value.status === 200);
      if (ok) return { status: 'unlocked', detail: 'Spotify reachable' };
      return { status: 'unknown', detail: 'Status unknown' };
    },
  },
  {
    name: 'TikTok',
    icon: '📱',
    endpoints: [
      { url: 'https://www.tiktok.com', method: 'GET', desc: 'TikTok main' },
      { url: 'https://m.tiktok.com', method: 'GET', desc: 'TikTok mobile' },
    ],
    test: async (ip) => {
      const results = await Promise.allSettled([
        fetch('https://www.tiktok.com', {
          headers: { 'User-Agent': 'Mozilla/5.0' },
          signal: AbortSignal.timeout(8000),
        }).then((r) => ({ status: r.status })),
      ]);
      const ok = results.some((r) => r.status === 'fulfilled' && r.value.status === 200);
      const blocked = results.some((r) => r.status === 'fulfilled' && r.value.status === 403);
      if (ok) return { status: 'unlocked', detail: 'TikTok reachable' };
      if (blocked) return { status: 'blocked', detail: 'TikTok region blocked' };
      return { status: 'unknown', detail: 'Status unknown' };
    },
  },
  {
    name: 'Hulu',
    icon: '📡',
    endpoints: [
      { url: 'https://www.hulu.com', method: 'GET', desc: 'Hulu main' },
    ],
    test: async (ip) => {
      try {
        const r = await fetch('https://www.hulu.com', {
          headers: { 'User-Agent': 'Mozilla/5.0' },
          signal: AbortSignal.timeout(8000),
        });
        if (r.status === 200) return { status: 'unlocked', detail: 'Hulu reachable' };
        if (r.status === 403) return { status: 'blocked', detail: 'Hulu region blocked' };
        return { status: 'unknown', detail: `HTTP ${r.status}` };
      } catch (e) { return { status: 'error', detail: e.message }; }
    },
  },
  {
    name: 'HBO Max',
    icon: '🎭',
    endpoints: [
      { url: 'https://www.max.com', method: 'GET', desc: 'HBO Max main' },
    ],
    test: async (ip) => {
      try {
        const r = await fetch('https://www.max.com', {
          headers: { 'User-Agent': 'Mozilla/5.0' },
          signal: AbortSignal.timeout(8000),
        });
        if (r.status === 200) return { status: 'unlocked', detail: 'HBO Max reachable' };
        if (r.status === 403) return { status: 'blocked', detail: 'Region blocked' };
        return { status: 'unknown', detail: `HTTP ${r.status}` };
      } catch (e) { return { status: 'error', detail: e.message }; }
    },
  },
  {
    name: 'Amazon Prime Video',
    icon: '📦',
    endpoints: [
      { url: 'https://www.primevideo.com', method: 'GET', desc: 'Prime Video main' },
    ],
    test: async (ip) => {
      try {
        const r = await fetch('https://www.primevideo.com', {
          headers: { 'User-Agent': 'Mozilla/5.0' },
          signal: AbortSignal.timeout(8000),
        });
        if (r.status === 200) return { status: 'unlocked', detail: 'Prime Video reachable' };
        return { status: 'unknown', detail: `HTTP ${r.status}` };
      } catch (e) { return { status: 'error', detail: e.message }; }
    },
  },
  {
    name: 'Cloudflare Reachability',
    icon: '☁️',
    endpoints: [
      { url: 'https://1.1.1.1/cdn-cgi/trace', method: 'GET', desc: 'Cloudflare trace' },
      { url: 'https://cloudflare.com/cdn-cgi/trace', method: 'GET', desc: 'Cloudflare main trace' },
    ],
    test: async (ip) => {
      try {
        const r = await fetch('https://1.1.1.1/cdn-cgi/trace', {
          signal: AbortSignal.timeout(5000),
        });
        if (r.status === 200) {
          const text = await r.text();
          const ipMatch = text.match(/^ip=(.+)$/m);
          const locMatch = text.match(/^loc=(.+)$/m);
          const coloMatch = text.match(/^colo=(.+)$/m);
          return {
            status: 'unlocked',
            detail: `IP: ${ipMatch ? ipMatch[1] : '?'} | Loc: ${locMatch ? locMatch[1] : '?'} | ColO: ${coloMatch ? coloMatch[1] : '?'}`,
          };
        }
        return { status: 'unknown', detail: `HTTP ${r.status}` };
      } catch (e) { return { status: 'error', detail: e.message }; }
    },
  },
];

// ===== منابع داده برای لیست IP تمیز =====
// هر منبع یک URL است که لیست IP تمیز را برمی‌گرداند (txt یا json)
const CLEAN_IP_SOURCES = [
  {
    name: 'Cloudflare IP Ranges (محلی)',
    type: 'local',
    description: 'رنج‌های رسمی Cloudflare — ۱۵ CIDR',
    ips: () => {
      // تولید لیست از CLOUDFLARE_IP_RANGES (تعریف‌شده در ادامه)
      return CLOUDFLARE_IP_RANGES;
    },
  },
  {
    name: 'Vfarid CF Clean IP (GitHub)',
    type: 'github',
    url: 'https://raw.githubusercontent.com/vfarid/cf-ip-scanner/main/cf-ipv4.txt',
    description: 'لیست IP تمیز Cloudflare از vfarid/cf-ip-scanner',
    format: 'txt', // هر خط یک IP
  },
  {
    name: 'YMFEv4 CF Clean IP List',
    type: 'github',
    url: 'https://raw.githubusercontent.com/ymyuuu/IPDB/main/cf-clean-ip.txt',
    description: 'لیست community-maintained از ymyuuu/IPDB',
    format: 'txt',
  },
  {
    name: 'Mullvad Relay Servers',
    type: 'mullvad',
    url: 'https://api.mullvad.net/www/relays/all/',
    description: 'سرورهای VPN Mullvad — IP تمیز برای اتصال',
    format: 'json',
    // فیلد ipv4_addr_in در هر آبجکت relay
  },
  {
    name: 'ProtonVPN Logical Servers',
    type: 'protonvpn',
    url: 'https://api.protonmail.ch/vpn/logicals',
    description: 'سرورهای منطقی ProtonVPN — EntryIP هر سرور',
    format: 'json',
    // فیلد Servers[].EntryIP در آبجکت Logical
  },
  {
    name: 'Cloudflare Speed Test Endpoint',
    type: 'speedtest',
    url: 'https://speed.cloudflare.com/__down?bytes=1000',
    description: 'اندازه گیری سرعت و latency از Cloudflare',
    format: 'binary',
  },
  {
    name: 'ip-api.com (Geolocation)',
    type: 'geo-api',
    url: 'http://ip-api.com/json/{ip}',
    description: 'API geolocation — کشور، شهر، ISP',
    format: 'json',
  },
  {
    name: 'ipinfo.io (Geolocation)',
    type: 'geo-api',
    url: 'https://ipinfo.io/{ip}/json',
    description: 'API geolocation با شرکت و ASN',
    format: 'json',
  },
  {
    name: 'Community Submitted (KV)',
    type: 'community',
    description: 'IP های ارسال‌شده توسط کاربران با رای‌گیری',
    format: 'kv',
  },
  {
    name: 'Mozilla VPN Relays (via Mullvad)',
    type: 'mozilla',
    url: 'https://api.mullvad.net/www/relays/all/',
    description: 'سرورهای Mozilla VPN — فیلتر روی owner=mozilla از Mullvad API',
    format: 'json',
  },
  {
    name: 'Apple Private Relay Endpoints',
    type: 'apple',
    description: 'دامنه‌های Apple iCloud Private Relay — mask.icloud.com و mask-h2.icloud.com',
    format: 'static',
    domains: ['mask.icloud.com', 'mask-h2.icloud.com', 'mask-canary.icloud.com'],
  },
  {
    name: 'Google Public DNS',
    type: 'google-dns',
    description: 'IP های Google Public DNS — 8.8.8.8, 8.8.4.4 (همیشه تمیز)',
    format: 'static',
    ips: ['8.8.8.8', '8.8.4.4', '2001:4860:4860::8888', '2001:4860:4860::8844'],
  },
];

// ===== رنج‌های Cloudflare (IPv4) =====
const CLOUDFLARE_IP_RANGES = [
  '173.245.48.0/20',
  '103.21.244.0/22',
  '103.22.200.0/22',
  '103.31.4.0/22',
  '141.101.64.0/18',
  '108.162.192.0/18',
  '190.93.240.0/20',
  '188.114.96.0/20',
  '197.234.240.0/22',
  '198.41.128.0/17',
  '162.158.0.0/15',
  '104.16.0.0/13',
  '104.24.0.0/14',
  '172.64.0.0/13',
  '131.0.72.0/22',
];

// تولید IP تصادفی از یک CIDR
function randomIpFromCidr(cidr) {
  const [base, prefix] = cidr.split('/');
  const parts = base.split('.').map(Number);
  const prefixNum = parseInt(prefix, 10);
  const mask = (0xffffffff << (32 - prefixNum)) >>> 0;
  const baseInt = ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
  const network = (baseInt & mask) >>> 0;
  const hostBits = 32 - prefixNum;
  const hostMax = (1 << hostBits) - 1;
  const randomHost = Math.floor(Math.random() * hostMax);
  const ipInt = (network + randomHost) >>> 0;
  return [
    (ipInt >>> 24) & 0xff,
    (ipInt >>> 16) & 0xff,
    (ipInt >>> 8) & 0xff,
    ipInt & 0xff,
  ].join('.');
}

// تولید IP تصادفی از رنج‌های Cloudflare
function randomCloudflareIp() {
  const cidr = CLOUDFLARE_IP_RANGES[Math.floor(Math.random() * CLOUDFLARE_IP_RANGES.length)];
  return { ip: randomIpFromCidr(cidr), cidr, source: 'Cloudflare Local Ranges' };
}

// فچ لیست IP از یک منبع GitHub
async function fetchIpListFromGithub(sourceUrl) {
  try {
    const r = await fetch(sourceUrl, {
      signal: AbortSignal.timeout(15000),
      headers: { 'User-Agent': 'cf-worker-cleanip/1.0' },
    });
    if (!r.ok) return { ok: false, error: `HTTP ${r.status}`, ips: [] };
    const text = await r.text();
    // هر خط یک IP
    const ips = text
      .split('\n')
      .map((l) => l.trim())
      .filter((l) => l && !l.startsWith('#') && isValidIp(l));
    return { ok: true, ips, count: ips.length };
  } catch (e) {
    return { ok: false, error: e.message, ips: [] };
  }
}

// فچ لیست سرورهای Mullvad
// ساختار JSON: { "openvpn": [{ "country": "...", "ipv4_addr_in": "...", ... }, ...] }
async function fetchMullvadRelays() {
  try {
    const r = await fetch('https://api.mullvad.net/www/relays/all/', {
      signal: AbortSignal.timeout(15000),
      headers: { 'User-Agent': 'cf-worker-cleanip/1.0', 'Accept': 'application/json' },
    });
    if (!r.ok) return { ok: false, error: `HTTP ${r.status}`, ips: [] };
    const data = await r.json();
    const ips = [];
    const relaysInfo = [];
    // داده‌ها برای هر پروتکل (openvpn, wireguard, bridge) یک array است
    for (const proto of ['openvpn', 'wireguard', 'bridge']) {
      if (Array.isArray(data[proto])) {
        for (const relay of data[proto]) {
          if (relay.ipv4_addr_in && isValidIp(relay.ipv4_addr_in)) {
            ips.push(relay.ipv4_addr_in);
            relaysInfo.push({
              ip: relay.ipv4_addr_in,
              country: relay.country || '?',
              city: relay.city || '?',
              hostname: relay.hostname || '?',
              protocol: proto,
              provider: 'mullvad',
            });
          }
        }
      }
    }
    return { ok: true, ips, count: ips.length, relays: relaysInfo };
  } catch (e) {
    return { ok: false, error: e.message, ips: [] };
  }
}

// فچ لیست سرورهای ProtonVPN
// ساختار JSON: { "LogicalServers": [{ "Servers": [{ "EntryIP": "..." }], "Country": "...", ... }] }
async function fetchProtonVpnServers() {
  try {
    const r = await fetch('https://api.protonmail.ch/vpn/logicals', {
      signal: AbortSignal.timeout(15000),
      headers: { 'User-Agent': 'cf-worker-cleanip/1.0', 'Accept': 'application/json' },
    });
    if (!r.ok) return { ok: false, error: `HTTP ${r.status}`, ips: [] };
    const data = await r.json();
    const ips = [];
    const serversInfo = [];
    if (data.LogicalServers && Array.isArray(data.LogicalServers)) {
      for (const logical of data.LogicalServers) {
        if (logical.Servers && Array.isArray(logical.Servers)) {
          for (const srv of logical.Servers) {
            if (srv.EntryIP && isValidIp(srv.EntryIP)) {
              ips.push(srv.EntryIP);
              serversInfo.push({
                ip: srv.EntryIP,
                country: logical.Country || '?',
                name: logical.Name || '?',
                tier: logical.Tier || 0,
                provider: 'protonvpn',
              });
            }
          }
        }
      }
    }
    return { ok: true, ips, count: ips.length, servers: serversInfo };
  } catch (e) {
    return { ok: false, error: e.message, ips: [] };
  }
}

// فچ لیست سرورهای Mozilla VPN — از Mullvad API با فیلتر owner
// در Mullvad API، Mozilla VPN سرورهایی با owner="mozilla" یا provider="moz" هستند
async function fetchMozillaRelays() {
  try {
    const r = await fetch('https://api.mullvad.net/www/relays/all/', {
      signal: AbortSignal.timeout(15000),
      headers: { 'User-Agent': 'cf-worker-cleanip/1.0', 'Accept': 'application/json' },
    });
    if (!r.ok) return { ok: false, error: `HTTP ${r.status}`, ips: [], relays: [] };
    const data = await r.json();
    const ips = [];
    const relaysInfo = [];
    // Mozilla از Mullvad infrastructure استفاده می‌کند، اما سرورهای مخصوص Mozilla
    // معمولاً با hostname شامل "mozilla" یا owner="mozilla" مشخص می‌شوند.
    // در عمل، Mullvad لیست جداگانه ندارد، اما ما می‌توانیم همه را برگردانیم و فیلتر Mozilla را تطبیق دهیم.
    // در اینجا، فیلتر روی شامل بودن "moz" در hostname را اعمال می‌کنیم.
    for (const proto of ['openvpn', 'wireguard', 'bridge']) {
      if (Array.isArray(data[proto])) {
        for (const relay of data[proto]) {
          // Mozilla relays معمولاً owner != "mullvad" هستند
          const isMozilla = relay.owner && (
            relay.owner.toLowerCase().includes('moz') ||
            (relay.hostname && relay.hostname.toLowerCase().includes('moz'))
          );
          if (isMozilla && relay.ipv4_addr_in && isValidIp(relay.ipv4_addr_in)) {
            ips.push(relay.ipv4_addr_in);
            relaysInfo.push({
              ip: relay.ipv4_addr_in,
              country: relay.country || '?',
              city: relay.city || '?',
              hostname: relay.hostname || '?',
              owner: relay.owner || '?',
              protocol: proto,
              provider: 'mozilla',
            });
          }
        }
      }
    }
    // اگر هیچ Mozilla relay پیدا نشد، fallback: همه Mullvad relays را برگردان
    // (با علامت‌گذاری provider=mullvad-for-mozilla)
    if (ips.length === 0) {
      for (const proto of ['wireguard']) {
        if (Array.isArray(data[proto])) {
          for (const relay of data[proto].slice(0, 20)) {
            if (relay.ipv4_addr_in && isValidIp(relay.ipv4_addr_in)) {
              ips.push(relay.ipv4_addr_in);
              relaysInfo.push({
                ip: relay.ipv4_addr_in,
                country: relay.country || '?',
                city: relay.city || '?',
                hostname: relay.hostname || '?',
                owner: relay.owner || '?',
                protocol: proto,
                provider: 'mullvad (fallback for mozilla)',
              });
            }
          }
        }
      }
    }
    return { ok: true, ips, count: ips.length, relays: relaysInfo };
  } catch (e) {
    return { ok: false, error: e.message, ips: [], relays: [] };
  }
}

// تست Apple Private Relay — بررسی دسترسی به دامنه‌های mask.icloud.com
async function fetchAppleRelayEndpoints() {
  const domains = ['mask.icloud.com', 'mask-h2.icloud.com', 'mask-canary.icloud.com'];
  const endpoints = [];
  for (const domain of domains) {
    let reachable = false;
    let status = null;
    let ip = null;
    try {
      const r = await fetch(`https://${domain}/cdn-cgi/trace`, {
        signal: AbortSignal.timeout(8000),
      });
      status = r.status;
      if (r.ok) {
        reachable = true;
        const text = await r.text();
        const ipMatch = text.match(/^ip=(.+)$/m);
        if (ipMatch) ip = ipMatch[1];
      }
    } catch (e) {
      status = 'timeout';
    }
    endpoints.push({ domain, reachable, status, ip, provider: 'apple-private-relay' });
  }
  return { ok: true, endpoints, count: endpoints.length };
}

// Google DNS endpoints (static list)
function getGoogleDnsEndpoints() {
  return {
    ok: true,
    ips: ['8.8.8.8', '8.8.4.4'],
    ipv6: ['2001:4860:4860::8888', '2001:4860:4860::8844'],
    domains: ['dns.google', 'dns.google.com'],
    dohEndpoint: 'https://dns.google/resolve',
    count: 4,
    description: 'Google Public DNS — همیشه تمیز و قابل اعتماد',
  };
}

// تست سرعت Cloudflare برای یک IP
// اندازه‌گیری latency و throughput از speed.cloudflare.com
async function runSpeedTest(ip, bytesToDownload = 1_000_000) {
  const results = {
    latencyMs: null,
    downloadSpeedMbps: null,
    downloadedBytes: 0,
    durationMs: null,
  };
  try {
    // تست latency: HEAD request به speed.cloudflare.com
    const startLatency = Date.now();
    const latencyResp = await fetch('https://speed.cloudflare.com/__down?bytes=100', {
      signal: AbortSignal.timeout(8000),
      method: 'GET',
    });
    await latencyResp.arrayBuffer(); // مصرف body
    results.latencyMs = Date.now() - startLatency;
  } catch (e) { results.latencyError = e.message; }

  try {
    // تست download: دریافت bytes مشخص
    const startDownload = Date.now();
    const dlResp = await fetch(`https://speed.cloudflare.com/__down?bytes=${bytesToDownload}`, {
      signal: AbortSignal.timeout(30000),
      method: 'GET',
    });
    if (dlResp.ok) {
      const buf = await dlResp.arrayBuffer();
      results.downloadedBytes = buf.byteLength;
      results.durationMs = Date.now() - startDownload;
      if (results.durationMs > 0) {
        // throughput در Mbps: bytes * 8 / 1000000 / seconds
        results.downloadSpeedMbps = (results.downloadedBytes * 8 / 1_000_000) / (results.durationMs / 1000);
        results.downloadSpeedMbps = parseFloat(results.downloadSpeedMbps.toFixed(2));
      }
    }
  } catch (e) { results.speedError = e.message; }

  return results;
}

// ===== ثبت IP تمیز توسط کاربر (KV) =====
// ساختار در KV (CLEANIPS_KV):
//   key:   userip:<ip>
//   value: JSON { ip, services, submitterName, timestamp, votesUp, votesDown, verified }
//   key:   userip:list
//   value: JSON array of all submitted IPs (برای لیست سریع)

async function submitCleanIp(env, ip, services, submitterName) {
  if (!env.CLEANIPS_KV) {
    return { ok: false, error: 'CLEANIPS_KV namespace not bound' };
  }
  if (!isValidIp(ip)) {
    return { ok: false, error: 'invalid IP' };
  }
  const key = `userip:${ip}`;
  // بررسی اینکه IP قبلاً ثبت شده یا نه
  const existing = await env.CLEANIPS_KV.get(key);
  let entry;
  if (existing) {
    entry = JSON.parse(existing);
    // اگر submitter جدید، فقط یک بار ثبت کن
    entry.votesUp = (entry.votesUp || 0) + 1;
    entry.lastVotedAt = Date.now();
  } else {
    entry = {
      ip,
      services: services || [],
      submitterName: submitterName || 'anonymous',
      timestamp: Date.now(),
      votesUp: 1,
      votesDown: 0,
      verified: false,
    };
  }
  await env.CLEANIPS_KV.put(key, JSON.stringify(entry));
  return { ok: true, entry };
}

// رای به یک IP ثبت‌شده (up یا down)
async function voteCleanIp(env, ip, vote) {
  if (!env.CLEANIPS_KV) {
    return { ok: false, error: 'CLEANIPS_KV namespace not bound' };
  }
  if (!isValidIp(ip)) {
    return { ok: false, error: 'invalid IP' };
  }
  if (vote !== 'up' && vote !== 'down') {
    return { ok: false, error: 'vote must be up or down' };
  }
  const key = `userip:${ip}`;
  const existing = await env.CLEANIPS_KV.get(key);
  if (!existing) {
    return { ok: false, error: 'IP not found' };
  }
  const entry = JSON.parse(existing);
  if (vote === 'up') entry.votesUp = (entry.votesUp || 0) + 1;
  else entry.votesDown = (entry.votesDown || 0) + 1;
  // تأیید خودکار: اگر ۵ رای مثبت داشت و ۰ منفی، verified = true
  if (entry.votesUp >= 5 && entry.votesDown === 0) entry.verified = true;
  await env.CLEANIPS_KV.put(key, JSON.stringify(entry));
  return { ok: true, entry };
}

// لیست همه IP های ثبت‌شده توسط کاربران
async function listCommunityCleanIps(env) {
  if (!env.CLEANIPS_KV) {
    return { ok: false, error: 'CLEANIPS_KV namespace not bound', ips: [] };
  }
  const list = await env.CLEANIPS_KV.list({ prefix: 'userip:' });
  const ips = [];
  for (const k of list.keys) {
    if (k.name === 'userip:list') continue;
    const raw = await env.CLEANIPS_KV.get(k.name);
    try {
      const entry = JSON.parse(raw);
      ips.push(entry);
    } catch {}
  }
  // مرتب‌سازی بر اساس (votesUp - votesDown) نزولی
  ips.sort((a, b) => ((b.votesUp || 0) - (b.votesDown || 0)) - ((a.votesUp || 0) - (a.votesDown || 0)));
  return { ok: true, ips, count: ips.length };
}

// ===== آمار برای Dashboard =====
// جمع‌آوری آمار از KV برای نمایش نموداری
async function getCommunityStats(env) {
  if (!env.CLEANIPS_KV) {
    return { ok: false, error: 'CLEANIPS_KV namespace not bound' };
  }
  const list = await env.CLEANIPS_KV.list({ prefix: 'userip:' });
  const allIps = [];
  for (const k of list.keys) {
    if (k.name === 'userip:list') continue;
    const raw = await env.CLEANIPS_KV.get(k.name);
    try {
      const entry = JSON.parse(raw);
      allIps.push(entry);
    } catch {}
  }

  // آمار کلی
  const totalIps = allIps.length;
  const verifiedIps = allIps.filter((e) => e.verified).length;
  const totalVotesUp = allIps.reduce((sum, e) => sum + (e.votesUp || 0), 0);
  const totalVotesDown = allIps.reduce((sum, e) => sum + (e.votesDown || 0), 0);
  const totalSubmitters = new Set(allIps.map((e) => e.submitterName || 'anonymous')).size;

  // Top 5 most-voted IPs
  const topVoted = [...allIps]
    .sort((a, b) => ((b.votesUp || 0) - (b.votesDown || 0)) - ((a.votesUp || 0) - (a.votesDown || 0)))
    .slice(0, 5)
    .map((e) => ({ ip: e.ip, votesUp: e.votesUp || 0, votesDown: e.votesDown || 0, verified: e.verified }));

  // Top 5 submitters
  const submitterCounts = {};
  for (const e of allIps) {
    const name = e.submitterName || 'anonymous';
    submitterCounts[name] = (submitterCounts[name] || 0) + 1;
  }
  const topSubmitters = Object.entries(submitterCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([name, count]) => ({ name, count }));

  // توزیع سرویس‌ها — شمارش هر سرویس در services field
  const serviceCounts = {};
  for (const e of allIps) {
    if (Array.isArray(e.services)) {
      for (const svc of e.services) {
        const trimmed = (svc || '').trim();
        if (trimmed) serviceCounts[trimmed] = (serviceCounts[trimmed] || 0) + 1;
      }
    }
  }
  const serviceDistribution = Object.entries(serviceCounts)
    .sort((a, b) => b[1] - a[1])
    .map(([name, count]) => ({ name, count }));

  // توزیع روزانه ثبت‌ها (۷ روز اخیر)
  const now = Date.now();
  const sevenDaysAgo = now - 7 * 24 * 60 * 60 * 1000;
  const dailySubmissions = [];
  for (let i = 6; i >= 0; i--) {
    const dayStart = now - i * 24 * 60 * 60 * 1000;
    const dayEnd = dayStart + 24 * 60 * 60 * 1000;
    const date = new Date(dayStart);
    const dayLabel = `${date.getMonth() + 1}/${date.getDate()}`;
    const count = allIps.filter((e) => e.timestamp >= dayStart && e.timestamp < dayEnd).length;
    dailySubmissions.push({ date: dayLabel, count });
  }

  // توزیع تأیید شده vs تأیید نشده
  const verificationStats = {
    verified: verifiedIps,
    unverified: totalIps - verifiedIps,
  };

  return {
    ok: true,
    stats: {
      totalIps,
      verifiedIps,
      totalVotesUp,
      totalVotesDown,
      totalSubmitters,
      topVoted,
      topSubmitters,
      serviceDistribution,
      dailySubmissions,
      verificationStats,
    },
  };
}

// lookup اطلاعات geolocation برای یک IP
async function lookupIpGeo(ip) {
  const results = {};
  // ip-api.com
  try {
    const r = await fetch(`http://ip-api.com/json/${ip}?fields=country,countryCode,region,city,isp,as,query`, {
      signal: AbortSignal.timeout(8000),
    });
    if (r.ok) {
      const data = await r.json();
      results.ipApi = {
        country: data.country,
        countryCode: data.countryCode,
        region: data.region,
        city: data.city,
        isp: data.isp,
        as: data.as,
      };
    }
  } catch (e) { results.ipApi = { error: e.message }; }
  // ipinfo.io (بدون توکن هم کار می‌کند، اما با محدودیت rate)
  try {
    const r = await fetch(`https://ipinfo.io/${ip}/json`, {
      signal: AbortSignal.timeout(8000),
    });
    if (r.ok) {
      const data = await r.json();
      results.ipinfo = {
        country: data.country,
        region: data.region,
        city: data.city,
        org: data.org,
        hostname: data.hostname,
      };
    }
  } catch (e) { results.ipinfo = { error: e.message }; }
  return results;
}

// تایید اعتبار IP
function isValidIp(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) return false;
  return parts.every((p) => {
    const n = parseInt(p, 10);
    return !isNaN(n) && n >= 0 && n <= 255;
  });
}

// اجرای تست‌های Clean IP روی یک IP — همه سرویس‌ها به‌صورت موازی
async function runCleanIpTests(ip) {
  const promises = CLEAN_IP_SERVICES.map(async (svc) => {
    const result = await svc.test(ip);
    return {
      name: svc.name,
      icon: svc.icon,
      status: result.status,
      detail: result.detail,
      endpoints: svc.endpoints,
    };
  });
  return Promise.all(promises);
}

// فچ IP تصادفی از همه منابع (برای مقایسه)
async function getCleanIpsFromAllSources(env) {
  const results = [];
  // منبع محلی (Cloudflare)
  const local = randomCloudflareIp();
  results.push({
    source: CLEAN_IP_SOURCES[0].name,
    type: 'local',
    ip: local.ip,
    cidr: local.cidr,
    description: CLEAN_IP_SOURCES[0].description,
  });
  // منابع GitHub
  const githubSources = CLEAN_IP_SOURCES.filter((s) => s.type === 'github');
  for (const source of githubSources) {
    const fetched = await fetchIpListFromGithub(source.url);
    if (fetched.ok && fetched.ips.length > 0) {
      const randomIp = fetched.ips[Math.floor(Math.random() * fetched.ips.length)];
      results.push({
        source: source.name,
        type: 'github',
        ip: randomIp,
        count: fetched.count,
        description: source.description,
        url: source.url,
      });
    } else {
      results.push({
        source: source.name,
        type: 'github',
        error: fetched.error,
        description: source.description,
      });
    }
  }
  // منبع Mullvad
  const mullvadSource = CLEAN_IP_SOURCES.find((s) => s.type === 'mullvad');
  const mullvad = await fetchMullvadRelays();
  if (mullvad.ok && mullvad.ips.length > 0) {
    const randomIp = mullvad.ips[Math.floor(Math.random() * mullvad.ips.length)];
    results.push({
      source: mullvadSource.name,
      type: 'mullvad',
      ip: randomIp,
      count: mullvad.count,
      description: mullvadSource.description,
    });
  } else {
    results.push({
      source: mullvadSource.name,
      type: 'mullvad',
      error: mullvad.error,
      description: mullvadSource.description,
    });
  }
  // منبع ProtonVPN
  const protonSource = CLEAN_IP_SOURCES.find((s) => s.type === 'protonvpn');
  const proton = await fetchProtonVpnServers();
  if (proton.ok && proton.ips.length > 0) {
    const randomIp = proton.ips[Math.floor(Math.random() * proton.ips.length)];
    results.push({
      source: protonSource.name,
      type: 'protonvpn',
      ip: randomIp,
      count: proton.count,
      description: protonSource.description,
    });
  } else {
    results.push({
      source: protonSource.name,
      type: 'protonvpn',
      error: proton.error,
      description: protonSource.description,
    });
  }
  // منبع Community (KV)
  if (env && env.CLEANIPS_KV) {
    const community = await listCommunityCleanIps(env);
    if (community.ok && community.ips.length > 0) {
      // IP با بالاترین رای را انتخاب کن
      const top = community.ips[0];
      results.push({
        source: 'Community Submitted (KV)',
        type: 'community',
        ip: top.ip,
        count: community.count,
        votesUp: top.votesUp,
        votesDown: top.votesDown,
        verified: top.verified,
        description: 'IP ثبت‌شده توسط کاربران با رای بالا',
      });
    } else {
      results.push({
        source: 'Community Submitted (KV)',
        type: 'community',
        error: 'No community IPs yet',
        description: 'IP های ثبت‌شده توسط کاربران',
      });
    }
  }
  return results;
}


// صفحه HTML بخش Clean IP (نسخه کامل با منابع متعدد)
function renderCleanIpPage(host) {
  const sourcesList = CLEAN_IP_SOURCES.map((s) => `- ${s.name} (${s.type}): ${s.description}`).join('\\n');
  return `<!DOCTYPE html>
<html dir="rtl" lang="fa">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Clean IP Search — جستجوی IP تمیز (چند منبعی)</title>
<style>
body{font-family:system-ui,-apple-system,sans-serif;background:#0f172a;color:#e2e8f0;padding:24px;line-height:1.7;max-width:1000px;margin:0 auto}
h1{color:#60a5fa;border-bottom:2px solid #334155;padding-bottom:8px}
h2{color:#a78bfa;margin-top:32px}
h3{color:#34d399;margin-top:20px;font-size:16px}
.box{background:#1e293b;border:1px solid #334155;padding:16px;border-radius:8px;margin:12px 0}
input{padding:10px;border-radius:6px;border:1px solid #334155;background:#1e293b;color:#e2e8f0;width:280px;font-family:inherit;font-size:14px}
button{background:#3b82f6;color:white;border:none;padding:10px 16px;border-radius:6px;cursor:pointer;font-family:inherit;margin:4px;font-size:13px}
button:hover{background:#2563eb}
button.success{background:#10b981}
button.success:hover{background:#059669}
button.warning{background:#f59e0b}
button.warning:hover{background:#d97706}
button.secondary{background:#64748b}
button.secondary:hover{background:#475569}
.results{margin-top:24px}
.service{display:flex;align-items:center;padding:12px;border-radius:8px;margin:8px 0;background:#1e293b;border:1px solid #334155}
.service-icon{font-size:22px;margin-left:12px}
.service-name{flex:1;font-weight:bold;font-size:14px}
.service-status{padding:4px 12px;border-radius:4px;font-size:11px;font-weight:bold;min-width:60px;text-align:center}
.status-unlocked{background:#065f46;color:#a7f3d0}
.status-blocked{background:#7f1d1d;color:#fecaca}
.status-unknown{background:#334155;color:#cbd5e1}
.status-error{background:#7c2d12;color:#fed7aa}
.service-detail{margin-left:12px;color:#94a3b8;font-size:11px;font-family:monospace;max-width:300px;text-overflow:ellipsis;overflow:hidden}
.loading{display:none;text-align:center;padding:24px}
.loading.show{display:block}
.spinner{display:inline-block;width:32px;height:32px;border:3px solid #334155;border-radius:50%;border-top-color:#60a5fa;animation:spin 1s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.note{background:#1e3a8a;border:1px solid #3b82f6;color:#dbeafe;padding:12px;border-radius:8px;margin:12px 0;font-size:13px}
.warning-note{background:#78350f;border:1px solid #f59e0b;color:#fef3c7;padding:12px;border-radius:8px;margin:12px 0;font-size:13px}
.ip-display{font-family:monospace;font-size:20px;color:#34d399;text-align:center;padding:16px;background:#1e293b;border-radius:8px;margin:16px 0}
.source-card{background:#1e293b;border:1px solid #334155;padding:12px;border-radius:8px;margin:8px 0}
.source-card h4{margin:0 0 8px 0;color:#60a5fa;font-size:14px}
.source-card .source-meta{color:#94a3b8;font-size:11px;margin-bottom:8px}
.source-card .source-ip{font-family:monospace;color:#34d399;font-size:16px}
.geo-card{background:#1e293b;border:1px solid #334155;padding:14px;border-radius:8px;margin:12px 0}
.geo-card h3{margin:0 0 12px 0;color:#a78bfa;font-size:16px}
.geo-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.geo-item{padding:8px;background:#0f172a;border-radius:6px;border:1px solid #334155}
.geo-item .geo-label{color:#94a3b8;font-size:11px}
.geo-item .geo-value{color:#e2e8f0;font-weight:bold;font-size:13px;margin-top:4px}
.tabs{display:flex;border-bottom:2px solid #334155;margin:16px 0}
.tab{padding:10px 20px;cursor:pointer;border-bottom:2px solid transparent;color:#94a3b8;font-weight:bold;font-size:14px}
.tab.active{color:#60a5fa;border-bottom-color:#60a5fa}
.tab-content{display:none}
.tab-content.active{display:block}
</style>
</head>
<body>
<h1>🔍 Clean IP Search <span style="font-size:14px;color:#94a3b8">(چند منبعی)</span></h1>
<p>جستجو و تست IP تمیز با چندین منبع داده و چندین endpoint تست برای هر سرویس.</p>

<div class="note">
<strong>منابع داده:</strong> لیست IP تمیز از چندین منبع جمع‌آوری می‌شود:
<br>• رنج‌های رسمی Cloudflare (محلی)
<br>• لیست‌های جامعه‌محور در GitHub (vfarid/cf-ip-scanner, ymyuuu/IPDB)
<br>• API های geolocation (ip-api.com, ipinfo.io)
<br>• تست مستقیم endpoint هر سرویس (۱۰+ سرویس)
</div>

<div class="warning-note">
<strong>نکته مهم:</strong> تست‌ها از داخل Worker اجرا می‌شوند و وضعیت IP خود Worker را نشان می‌دهند. برای تست واقعی IP، آن را در کلاینت به‌عنوان SNI/Address تنظیم کنید.
</div>

<div class="tabs">
<div class="tab active" onclick="switchTab('test')">🧪 تست IP</div>
<div class="tab" onclick="switchTab('sources')">📚 منابع داده</div>
<div class="tab" onclick="switchTab('mullvad')">🟢 Mullvad</div>
<div class="tab" onclick="switchTab('proton')">🟣 ProtonVPN</div>
<div class="tab" onclick="switchTab('mozilla')">🦊 Mozilla</div>
<div class="tab" onclick="switchTab('apple')">🍎 Apple</div>
<div class="tab" onclick="switchTab('google')">🔍 Google</div>
<div class="tab" onclick="switchTab('community')">👥 Community</div>
<div class="tab" onclick="switchTab('dashboard')">📊 Dashboard</div>
<div class="tab" onclick="switchTab('speedtest')">⚡ Speed</div>
<div class="tab" onclick="switchTab('ranges')">🌐 رنج‌ها</div>
</div>

<div id="tab-test" class="tab-content active">
<h2>تست IP</h2>
<div class="box">
  <input id="ipInput" placeholder="مثال: 104.16.123.45" />
  <button onclick="testIp()">🧪 تست IP</button>
  <button class="success" onclick="randomIp()">🎲 IP تصادفی Cloudflare</button>
  <button class="warning" onclick="allSourcesIp()">📚 IP از همه منابع</button>
  <button class="secondary" onclick="lookupGeo()">🌍 Geolocation</button>
</div>

<div id="ipDisplay" class="ip-display" style="display:none;"></div>

<div id="loading" class="loading">
  <div class="spinner"></div>
  <p>در حال اجرای تست‌ها... ممکن است ۳۰-۶۰ ثانیه طول بکشد</p>
</div>

<div id="results" class="results"></div>

<div id="geoResults"></div>

<div id="sourcesResults"></div>
</div>

<div id="tab-sources" class="tab-content">
<h2>منابع داده برای Clean IP</h2>
<p>این بخش IP تمیز را از چندین منبع همزمان fetch می‌کند:</p>

<div class="box">
<button class="success" onclick="fetchAllSources()">📚 دریافت IP از همه منابع</button>
<button onclick="listSources()">📋 لیست منابع موجود</button>
</div>

<div id="sourcesList"></div>
<div id="allSourcesResults"></div>
</div>

<div id="tab-mullvad" class="tab-content">
<h2>🟢 سرورهای Mullvad</h2>
<p>سرورهای VPN Mullvad — منبع IP تمیز قابل اعتماد.</p>

<div class="box">
<button class="success" onclick="fetchMullvad()">🟢 دریافت لیست Mullvad</button>
</div>

<div id="mullvadResults"></div>
</div>

<div id="tab-proton" class="tab-content">
<h2>🟣 سرورهای ProtonVPN</h2>
<p>سرورهای منطقی ProtonVPN — EntryIP هر سرور.</p>

<div class="box">
<button class="success" onclick="fetchProton()">🟣 دریافت لیست ProtonVPN</button>
</div>

<div id="protonResults"></div>
</div>

<div id="tab-mozilla" class="tab-content">
<h2>🦊 سرورهای Mozilla VPN</h2>
<p>Mozilla VPN از infrastructure Mullvad استفاده می‌کند. این بخش relays با owner=mozilla را فیلتر می‌کند.</p>

<div class="box">
<button class="success" onclick="fetchMozilla()">🦊 دریافت لیست Mozilla VPN</button>
</div>

<div id="mozillaResults"></div>
</div>

<div id="tab-apple" class="tab-content">
<h2>🍎 Apple Private Relay Endpoints</h2>
<p>دامنه‌های Apple iCloud Private Relay — بررسی دسترسی به mask.icloud.com و مشتقات آن.</p>

<div class="box">
<button class="success" onclick="fetchApple()">🍎 تست Apple Private Relay Endpoints</button>
</div>

<div id="appleResults"></div>
</div>

<div id="tab-google" class="tab-content">
<h2>🔍 Google Public DNS</h2>
<p>IP های Google Public DNS — همیشه تمیز و قابل اعتماد. برای تست دسترسی به سرویس‌های Google.</p>

<div class="box">
<button class="success" onclick="fetchGoogleDns()">🔍 نمایش Google DNS</button>
</div>

<div id="googleResults"></div>
</div>

<div id="tab-community" class="tab-content">
<h2>👥 IP های ثبت‌شده توسط کاربران</h2>
<p>کاربران می‌توانند IP تمیز کشف‌شده را ثبت کنند و دیگران به آن رای دهند.</p>

<h3>ثبت IP جدید</h3>
<div class="box">
  <input id="submitIp" placeholder="IP تمیز" style="width:200px" />
  <input id="submitName" placeholder="نام شما (اختیاری)" style="width:200px" />
  <input id="submitServices" placeholder="سرویس‌های باز (اختیاری)" style="width:300px" />
  <button class="success" onclick="submitIpFunc()">✓ ثبت IP تمیز</button>
</div>

<h3>لیست IP های community</h3>
<div class="box">
  <button onclick="fetchCommunity()">🔄 بارگذاری لیست</button>
</div>

<div id="communityResults"></div>
</div>

<div id="tab-speedtest" class="tab-content">
<h2>⚡ Cloudflare Speed Test</h2>
<p>اندازه‌گیری latency و throughput از Cloudflare speed test endpoint.</p>

<div class="box">
  <label>حجم دانلود (bytes): </label>
  <input id="speedBytes" value="1000000" style="width:120px" />
  <button class="success" onclick="runSpeedTest()">⚡ اجرای تست سرعت</button>
</div>

<div id="speedResults"></div>
</div>

<div id="tab-dashboard" class="tab-content">
<h2>📊 Dashboard آماری Community</h2>
<p>نمودارهای آماری از IP های ثبت‌شده توسط کاربران، رای‌ها، سرویس‌ها و فعالیت روزانه.</p>

<div class="box">
<button class="success" onclick="loadDashboard()">📊 بارگذاری Dashboard</button>
</div>

<div id="dashboardStats"></div>

<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-top:16px">
<div class="box" style="padding:16px">
<h3 style="margin-top:0">📈 ثبت روزانه (۷ روز اخیر)</h3>
<canvas id="dailyChart" height="200"></canvas>
</div>
<div class="box" style="padding:16px">
<h3 style="margin-top:0">🎯 توزیع سرویس‌ها</h3>
<canvas id="servicesChart" height="200"></canvas>
</div>
<div class="box" style="padding:16px">
<h3 style="margin-top:0">✓ توزیع تأیید</h3>
<canvas id="verifiedChart" height="200"></canvas>
</div>
<div class="box" style="padding:16px">
<h3 style="margin-top:0">🏆 Top Submitters</h3>
<canvas id="submittersChart" height="200"></canvas>
</div>
</div>
</div>

<div id="tab-ranges" class="tab-content">
<h2>رنج‌های IP Cloudflare</h2>
<div class="box">
  <p style="font-family:monospace;font-size:12px;color:#94a3b8;line-height:1.8">
    ${CLOUDFLARE_IP_RANGES.join('<br>')}
  </p>
</div>

<h2>سرویس‌های تست‌شونده</h2>
<div class="box">
  <ul style="padding-right:20px;color:#cbd5e1">
    ${CLEAN_IP_SERVICES.map((s) => `<li style="margin:6px 0"><strong>${s.icon} ${s.name}</strong> — ${s.endpoints.length} endpoint</li>`).join('')}
  </ul>
</div>
</div>

<script>
function switchTab(name) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
  event.target.classList.add('active');
  document.getElementById('tab-' + name).classList.add('active');
}

async function testIp() {
  const ip = document.getElementById('ipInput').value.trim();
  if (!ip) { alert('لطفاً IP را وارد کنید'); return; }
  if (!/^\\d+\\.\\d+\\.\\d+\\.\\d+$/.test(ip)) { alert('فرمت IP اشتباه است'); return; }
  await runTests(ip);
}

async function randomIp() {
  document.getElementById('loading').classList.add('show');
  document.getElementById('results').innerHTML = '';
  try {
    const r = await fetch('/cleanip/api/random', { method: 'POST' });
    const data = await r.json();
    if (data.ok) {
      document.getElementById('ipInput').value = data.ip;
      const display = document.getElementById('ipDisplay');
      display.style.display = 'block';
      display.innerHTML = '🎲 IP تصادفی: <strong>' + data.ip + '</strong><br><small style="color:#94a3b8">منبع: ' + data.source + ' | CIDR: ' + data.cidr + '</small>';
    }
  } catch (e) { alert('Error: ' + e.message); }
  document.getElementById('loading').classList.remove('show');
}

async function allSourcesIp() {
  document.getElementById('loading').classList.add('show');
  document.getElementById('sourcesResults').innerHTML = '';
  try {
    const r = await fetch('/cleanip/api/all-sources', { method: 'POST' });
    const data = await r.json();
    if (data.ok) {
      const html = data.sources.map(s => {
        if (s.error) {
          return '<div class="source-card"><h4>❌ ' + s.source + '</h4><div class="source-meta">' + s.description + '</div><div style="color:#fecaca">خطا: ' + s.error + '</div></div>';
        }
        return '<div class="source-card"><h4>✅ ' + s.source + '</h4><div class="source-meta">نوع: ' + s.type + (s.count ? ' | تعداد: ' + s.count + ' IP' : '') + '</div><div class="source-ip">IP: ' + s.ip + '</div><div style="margin-top:8px"><button onclick="document.getElementById(\\'ipInput\\').value=\\'' + s.ip + '\\';testIp();">🧪 تست این IP</button></div></div>';
      }).join('');
      document.getElementById('sourcesResults').innerHTML = '<h3>IP از همه منابع:</h3>' + html;
    }
  } catch (e) { alert('Error: ' + e.message); }
  document.getElementById('loading').classList.remove('show');
}

async function lookupGeo() {
  const ip = document.getElementById('ipInput').value.trim();
  if (!ip) { alert('لطفاً IP را وارد کنید'); return; }
  document.getElementById('loading').classList.add('show');
  document.getElementById('geoResults').innerHTML = '';
  try {
    const r = await fetch('/cleanip/api/geo?ip=' + encodeURIComponent(ip));
    const data = await r.json();
    if (data.ok) {
      const geo = data.geo;
      let html = '<div class="geo-card"><h3>🌍 Geolocation برای ' + ip + '</h3><div class="geo-grid">';
      if (geo.ipApi) {
        html += '<div class="geo-item"><div class="geo-label">ip-api.com</div><div class="geo-value">' + (geo.ipApi.country || '?') + ', ' + (geo.ipApi.city || '?') + '</div><div style="color:#94a3b8;font-size:11px;margin-top:4px">ISP: ' + (geo.ipApi.isp || '?') + '</div></div>';
      }
      if (geo.ipinfo) {
        html += '<div class="geo-item"><div class="geo-label">ipinfo.io</div><div class="geo-value">' + (geo.ipinfo.country || '?') + ', ' + (geo.ipinfo.city || '?') + '</div><div style="color:#94a3b8;font-size:11px;margin-top:4px">Org: ' + (geo.ipinfo.org || '?') + '</div></div>';
      }
      html += '</div></div>';
      document.getElementById('geoResults').innerHTML = html;
    }
  } catch (e) { alert('Error: ' + e.message); }
  document.getElementById('loading').classList.remove('show');
}

async function runTests(ip) {
  document.getElementById('loading').classList.add('show');
  document.getElementById('results').innerHTML = '';
  document.getElementById('geoResults').innerHTML = '';
  try {
    const r = await fetch('/cleanip/api/test?ip=' + encodeURIComponent(ip));
    const data = await r.json();
    if (data.ok) {
      const html = data.results.map(s => {
        const statusClass = 'status-' + s.status;
        const statusText = { unlocked: '✓ باز', blocked: '✗ بلاک', unknown: '? نامشخص', error: '⚠ خطا' }[s.status];
        return '<div class="service">' +
          '<div class="service-icon">' + s.icon + '</div>' +
          '<div class="service-name">' + s.name + '<br><small style="color:#64748b;font-weight:normal">' + s.endpoints.length + ' endpoint</small></div>' +
          '<div class="service-status ' + statusClass + '">' + statusText + '</div>' +
          '<div class="service-detail">' + s.detail + '</div>' +
        '</div>';
      }).join('');
      document.getElementById('results').innerHTML = '<h3>نتایج تست ' + ip + ':</h3>' + html;
      // نمایش geolocation به‌صورت خودکار
      if (data.geo) {
        const geo = data.geo;
        let geoHtml = '<div class="geo-card"><h3>🌍 Geolocation</h3><div class="geo-grid">';
        if (geo.ipApi && !geo.ipApi.error) {
          geoHtml += '<div class="geo-item"><div class="geo-label">ip-api.com</div><div class="geo-value">' + (geo.ipApi.country || '?') + ', ' + (geo.ipApi.city || '?') + '</div><div style="color:#94a3b8;font-size:11px;margin-top:4px">ISP: ' + (geo.ipApi.isp || '?') + '</div></div>';
        }
        if (geo.ipinfo && !geo.ipinfo.error) {
          geoHtml += '<div class="geo-item"><div class="geo-label">ipinfo.io</div><div class="geo-value">' + (geo.ipinfo.country || '?') + ', ' + (geo.ipinfo.city || '?') + '</div><div style="color:#94a3b8;font-size:11px;margin-top:4px">Org: ' + (geo.ipinfo.org || '?') + '</div></div>';
        }
        geoHtml += '</div></div>';
        document.getElementById('geoResults').innerHTML = geoHtml;
      }
    } else {
      document.getElementById('results').innerHTML = '<p>خطا: ' + data.error + '</p>';
    }
  } catch (e) {
    document.getElementById('results').innerHTML = '<p>خطا: ' + e.message + '</p>';
  }
  document.getElementById('loading').classList.remove('show');
}

async function fetchAllSources() {
  document.getElementById('loading').classList.add('show');
  document.getElementById('allSourcesResults').innerHTML = '';
  try {
    const r = await fetch('/cleanip/api/all-sources', { method: 'POST' });
    const data = await r.json();
    if (data.ok) {
      const html = data.sources.map(s => {
        if (s.error) {
          return '<div class="source-card"><h4>❌ ' + s.source + '</h4><div class="source-meta">' + s.description + '</div><div style="color:#fecaca">خطا: ' + s.error + '</div></div>';
        }
        return '<div class="source-card"><h4>✅ ' + s.source + '</h4><div class="source-meta">نوع: ' + s.type + (s.count ? ' | تعداد کل: ' + s.count + ' IP' : '') + '</div><div class="source-ip">IP پیشنهادی: ' + s.ip + '</div><div style="margin-top:8px"><button onclick="document.getElementById(\\'ipInput\\').value=\\'' + s.ip + '\\';switchTab(\\'test\\');testIp();">🧪 تست این IP</button></div></div>';
      }).join('');
      document.getElementById('allSourcesResults').innerHTML = html;
    }
  } catch (e) { alert('Error: ' + e.message); }
  document.getElementById('loading').classList.remove('show');
}

async function listSources() {
  try {
    const r = await fetch('/cleanip/api/sources');
    const data = await r.json();
    if (data.ok) {
      const html = data.sources.map(s => '<div class="source-card"><h4>' + s.name + '</h4><div class="source-meta">نوع: <strong>' + s.type + '</strong></div><div style="color:#cbd5e1;font-size:13px">' + s.description + '</div>' + (s.url ? '<div style="color:#64748b;font-size:11px;margin-top:6px;font-family:monospace">' + s.url + '</div>' : '') + '</div>').join('');
      document.getElementById('sourcesList').innerHTML = html;
    }
  } catch (e) { alert('Error: ' + e.message); }
}

// ===== Mullvad =====
async function fetchMullvad() {
  document.getElementById('loading').classList.add('show');
  document.getElementById('mullvadResults').innerHTML = '';
  try {
    const r = await fetch('/cleanip/api/mullvad');
    const data = await r.json();
    if (data.ok) {
      const html = '<div class="box"><p>تعداد کل: <strong>' + data.count + '</strong> سرور (نمایش ۵۰ سرور اول)</p></div>' +
        data.relays.map(relay => '<div class="source-card"><h4>🟢 ' + relay.hostname + '</h4><div class="source-meta">کشور: ' + relay.country + ' | شهر: ' + relay.city + ' | پروتکل: ' + relay.protocol + '</div><div class="source-ip">IP: ' + relay.ip + '</div><div style="margin-top:8px"><button onclick="document.getElementById(\\'ipInput\\').value=\\'' + relay.ip + '\\';switchTab(\\'test\\');testIp();">🧪 تست این IP</button></div></div>').join('');
      document.getElementById('mullvadResults').innerHTML = html;
    } else {
      document.getElementById('mullvadResults').innerHTML = '<div class="box"><p style="color:#fecaca">خطا: ' + data.error + '</p></div>';
    }
  } catch (e) { alert('Error: ' + e.message); }
  document.getElementById('loading').classList.remove('show');
}

// ===== ProtonVPN =====
async function fetchProton() {
  document.getElementById('loading').classList.add('show');
  document.getElementById('protonResults').innerHTML = '';
  try {
    const r = await fetch('/cleanip/api/protonvpn');
    const data = await r.json();
    if (data.ok) {
      const tierText = { 0: 'Free', 1: 'Basic', 2: 'Plus', 3: 'Visionary' };
      const html = '<div class="box"><p>تعداد کل: <strong>' + data.count + '</strong> سرور (نمایش ۵۰ سرور اول)</p></div>' +
        data.servers.map(srv => '<div class="source-card"><h4>🟣 ' + srv.name + '</h4><div class="source-meta">کشور: ' + srv.country + ' | Tier: ' + (tierText[srv.tier] || srv.tier) + '</div><div class="source-ip">EntryIP: ' + srv.ip + '</div><div style="margin-top:8px"><button onclick="document.getElementById(\\'ipInput\\').value=\\'' + srv.ip + '\\';switchTab(\\'test\\');testIp();">🧪 تست این IP</button></div></div>').join('');
      document.getElementById('protonResults').innerHTML = html;
    } else {
      document.getElementById('protonResults').innerHTML = '<div class="box"><p style="color:#fecaca">خطا: ' + data.error + '</p></div>';
    }
  } catch (e) { alert('Error: ' + e.message); }
  document.getElementById('loading').classList.remove('show');
}

// ===== Community =====
async function submitIpFunc() {
  const ip = document.getElementById('submitIp').value.trim();
  const name = document.getElementById('submitName').value.trim();
  const services = document.getElementById('submitServices').value.trim();
  if (!ip) { alert('لطفاً IP را وارد کنید'); return; }
  if (!/^\\d+\\.\\d+\\.\\d+\\.\\d+$/.test(ip)) { alert('فرمت IP اشتباه است'); return; }
  try {
    const r = await fetch('/cleanip/api/submit', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip, name, services: services ? services.split(',') : [] }),
    });
    const data = await r.json();
    if (data.ok) {
      alert('✅ IP ثبت شد! رای مثبت شما اضافه شد.');
      document.getElementById('submitIp').value = '';
      document.getElementById('submitName').value = '';
      document.getElementById('submitServices').value = '';
      fetchCommunity();
    } else {
      alert('❌ خطا: ' + data.error);
    }
  } catch (e) { alert('Error: ' + e.message); }
}

async function fetchCommunity() {
  document.getElementById('loading').classList.add('show');
  document.getElementById('communityResults').innerHTML = '';
  try {
    const r = await fetch('/cleanip/api/community');
    const data = await r.json();
    if (data.ok) {
      if (data.count === 0) {
        document.getElementById('communityResults').innerHTML = '<div class="box"><p style="color:#94a3b8">هنوز IP ثبت‌شده‌ای وجود ندارد. اولین نفر باشید!</p></div>';
      } else {
        const html = '<div class="box"><p>تعداد کل: <strong>' + data.count + '</strong> IP</p></div>' +
          data.ips.map(entry => {
            const date = new Date(entry.timestamp).toLocaleDateString('fa-IR');
            const verifiedBadge = entry.verified ? '<span style="background:#10b981;color:white;padding:2px 8px;border-radius:4px;font-size:10px;margin-right:6px">✓ تأیید شده</span>' : '';
            return '<div class="source-card"><h4>' + verifiedBadge + entry.ip + '</h4><div class="source-meta">ارسال توسط: ' + entry.submitterName + ' | تاریخ: ' + date + '</div>' +
              (entry.services && entry.services.length > 0 ? '<div style="color:#cbd5e1;font-size:12px;margin:6px 0">سرویس‌ها: ' + entry.services.join(', ') + '</div>' : '') +
              '<div style="margin-top:8px"><span style="color:#10b981">👍 ' + (entry.votesUp || 0) + '</span> <span style="color:#ef4444;margin-right:12px">👎 ' + (entry.votesDown || 0) + '</span>' +
              '<button style="margin-right:12px" onclick="voteIp(\\'' + entry.ip + '\\',\\'up\\')">👍 رای مثبت</button>' +
              '<button onclick="voteIp(\\'' + entry.ip + '\\',\\'down\\')">👎 رای منفی</button>' +
              '<button class="secondary" onclick="document.getElementById(\\'ipInput\\').value=\\'' + entry.ip + '\\';switchTab(\\'test\\');testIp();">🧪 تست</button></div></div>';
          }).join('');
        document.getElementById('communityResults').innerHTML = html;
      }
    } else {
      document.getElementById('communityResults').innerHTML = '<div class="box"><p style="color:#fecaca">خطا: ' + data.error + '</p></div>';
    }
  } catch (e) { alert('Error: ' + e.message); }
  document.getElementById('loading').classList.remove('show');
}

async function voteIp(ip, vote) {
  try {
    const r = await fetch('/cleanip/api/vote', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip, vote }),
    });
    const data = await r.json();
    if (data.ok) {
      fetchCommunity();
    } else {
      alert('❌ خطا: ' + data.error);
    }
  } catch (e) { alert('Error: ' + e.message); }
}

// ===== Speed Test =====
async function runSpeedTest() {
  const bytes = parseInt(document.getElementById('speedBytes').value) || 1000000;
  document.getElementById('loading').classList.add('show');
  document.getElementById('speedResults').innerHTML = '';
  try {
    const r = await fetch('/cleanip/api/speedtest?bytes=' + bytes);
    const data = await r.json();
    if (data.ok) {
      const speedMbps = data.downloadSpeedMbps !== null ? data.downloadSpeedMbps + ' Mbps' : 'نامشخص';
      const html = '<div class="geo-card"><h3>⚡ نتایج تست سرعت</h3><div class="geo-grid">' +
        '<div class="geo-item"><div class="geo-label">Latency</div><div class="geo-value">' + (data.latencyMs || '?') + ' ms</div></div>' +
        '<div class="geo-item"><div class="geo-label">Download Speed</div><div class="geo-value">' + speedMbps + '</div></div>' +
        '<div class="geo-item"><div class="geo-label">Downloaded</div><div class="geo-value">' + (data.downloadedBytes / 1000).toFixed(0) + ' KB</div></div>' +
        '<div class="geo-item"><div class="geo-label">Duration</div><div class="geo-value">' + (data.durationMs || '?') + ' ms</div></div>' +
        '</div></div>';
      document.getElementById('speedResults').innerHTML = html;
    } else {
      document.getElementById('speedResults').innerHTML = '<div class="box"><p style="color:#fecaca">خطا: ' + data.error + '</p></div>';
    }
  } catch (e) { alert('Error: ' + e.message); }
  document.getElementById('loading').classList.remove('show');
}

// ===== Mozilla =====
async function fetchMozilla() {
  document.getElementById('loading').classList.add('show');
  document.getElementById('mozillaResults').innerHTML = '';
  try {
    const r = await fetch('/cleanip/api/mozilla');
    const data = await r.json();
    if (data.ok) {
      const html = '<div class="box"><p>تعداد کل: <strong>' + data.count + '</strong> سرور Mozilla (نمایش ۵۰ سرور اول)</p></div>' +
        data.relays.map(relay => '<div class="source-card"><h4>🦊 ' + relay.hostname + '</h4><div class="source-meta">کشور: ' + relay.country + ' | شهر: ' + relay.city + ' | Owner: ' + relay.owner + ' | پروتکل: ' + relay.protocol + '</div><div class="source-ip">IP: ' + relay.ip + '</div><div style="margin-top:8px"><button onclick="document.getElementById(\\'ipInput\\').value=\\'' + relay.ip + '\\';switchTab(\\'test\\');testIp();">🧪 تست این IP</button></div></div>').join('');
      document.getElementById('mozillaResults').innerHTML = html;
    } else {
      document.getElementById('mozillaResults').innerHTML = '<div class="box"><p style="color:#fecaca">خطا: ' + data.error + '</p></div>';
    }
  } catch (e) { alert('Error: ' + e.message); }
  document.getElementById('loading').classList.remove('show');
}

// ===== Apple Private Relay =====
async function fetchApple() {
  document.getElementById('loading').classList.add('show');
  document.getElementById('appleResults').innerHTML = '';
  try {
    const r = await fetch('/cleanip/api/apple');
    const data = await r.json();
    if (data.ok) {
      const html = '<div class="box"><p>تعداد endpoint ها: <strong>' + data.count + '</strong></p></div>' +
        data.endpoints.map(ep => {
          const statusIcon = ep.reachable ? '✅' : '❌';
          const statusColor = ep.reachable ? '#a7f3d0' : '#fecaca';
          return '<div class="source-card"><h4>🍎 ' + statusIcon + ' ' + ep.domain + '</h4><div class="source-meta">Reachable: <strong style="color:' + statusColor + '">' + (ep.reachable ? 'بله' : 'خیر') + '</strong> | Status: ' + ep.status + '</div>' + (ep.ip ? '<div class="source-ip">IP: ' + ep.ip + '</div>' : '') + '</div>';
        }).join('');
      document.getElementById('appleResults').innerHTML = html;
    } else {
      document.getElementById('appleResults').innerHTML = '<div class="box"><p style="color:#fecaca">خطا: ' + data.error + '</p></div>';
    }
  } catch (e) { alert('Error: ' + e.message); }
  document.getElementById('loading').classList.remove('show');
}

// ===== Google DNS =====
async function fetchGoogleDns() {
  try {
    const r = await fetch('/cleanip/api/google-dns');
    const data = await r.json();
    if (data.ok) {
      const html = '<div class="box"><p>تعداد: <strong>' + data.count + '</strong> endpoint</p><p style="color:#94a3b8;font-size:13px">' + data.description + '</p></div>' +
        '<div class="source-card"><h4>IPv4</h4><div class="source-ip">' + data.ips.join('<br>') + '</div></div>' +
        '<div class="source-card"><h4>IPv6</h4><div class="source-ip">' + data.ipv6.join('<br>') + '</div></div>' +
        '<div class="source-card"><h4>Domains</h4><div class="source-ip">' + data.domains.join('<br>') + '</div></div>' +
        '<div class="source-card"><h4>DoH Endpoint</h4><div class="source-ip">' + data.dohEndpoint + '</div></div>';
      document.getElementById('googleResults').innerHTML = html;
    }
  } catch (e) { alert('Error: ' + e.message); }
}

// ===== Dashboard با Chart.js =====
let chartDaily, chartServices, chartVerified, chartSubmitters;

async function loadDashboard() {
  document.getElementById('loading').classList.add('show');
  document.getElementById('dashboardStats').innerHTML = '';
  try {
    const r = await fetch('/cleanip/api/stats');
    const data = await r.json();
    if (data.ok) {
      const s = data.stats;
      const html = '<div class="geo-card"><h3>📊 آمار کلی</h3><div class="geo-grid">' +
        '<div class="geo-item"><div class="geo-label">کل IP ها</div><div class="geo-value">' + s.totalIps + '</div></div>' +
        '<div class="geo-item"><div class="geo-label">IP های تأیید شده</div><div class="geo-value">' + s.verifiedIps + '</div></div>' +
        '<div class="geo-item"><div class="geo-label">کل رای مثبت</div><div class="geo-value" style="color:#10b981">' + s.totalVotesUp + '</div></div>' +
        '<div class="geo-item"><div class="geo-label">کل رای منفی</div><div class="geo-value" style="color:#ef4444">' + s.totalVotesDown + '</div></div>' +
        '<div class="geo-item"><div class="geo-label">تعداد ارسال‌کنندگان</div><div class="geo-value">' + s.totalSubmitters + '</div></div>' +
        '</div></div>';
      document.getElementById('dashboardStats').innerHTML = html;

      // نمایش Top 5 IP های با رای بالا
      if (s.topVoted && s.topVoted.length > 0) {
        const topHtml = '<div class="box" style="margin-top:16px"><h3>🏆 Top 5 IP های با رای بالا</h3>' +
          s.topVoted.map((t, i) => '<div class="source-card"><h4>#' + (i+1) + ' ' + (t.verified ? '✓ ' : '') + t.ip + '</h4><div class="source-meta">👍 ' + t.votesUp + ' | 👎 ' + t.votesDown + '</div></div>').join('') +
          '</div>';
        document.getElementById('dashboardStats').innerHTML += topHtml;
      }

      // رسم نمودارها
      drawDailyChart(s.dailySubmissions);
      drawServicesChart(s.serviceDistribution);
      drawVerifiedChart(s.verificationStats);
      drawSubmittersChart(s.topSubmitters);
    } else {
      document.getElementById('dashboardStats').innerHTML = '<div class="box"><p style="color:#fecaca">خطا: ' + data.error + '</p></div>';
    }
  } catch (e) { alert('Error: ' + e.message); }
  document.getElementById('loading').classList.remove('show');
}

function drawDailyChart(data) {
  const ctx = document.getElementById('dailyChart');
  if (chartDaily) chartDaily.destroy();
  if (!data || data.length === 0) return;
  chartDaily = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: data.map(d => d.date),
      datasets: [{
        label: 'ثبت IP در روز',
        data: data.map(d => d.count),
        backgroundColor: '#3b82f6',
        borderColor: '#60a5fa',
        borderWidth: 1
      }]
    },
    options: {
      responsive: true,
      plugins: { legend: { labels: { color: '#e2e8f0' } } },
      scales: {
        x: { ticks: { color: '#94a3b8' }, grid: { color: '#334155' } },
        y: { ticks: { color: '#94a3b8' }, grid: { color: '#334155' }, beginAtZero: true }
      }
    }
  });
}

function drawServicesChart(data) {
  const ctx = document.getElementById('servicesChart');
  if (chartServices) chartServices.destroy();
  if (!data || data.length === 0) return;
  const colors = ['#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#a78bfa', '#06b6d4', '#ec4899', '#84cc16'];
  chartServices = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: data.map(d => d.name),
      datasets: [{
        data: data.map(d => d.count),
        backgroundColor: colors.slice(0, data.length),
        borderColor: '#1e293b',
        borderWidth: 2
      }]
    },
    options: {
      responsive: true,
      plugins: { legend: { labels: { color: '#e2e8f0', font: { size: 10 } }, position: 'right' } }
    }
  });
}

function drawVerifiedChart(data) {
  const ctx = document.getElementById('verifiedChart');
  if (chartVerified) chartVerified.destroy();
  if (!data) return;
  chartVerified = new Chart(ctx, {
    type: 'pie',
    data: {
      labels: ['تأیید شده ✓', 'تأیید نشده'],
      datasets: [{
        data: [data.verified, data.unverified],
        backgroundColor: ['#10b981', '#64748b'],
        borderColor: '#1e293b',
        borderWidth: 2
      }]
    },
    options: {
      responsive: true,
      plugins: { legend: { labels: { color: '#e2e8f0' }, position: 'right' } }
    }
  });
}

function drawSubmittersChart(data) {
  const ctx = document.getElementById('submittersChart');
  if (chartSubmitters) chartSubmitters.destroy();
  if (!data || data.length === 0) return;
  chartSubmitters = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: data.map(d => d.name),
      datasets: [{
        label: 'تعداد IP ثبت‌شده',
        data: data.map(d => d.count),
        backgroundColor: '#a78bfa',
        borderColor: '#c4b5fd',
        borderWidth: 1
      }]
    },
    options: {
      indexAxis: 'y',
      responsive: true,
      plugins: { legend: { labels: { color: '#e2e8f0' } } },
      scales: {
        x: { ticks: { color: '#94a3b8' }, grid: { color: '#334155' }, beginAtZero: true },
        y: { ticks: { color: '#94a3b8' }, grid: { color: '#334155' } }
      }
    }
  });
}
</script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
</body>
</html>`;
}

// هندلر مسیرهای Clean IP
async function handleCleanIp(request, env, ctx) {
  const url = new URL(request.url);
  const cleanIpPath = (env && env.CLEANIP_PATH) || DEFAULTS.CLEANIP_PATH;

  // صفحه اصلی
  if (url.pathname === `/${cleanIpPath}` || url.pathname === `/${cleanIpPath}/`) {
    return new Response(renderCleanIpPage(url.hostname), {
      headers: { 'Content-Type': 'text/html; charset=utf-8' },
    });
  }

  // API: تست IP
  if (url.pathname === `/${cleanIpPath}/api/test`) {
    const ip = url.searchParams.get('ip');
    if (!ip || !isValidIp(ip)) {
      return new Response(JSON.stringify({ ok: false, error: 'invalid ip' }), {
        headers: { 'Content-Type': 'application/json' },
      });
    }
    // تست‌های سرویس + geolocation به‌صورت موازی
    const [serviceResults, geo] = await Promise.all([
      runCleanIpTests(ip),
      lookupIpGeo(ip),
    ]);
    return new Response(JSON.stringify({ ok: true, ip, results: serviceResults, geo }), {
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // API: تولید IP تصادفی Cloudflare (منبع محلی)
  if (url.pathname === `/${cleanIpPath}/api/random` && request.method === 'POST') {
    const { ip, cidr, source } = randomCloudflareIp();
    return new Response(JSON.stringify({ ok: true, ip, cidr, source }), {
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // API: دریافت IP تمیز از همه منابع (محلی + GitHub + Mullvad + ProtonVPN + Community)
  if (url.pathname === `/${cleanIpPath}/api/all-sources` && request.method === 'POST') {
    const results = await getCleanIpsFromAllSources(env);
    return new Response(JSON.stringify({ ok: true, sources: results }), {
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // API: فچ لیست کامل از یک منبع GitHub مشخص
  if (url.pathname === `/${cleanIpPath}/api/source-list`) {
    const sourceName = url.searchParams.get('source');
    const source = CLEAN_IP_SOURCES.find((s) => s.name === sourceName && s.type === 'github');
    if (!source) {
      return new Response(JSON.stringify({ ok: false, error: 'source not found' }), {
        headers: { 'Content-Type': 'application/json' },
      });
    }
    const fetched = await fetchIpListFromGithub(source.url);
    return new Response(JSON.stringify({ ok: fetched.ok, ...fetched, source: source.name }), {
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // API: فچ لیست سرورهای Mullvad
  if (url.pathname === `/${cleanIpPath}/api/mullvad`) {
    const result = await fetchMullvadRelays();
    // محدود کردن به ۵۰ سرور اول برای جلوگیری از پاسخ بزرگ
    const limitedRelays = result.relays ? result.relays.slice(0, 50) : [];
    return new Response(JSON.stringify({
      ok: result.ok,
      count: result.count,
      error: result.error,
      relays: limitedRelays,
    }), {
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // API: فچ لیست سرورهای ProtonVPN
  if (url.pathname === `/${cleanIpPath}/api/protonvpn`) {
    const result = await fetchProtonVpnServers();
    const limitedServers = result.servers ? result.servers.slice(0, 50) : [];
    return new Response(JSON.stringify({
      ok: result.ok,
      count: result.count,
      error: result.error,
      servers: limitedServers,
    }), {
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // API: تست سرعت Cloudflare (latency + throughput)
  if (url.pathname === `/${cleanIpPath}/api/speedtest`) {
    const bytes = parseInt(url.searchParams.get('bytes') || '1000000', 10);
    const result = await runSpeedTest(null, Math.min(bytes, 10_000_000));
    return new Response(JSON.stringify({ ok: true, ...result }), {
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // API: ثبت IP تمیز توسط کاربر
  if (url.pathname === `/${cleanIpPath}/api/submit` && request.method === 'POST') {
    let body;
    try { body = await request.json(); }
    catch { return new Response(JSON.stringify({ ok: false, error: 'invalid JSON' }), { headers: { 'Content-Type': 'application/json' } }); }
    if (!body.ip) {
      return new Response(JSON.stringify({ ok: false, error: 'ip required' }), {
        headers: { 'Content-Type': 'application/json' },
      });
    }
    const result = await submitCleanIp(env, body.ip, body.services || [], body.name);
    return new Response(JSON.stringify(result), {
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // API: رای‌گیری برای یک IP ثبت‌شده
  if (url.pathname === `/${cleanIpPath}/api/vote` && request.method === 'POST') {
    let body;
    try { body = await request.json(); }
    catch { return new Response(JSON.stringify({ ok: false, error: 'invalid JSON' }), { headers: { 'Content-Type': 'application/json' } }); }
    if (!body.ip || !body.vote) {
      return new Response(JSON.stringify({ ok: false, error: 'ip and vote required' }), {
        headers: { 'Content-Type': 'application/json' },
      });
    }
    const result = await voteCleanIp(env, body.ip, body.vote);
    return new Response(JSON.stringify(result), {
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // API: لیست IP های ثبت‌شده توسط کاربران (community)
  if (url.pathname === `/${cleanIpPath}/api/community`) {
    const result = await listCommunityCleanIps(env);
    return new Response(JSON.stringify(result), {
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // API: آمار کامل برای dashboard (با نمودار)
  if (url.pathname === `/${cleanIpPath}/api/stats`) {
    const result = await getCommunityStats(env);
    return new Response(JSON.stringify(result), {
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // API: فچ لیست سرورهای Mozilla VPN
  if (url.pathname === `/${cleanIpPath}/api/mozilla`) {
    const result = await fetchMozillaRelays();
    const limitedRelays = result.relays ? result.relays.slice(0, 50) : [];
    return new Response(JSON.stringify({
      ok: result.ok,
      count: result.count,
      error: result.error,
      relays: limitedRelays,
    }), {
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // API: تست Apple Private Relay endpoints
  if (url.pathname === `/${cleanIpPath}/api/apple`) {
    const result = await fetchAppleRelayEndpoints();
    return new Response(JSON.stringify(result), {
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // API: Google DNS endpoints
  if (url.pathname === `/${cleanIpPath}/api/google-dns`) {
    const result = getGoogleDnsEndpoints();
    return new Response(JSON.stringify(result), {
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // API: لیست همه منابع موجود
  if (url.pathname === `/${cleanIpPath}/api/sources`) {
    const sourcesInfo = CLEAN_IP_SOURCES.map((s) => ({
      name: s.name,
      type: s.type,
      description: s.description,
      url: s.url || null,
    }));
    return new Response(JSON.stringify({ ok: true, sources: sourcesInfo }), {
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // API: geolocation یک IP
  if (url.pathname === `/${cleanIpPath}/api/geo`) {
    const ip = url.searchParams.get('ip');
    if (!ip || !isValidIp(ip)) {
      return new Response(JSON.stringify({ ok: false, error: 'invalid ip' }), {
        headers: { 'Content-Type': 'application/json' },
      });
    }
    const geo = await lookupIpGeo(ip);
    return new Response(JSON.stringify({ ok: true, ip, geo }), {
      headers: { 'Content-Type': 'application/json' },
    });
  }

  return new Response('Not Found', { status: 404 });
}



// ===== ByteReader (همان v2) =====
class ByteReader {
  constructor(reader) { this.reader = reader; this.buf = new Uint8Array(0); }
  async ensure(n) {
    while (this.buf.length < n) {
      const { value, done } = await this.reader.read();
      if (done) return false;
      const merged = new Uint8Array(this.buf.length + value.length);
      merged.set(this.buf);
      merged.set(value, this.buf.length);
      this.buf = merged;
    }
    return true;
  }
  async read(n) {
    if (!(await this.ensure(n))) return null;
    const out = this.buf.slice(0, n);
    this.buf = this.buf.slice(n);
    return out;
  }
  remaining() { return this.buf; }
}

// ===== dial (TCP از طریق cloudflare:sockets) =====
async function dial(addr, port) {
  try {
    const { connect } = await import('cloudflare:sockets');
    return connect({ hostname: addr, port: port });
  } catch (e) {
    console.error('dial failed:', e);
    return null;
  }
}

// ===== پشتیبانی چندکاربره (KV) =====
// ساختار در KV (USERS_KV):
//   key:   uuid (مثلاً "d342d11e-d424-...")
//   value: JSON { trojanPass, ssPass, ss2022Pass, name, enabled }
// یا برای حالت تک‌کاربره، متغیرهای env مستقیماً استفاده می‌شوند.

async function getUserConfig(env, uuid) {
  if (!env.USERS_KV) {
    // حالت تک‌کاربره
    if (uuid === ((env && env.UUID) || DEFAULTS.UUID)) {
      return {
        uuid,
        trojanPass: (env && env.TROJAN_PASSWORD) || DEFAULTS.TROJAN_PASSWORD,
        ssPass: (env && env.SS_PASSWORD) || DEFAULTS.SS_PASSWORD,
        ss2022Pass: (env && env.SS2022_PASSWORD) || DEFAULTS.SS2022_PASSWORD,
        name: ((env && env.NAME) || DEFAULTS.NAME),
        enabled: true,
      };
    }
    return null;
  }
  const raw = await env.USERS_KV.get(uuid);
  if (!raw) return null;
  try {
    const cfg = JSON.parse(raw);
    if (!cfg.enabled) return null;
    return cfg;
  } catch { return null; }
}

// لیست همه کاربران (برای پنل مدیریت)
async function listUsers(env) {
  if (!env.USERS_KV) {
    return [{
      uuid: (env && env.UUID) || DEFAULTS.UUID,
      name: (env && env.NAME) || DEFAULTS.NAME,
      enabled: true,
    }];
  }
  const list = await env.USERS_KV.list();
  const users = [];
  for (const k of list.keys) {
    const raw = await env.USERS_KV.get(k.name);
    try {
      const cfg = JSON.parse(raw);
      users.push({ uuid: k.name, name: cfg.name || 'unnamed', enabled: cfg.enabled !== false });
    } catch {}
  }
  return users;
}

// افزودن کاربر جدید
async function addUser(env, uuid, cfg) {
  if (!env.USERS_KV) return { ok: false, error: 'KV not bound' };
  await env.USERS_KV.put(uuid, JSON.stringify(cfg));
  return { ok: true };
}

// حذف کاربر
async function deleteUser(env, uuid) {
  if (!env.USERS_KV) return { ok: false, error: 'KV not bound' };
  await env.USERS_KV.delete(uuid);
  return { ok: true };
}

// ===== آمار مصرف =====
// ساختار در KV (STATS_KV):
//   key:   stats:{uuid}:current
//   value: JSON { upload, download, total, lastReset }
//   key:   stats:{uuid}:history:{month}
//   value: JSON { upload, download, total }

async function updateStats(env, uuid, upload, download) {
  if (!env.STATS_KV) return;
  const key = `stats:${uuid}:current`;
  const raw = await env.STATS_KV.get(key);
  let stats = raw ? JSON.parse(raw) : { upload: 0, download: 0, total: 0, lastReset: Date.now() };
  stats.upload += upload;
  stats.download += download;
  stats.total += upload + download;
  await env.STATS_KV.put(key, JSON.stringify(stats));
}

async function getUserStats(env, uuid) {
  if (!env.STATS_KV) {
    return { upload: 0, download: 0, total: 0 };
  }
  const raw = await env.STATS_KV.get(`stats:${uuid}:current`);
  if (!raw) return { upload: 0, download: 0, total: 0 };
  try { return JSON.parse(raw); } catch { return { upload: 0, download: 0, total: 0 }; }
}

// ===== Shadowsocks کلاسیک (aes-128-gcm) =====
// (همان v2، خلاصه)
async function ssDeriveKey(password) {
  const passwordBytes = new TextEncoder().encode(password);
  // در Workers، crypto.subtle.digest('MD5', ...) پشتیبانی می‌شود
  const md5Digest = await crypto.subtle.digest('MD5', passwordBytes);
  return new Uint8Array(md5Digest);
}

async function ssAesGcmDecrypt(key, iv, ciphertext) {
  const cryptoKey = await crypto.subtle.importKey('raw', key, { name: 'AES-GCM' }, false, ['decrypt']);
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, tagLength: 128 }, cryptoKey, ciphertext);
  return new Uint8Array(plaintext);
}

async function ssAesGcmEncrypt(key, iv, plaintext) {
  const cryptoKey = await crypto.subtle.importKey('raw', key, { name: 'AES-GCM' }, false, ['encrypt']);
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, tagLength: 128 }, cryptoKey, plaintext);
  return new Uint8Array(ciphertext);
}

function randomIv() {
  const iv = new Uint8Array(12);
  crypto.getRandomValues(iv);
  return iv;
}

// ===== Shadowsocks 2022 =====
// تفاوت با SS کلاسیک:
//   - کلید: blake3(base64-decoded-password) به‌جای MD5
//   - هر بسته با nonce تصادفی ۱۲ بایتی رمز می‌شود (همان GCM)
//   - nonce به ابتدای ciphertext اضافه می‌شود
//   - سرآیند اولیه شامل SOCKS5 addr با اطلاعاتی برای replay protection

async function ss2022DeriveKey(passwordBase64, keyLen = 32) {
  // در محیط Workers، import از blake3.js
  return deriveSS2022Key(passwordBase64, keyLen);
}

// رمزگشایی SS 2022: nonce(12) + ciphertext
async function ss2022Decrypt(key, data) {
  if (data.length < 13) return null;
  const nonce = data.slice(0, 12);
  const cipher = data.slice(12);
  try {
    return await ssAesGcmDecrypt(key, nonce, cipher);
  } catch { return null; }
}

// رمزگذاری SS 2022: nonce(12) + ciphertext
async function ss2022Encrypt(key, plaintext) {
  const nonce = randomIv();
  const cipher = await ssAesGcmEncrypt(key, nonce, plaintext);
  const out = new Uint8Array(12 + cipher.length);
  out.set(nonce, 0);
  out.set(cipher, 12);
  return out;
}

// پارس سرآیند اولیه SS/SS2022: atype | addr | port | payload
function parseSsHeader(plain) {
  if (plain.length < 1) return null;
  const atype = plain[0];
  let addr, addrLen;
  if (atype === 1) {
    if (plain.length < 7) return null;
    addr = `${plain[1]}.${plain[2]}.${plain[3]}.${plain[4]}`;
    addrLen = 5;
  } else if (atype === 3) {
    if (plain.length < 2) return null;
    const len = plain[1];
    if (plain.length < 2 + len + 2) return null;
    addr = new TextDecoder().decode(plain.slice(2, 2 + len));
    addrLen = 2 + len;
  } else if (atype === 4) {
    if (plain.length < 19) return null;
    const parts = [];
    for (let i = 1; i < 17; i += 2) parts.push(((plain[i] << 8) | plain[i + 1]).toString(16));
    addr = `[${parts.join(':')}]`;
    addrLen = 17;
  } else { return null; }
  const port = (plain[addrLen] << 8) | plain[addrLen + 1];
  const payload = plain.slice(addrLen + 2);
  return { addr, port, payload };
}

// ===== هندلر Shadowsocks (هر دو نسخه) =====
async function handleShadowsocks(ws, userCfg, env, ctx) {
  ws.accept();
  // تصمیم: اگر ss2022Pass تنظیم شده و کلاینت از فرمت 2022 استفاده می‌کند، از آن استفاده کن.
  // در عمل، کلاینت SS 2022 nonce را به‌صورت ۱۲ بایت ابتدا می‌فرستد و سپس fixed-length header.
  // برای سادگی، اینجا هر دو حالت را پشتیبانی می‌کنیم: اول تلاش با SS 2022، اگر شکست خورد SS کلاسیک.

  const queue = [];
  let resolver = null;
  const onMessage = async (ev) => {
    const buf = ev.data instanceof ArrayBuffer ? ev.data : await ev.data.arrayBuffer();
    queue.push(new Uint8Array(buf));
    if (resolver) { resolver(); resolver = null; }
  };
  ws.addEventListener('message', onMessage);
  const fakeReader = {
    read: async () => {
      if (queue.length === 0) await new Promise((r) => { resolver = r; });
      return { value: queue.shift(), done: false };
    },
  };

  // اولین پیام: باید حداقل ۱۲ بایت (nonce) + ۱۶ بایت (header encrypted) داشته باشد.
  const firstMsg = await fakeReader.read();
  if (!firstMsg || !firstMsg.value) { ws.close(1008, 'no ss data'); return; }
  const data = firstMsg.value;

  // تلاش با SS 2022
  if (userCfg.ss2022Pass) {
    const key2022 = await ss2022DeriveKey(userCfg.ss2022Pass, 32);
    const plain = await ss2022Decrypt(key2022, data);
    if (plain) {
      const header = parseSsHeader(plain);
      if (header) {
        await ssPipe(ws, key2022, header, env, userCfg, ctx, 'ss2022');
        return;
      }
    }
  }

  // تلاش با SS کلاسیک (aes-128-gcm)
  if (userCfg.ssPass) {
    const keyClassic = await ssDeriveKey(userCfg.ssPass);
    if (data.length < 12) { ws.close(1008, 'too short'); return; }
    const iv = data.slice(0, 12);
    const cipher = data.slice(12);
    try {
      const plain = await ssAesGcmDecrypt(keyClassic, iv, cipher);
      const header = parseSsHeader(plain);
      if (header) {
        await ssPipe(ws, keyClassic, header, env, userCfg, ctx, 'ss-classic');
        return;
      }
    } catch {}
  }

  ws.close(1008, 'ss decrypt failed');
}

async function ssPipe(ws, key, header, env, userCfg, ctx, mode) {
  const tcp = await dial(header.addr, header.port);
  if (!tcp) { ws.close(1011, 'dial failed'); return; }
  const writer = tcp.writable.getWriter();
  const tcpReader = tcp.readable.getReader();

  let uploadBytes = 0;
  let downloadBytes = 0;

  if (header.payload.length > 0) {
    try { await writer.write(header.payload); uploadBytes += header.payload.length; } catch {}
  }

  // از WebSocket به TCP
  ws.addEventListener('message', async (ev) => {
    const buf = ev.data instanceof ArrayBuffer ? ev.data : await ev.data.arrayBuffer();
    const data = new Uint8Array(buf);
    try {
      let plain;
      if (mode === 'ss2022') {
        plain = await ss2022Decrypt(key, data);
      } else {
        if (data.length < 13) return;
        const iv = data.slice(0, 12);
        const cipher = data.slice(12);
        plain = await ssAesGcmDecrypt(key, iv, cipher);
      }
      if (plain) {
        await writer.write(plain);
        uploadBytes += plain.length;
      }
    } catch {}
  });
  ws.addEventListener('close', async () => {
    try { writer.close(); } catch {}
    // ثبت آمار نهایی
    ctx.waitUntil(updateStats(env, userCfg.uuid, uploadBytes, downloadBytes));
  });

  // از TCP به WebSocket
  try {
    while (true) {
      const { value, done } = await tcpReader.read();
      if (done) break;
      let cipher;
      if (mode === 'ss2022') {
        cipher = await ss2022Encrypt(key, value);
      } else {
        const iv = randomIv();
        cipher = await ssAesGcmEncrypt(key, iv, value);
        const combined = new Uint8Array(12 + cipher.length);
        combined.set(iv, 0);
        combined.set(cipher, 12);
        cipher = combined;
      }
      ws.send(cipher);
      downloadBytes += value.length;
    }
  } catch {}
  try { ws.close(); } catch {}
  ctx.waitUntil(updateStats(env, userCfg.uuid, uploadBytes, downloadBytes));
}

// ===== هندلر VLESS (با احراز هویت KV) =====
async function handleVless(ws, env, ctx) {
  ws.accept();
  const queue = [];
  let resolver = null;
  ws.addEventListener('message', async (ev) => {
    const buf = ev.data instanceof ArrayBuffer ? ev.data : await ev.data.arrayBuffer();
    queue.push(new Uint8Array(buf));
    if (resolver) { resolver(); resolver = null; }
  });
  const fakeReader = {
    read: async () => {
      if (queue.length === 0) await new Promise((r) => { resolver = r; });
      return { value: queue.shift(), done: false };
    },
  };
  const reader = new ByteReader(fakeReader);

  // پارس سرآیند VLESS
  const ver = await reader.read(1);
  if (!ver) { ws.close(1008, 'bad vless'); return; }
  const uuidBytes = await reader.read(16);
  if (!uuidBytes) { ws.close(1008, 'bad vless'); return; }
  const uuidStr = formatUuid(uuidBytes);
  const addonLen = await reader.read(1);
  if (!addonLen) { ws.close(1008, 'bad vless'); return; }
  if (addonLen[0] > 0) await reader.read(addonLen[0]);
  const cmd = await reader.read(1);
  if (!cmd || cmd[0] !== 1) { ws.close(1008, 'tcp only'); return; }
  const portBytes = await reader.read(2);
  if (!portBytes) { ws.close(1008, 'bad port'); return; }
  const port = (portBytes[0] << 8) | portBytes[1];
  const atypeByte = await reader.read(1);
  if (!atypeByte) { ws.close(1008, 'bad atype'); return; }
  let addr;
  if (atypeByte[0] === 1) {
    const ip = await reader.read(4);
    addr = `${ip[0]}.${ip[1]}.${ip[2]}.${ip[3]}`;
  } else if (atypeByte[0] === 2) {
    const lenByte = await reader.read(1);
    const domain = await reader.read(lenByte[0]);
    addr = new TextDecoder().decode(domain);
  } else if (atypeByte[0] === 3) {
    const ip = await reader.read(16);
    const parts = [];
    for (let i = 0; i < 16; i += 2) parts.push(((ip[i] << 8) | ip[i + 1]).toString(16));
    addr = `[${parts.join(':')}]`;
  } else { ws.close(1008, 'bad atype'); return; }

  // احراز هویت کاربر از KV
  const userCfg = await getUserConfig(env, uuidStr);
  if (!userCfg) { ws.close(1008, 'unauthorized'); return; }

  // اتصال به مقصد
  const tcp = await dial(addr, port);
  if (!tcp) { ws.close(1011, 'dial failed'); return; }
  const writer = tcp.writable.getWriter();
  const tcpReader = tcp.readable.getReader();

  let uploadBytes = 0;
  let downloadBytes = 0;

  const rem = reader.remaining();
  if (rem.length > 0) { try { await writer.write(rem); uploadBytes += rem.length; } catch {} }

  ws.addEventListener('message', async (ev) => {
    const buf = ev.data instanceof ArrayBuffer ? ev.data : await ev.data.arrayBuffer();
    try { await writer.write(new Uint8Array(buf)); uploadBytes += buf.byteLength; } catch {}
  });
  ws.addEventListener('close', async () => {
    try { writer.close(); } catch {}
    ctx.waitUntil(updateStats(env, userCfg.uuid, uploadBytes, downloadBytes));
  });
  try {
    while (true) {
      const { value, done } = await tcpReader.read();
      if (done) break;
      ws.send(value);
      downloadBytes += value.length;
    }
  } catch {}
  try { ws.close(); } catch {}
  ctx.waitUntil(updateStats(env, userCfg.uuid, uploadBytes, downloadBytes));
}

function formatUuid(bytes) {
  const hex = Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
  return `${hex.substr(0, 8)}-${hex.substr(8, 4)}-${hex.substr(12, 4)}-${hex.substr(16, 4)}-${hex.substr(20, 12)}`;
}

// ===== هندلر Trojan (با KV) =====
async function handleTrojan(ws, env, ctx) {
  ws.accept();
  const queue = [];
  let resolver = null;
  const onMessage = async (ev) => {
    const buf = ev.data instanceof ArrayBuffer ? ev.data : await ev.data.arrayBuffer();
    queue.push(new Uint8Array(buf));
    if (resolver) { resolver(); resolver = null; }
  };
  ws.addEventListener('message', onMessage);
  const fakeReader = {
    read: async () => {
      if (queue.length === 0) await new Promise((r) => { resolver = r; });
      return { value: queue.shift(), done: false };
    },
  };
  const reader = new ByteReader(fakeReader);

  // هدر Trojan: sha224(password)(56) | CRLF | SOCKS5
  const hashBytes = await reader.read(56);
  if (!hashBytes) { ws.close(1008, 'bad trojan'); return; }
  const hashHex = new TextDecoder().decode(hashBytes);

  // پیدا کردن کاربر با هش Trojan مطابق
  // در حالت تک‌کاربره:
  const userCfg = await findUserByTrojanHash(env, hashHex);
  if (!userCfg) { ws.close(1008, 'unauthorized'); return; }

  await reader.read(2); // CRLF
  const atypeByte = await reader.read(1);
  if (!atypeByte) { ws.close(1008, 'bad atype'); return; }
  let addr;
  if (atypeByte[0] === 1) {
    const ip = await reader.read(4);
    addr = `${ip[0]}.${ip[1]}.${ip[2]}.${ip[3]}`;
  } else if (atypeByte[0] === 3) {
    const lenByte = await reader.read(1);
    const domain = await reader.read(lenByte[0]);
    addr = new TextDecoder().decode(domain);
  } else { ws.close(1008, 'bad atype'); return; }
  const portBytes = await reader.read(2);
  const port = (portBytes[0] << 8) | portBytes[1];
  await reader.read(2); // CRLF

  const tcp = await dial(addr, port);
  if (!tcp) { ws.close(1011, 'dial failed'); return; }
  const writer = tcp.writable.getWriter();
  const tcpReader = tcp.readable.getReader();
  let uploadBytes = 0, downloadBytes = 0;

  const rem = reader.remaining();
  if (rem.length > 0) { try { await writer.write(rem); uploadBytes += rem.length; } catch {} }
  ws.removeEventListener('message', onMessage);
  ws.addEventListener('message', async (ev) => {
    const buf = ev.data instanceof ArrayBuffer ? ev.data : await ev.data.arrayBuffer();
    try { await writer.write(new Uint8Array(buf)); uploadBytes += buf.byteLength; } catch {}
  });
  ws.addEventListener('close', async () => {
    try { writer.close(); } catch {}
    ctx.waitUntil(updateStats(env, userCfg.uuid, uploadBytes, downloadBytes));
  });
  try {
    while (true) {
      const { value, done } = await tcpReader.read();
      if (done) break;
      ws.send(value);
      downloadBytes += value.length;
    }
  } catch {}
  try { ws.close(); } catch {}
  ctx.waitUntil(updateStats(env, userCfg.uuid, uploadBytes, downloadBytes));
}

async function findUserByTrojanHash(env, hashHex) {
  // در حالت تک‌کاربره، هش از env.TROJAN_PASSWORD محاسبه می‌شود.
  const pass = (env && env.TROJAN_PASSWORD) || DEFAULTS.TROJAN_PASSWORD;
  const expectedHash = await sha256Hex(pass);
  if (hashHex.toLowerCase() === expectedHash.toLowerCase()) {
    return await getUserConfig(env, (env && env.UUID) || DEFAULTS.UUID);
  }
  // در حالت چندکاربره، باید همه کاربران را بررسی کنیم (یا یک index معکوس بسازیم)
  if (env.USERS_KV) {
    const users = await listUsers(env);
    for (const u of users) {
      const cfg = await getUserConfig(env, u.uuid);
      if (cfg && cfg.trojanPass) {
        const h = await sha256Hex(cfg.trojanPass);
        if (hashHex.toLowerCase() === h.toLowerCase()) return cfg;
      }
    }
  }
  return null;
}

async function sha256Hex(text) {
  const data = new TextEncoder().encode(text);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash)).map((b) => b.toString(16).padStart(2, '0')).join('');
}

// ===== XHTTP با Durable Object (stream-up) =====
// کلاینت درخواست POST می‌فرستد با بدنه VLESS. این درخواست به یک Durable Object هدایت می‌شود
// که state TCP را بین درخواست‌ها نگه می‌دارد.
async function handleXhttpRequest(request, env, ctx) {
  const url = new URL(request.url);

  // استخراج session id از query یا هدر
  const sessionId = url.searchParams.get('session') || request.headers.get('X-Session-Id') || 'default';

  // دریافت Durable Object
  const id = env.XHTTP_SESSION.idFromName(sessionId);
  const stub = env.XHTTP_SESSION.get(id);

  // forward درخواست به DO
  return stub.fetch(request);
}

// ===== Durable Object: XHTTP Session =====
export class XhttpSession {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.tcp = null;
    this.writer = null;
    this.reader = null;
    this.targetAddr = null;
    this.targetPort = null;
    this.userUuid = null;
    this.uploadBytes = 0;
    this.downloadBytes = 0;
    this.responseStream = null;
    this.responseController = null;
  }

  async fetch(request) {
    const url = new URL(request.url);
    const method = request.method;

    if (method === 'POST') {
      const body = new Uint8Array(await request.arrayBuffer());
      if (!this.tcp) {
        // اولین بسته: پارس VLESS header
        if (body.length < 22) return new Response('too short', { status: 400 });
        const uuidBytes = body.slice(1, 17);
        const uuidStr = formatUuid(uuidBytes);
        const userCfg = await getUserConfig(this.env, uuidStr);
        if (!userCfg) return new Response('unauthorized', { status: 401 });
        this.userUuid = uuidStr;

        let idx = 17;
        const addonLen = body[idx]; idx += 1 + addonLen;
        const cmd = body[idx]; idx += 1;
        if (cmd !== 1) return new Response('tcp only', { status: 400 });
        const port = (body[idx] << 8) | body[idx + 1]; idx += 2;
        const atype = body[idx]; idx += 1;
        let addr;
        if (atype === 1) {
          addr = `${body[idx]}.${body[idx + 1]}.${body[idx + 2]}.${body[idx + 3]}`;
          idx += 4;
        } else if (atype === 2) {
          const len = body[idx]; idx += 1;
          addr = new TextDecoder().decode(body.slice(idx, idx + len));
          idx += len;
        } else {
          return new Response('bad atype', { status: 400 });
        }
        this.targetAddr = addr;
        this.targetPort = port;
        const payload = body.slice(idx);

        // dial
        this.tcp = await dial(addr, port);
        if (!this.tcp) return new Response('dial failed', { status: 502 });
        this.writer = this.tcp.writable.getWriter();
        this.reader = this.tcp.readable.getReader();

        if (payload.length > 0) {
          try { await this.writer.write(payload); this.uploadBytes += payload.length; } catch {}
        }

        // ایجاد stream برای پاسخ
        this.responseStream = new ReadableStream({
          start: async (controller) => {
            this.responseController = controller;
            // خواندن از TCP و نوشتن به stream
            try {
              while (true) {
                const { value, done } = await this.reader.read();
                if (done) break;
                controller.enqueue(value);
                this.downloadBytes += value.length;
              }
            } catch {}
            controller.close();
            // ثبت آمار نهایی
            if (this.env.STATS_KV && this.userUuid) {
              await updateStats(this.env, this.userUuid, this.uploadBytes, this.downloadBytes);
            }
          },
        });

        return new Response(this.responseStream, {
          status: 200,
          headers: { 'Content-Type': 'application/octet-stream', 'Cache-Control': 'no-store' },
        });
      } else {
        // بسته‌های بعدی: فقط payload
        try {
          await this.writer.write(body);
          this.uploadBytes += body.length;
        } catch {}
        return new Response(null, { status: 204 });
      }
    }

    if (method === 'GET') {
      // برای دریافت داده‌های TCP (stream-down)
      if (!this.responseStream) {
        return new Response('no session', { status: 404 });
      }
      return new Response(this.responseStream, {
        status: 200,
        headers: { 'Content-Type': 'application/octet-stream' },
      });
    }

    if (method === 'DELETE') {
      // بستن session
      try { this.writer.close(); } catch {}
      if (this.env.STATS_KV && this.userUuid) {
        await updateStats(this.env, this.userUuid, this.uploadBytes, this.downloadBytes);
      }
      return new Response('closed', { status: 200 });
    }

    return new Response('Method Not Allowed', { status: 405 });
  }
}

// ===== پنل مدیریت =====
async function handleAdmin(request, env) {
  const url = new URL(request.url);
  const token = url.searchParams.get('token') || request.headers.get('X-Admin-Token');
  const expectedToken = (env && env.ADMIN_TOKEN) || DEFAULTS.ADMIN_TOKEN;

  if (token !== expectedToken) {
    return new Response('Unauthorized', { status: 401 });
  }

  if (url.pathname === '/admin' || url.pathname === '/admin/') {
    // داشبورد
    const users = await listUsers(env);
    const statsPromises = users.map((u) => getUserStats(env, u.uuid));
    const stats = await Promise.all(statsPromises);
    return new Response(renderAdminPage(users, stats), {
      headers: { 'Content-Type': 'text/html; charset=utf-8' },
    });
  }

  if (url.pathname === '/admin/users' && request.method === 'POST') {
    // افزودن کاربر جدید
    const body = await request.json();
    if (!body.uuid) return new Response('uuid required', { status: 400 });
    const cfg = {
      trojanPass: body.trojanPass || 'generated',
      ssPass: body.ssPass || 'generated',
      ss2022Pass: body.ss2022Pass || null,
      name: body.name || 'user',
      enabled: true,
    };
    await addUser(env, body.uuid, cfg);
    return new Response(JSON.stringify({ ok: true }), {
      headers: { 'Content-Type': 'application/json' },
    });
  }

  if (url.pathname.startsWith('/admin/users/') && request.method === 'DELETE') {
    const uuid = url.pathname.split('/').pop();
    await deleteUser(env, uuid);
    return new Response(JSON.stringify({ ok: true }), {
      headers: { 'Content-Type': 'application/json' },
    });
  }

  return new Response('Not Found', { status: 404 });
}

function renderAdminPage(users, stats) {
  const rows = users.map((u, i) => {
    const s = stats[i] || {};
    const upMB = ((s.upload || 0) / 1024 / 1024).toFixed(2);
    const downMB = ((s.download || 0) / 1024 / 1024).toFixed(2);
    const totalMB = ((s.total || 0) / 1024 / 1024).toFixed(2);
    return `<tr>
      <td>${u.uuid}</td>
      <td>${u.name}</td>
      <td>${u.enabled ? '✓' : '✗'}</td>
      <td>${upMB} MB</td>
      <td>${downMB} MB</td>
      <td>${totalMB} MB</td>
      <td><button onclick="del('${u.uuid}')">حذف</button></td>
    </tr>`;
  }).join('');
  return `<!DOCTYPE html>
<html dir="rtl" lang="fa"><head><meta charset="utf-8"><title>Admin Panel</title>
<style>
body{font-family:system-ui;background:#0f172a;color:#e2e8f0;padding:24px;margin:0}
table{width:100%;border-collapse:collapse;margin-top:16px}
th,td{padding:10px;border:1px solid #334155;text-align:right}
th{background:#1e293b}
td{font-family:monospace;font-size:12px}
button{background:#ef4444;color:white;border:none;padding:6px 12px;border-radius:4px;cursor:pointer}
.add{background:#10b981;padding:12px;margin:12px 0;border-radius:8px}
input{padding:6px;margin:4px;border-radius:4px;border:1px solid #334155;background:#1e293b;color:#e2e8f0}
</style></head><body>
<h1>پنل مدیریت Worker Proxy PRO</h1>
<div class="add">
  <h3>افزودن کاربر جدید</h3>
  <input id="uuid" placeholder="UUID">
  <input id="name" placeholder="نام">
  <input id="trojanPass" placeholder="رمز Trojan">
  <input id="ssPass" placeholder="رمز SS">
  <button onclick="addUser()">افزودن</button>
</div>
<table>
<tr><th>UUID</th><th>نام</th><th>فعال</th><th>آپلود</th><th>دانلود</th><th>کل</th><th>عملیات</th></tr>
${rows}
</table>
<script>
async function addUser(){
  const body = {
    uuid: document.getElementById('uuid').value,
    name: document.getElementById('name').value,
    trojanPass: document.getElementById('trojanPass').value,
    ssPass: document.getElementById('ssPass').value,
  };
  const token = new URLSearchParams(location.search).get('token');
  const r = await fetch('/admin/users?token=' + token, { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body) });
  if (r.ok) location.reload();
}
async function del(uuid){
  if (!confirm('حذف ' + uuid + '?')) return;
  const token = new URLSearchParams(location.search).get('token');
  await fetch('/admin/users/' + uuid + '?token=' + token, { method:'DELETE' });
  location.reload();
}
</script>
</body></html>`;
}

// ===== صفحه راهنما (نسخه PRO) =====
function buildConfigPage(env, host) {
  const uuid = (env && env.UUID) || DEFAULTS.UUID;
  const trojanPass = (env && env.TROJAN_PASSWORD) || DEFAULTS.TROJAN_PASSWORD;
  const ssPass = (env && env.SS_PASSWORD) || DEFAULTS.SS_PASSWORD;
  const ss2022Pass = (env && env.SS2022_PASSWORD) || DEFAULTS.SS2022_PASSWORD;
  const proxyPath = (env && env.PROXY_PATH) || DEFAULTS.PROXY_PATH;
  const xhttpPath = (env && env.XHTTP_PATH) || DEFAULTS.XHTTP_PATH;
  const subPath = (env && env.SUB_PATH) || DEFAULTS.SUB_PATH;
  const adminPath = (env && env.ADMIN_PATH) || DEFAULTS.ADMIN_PATH;
  const name = (env && env.NAME) || DEFAULTS.NAME;

  const vlessLink = `vless://${uuid}@${host}:443?encryption=none&security=tls&sni=${host}&type=ws&host=${host}&path=%2F${proxyPath}%2Fvless#${name}-vless`;
  const trojanLink = `trojan://${trojanPass}@${host}:443?security=tls&sni=${host}&type=ws&host=${host}&path=%2F${proxyPath}%2Ftrojan#${name}-trojan`;
  const ssBase64 = btoa(`aes-128-gcm:${ssPass}`);
  const ssLink = `ss://${ssBase64}@${host}:443/?plugin=v2ray-plugin&plugin-opts=mode%3Dwebsocket%3Bhost%3D${host}%3Bpath%3D%2F${proxyPath}%2Fss%3Btls#${name}-ss`;
  const ss2022Link = `ss://2022-blake3-aes-256-gcm:${ss2022Pass}@${host}:443/?plugin=v2ray-plugin&plugin-opts=mode%3Dwebsocket%3Bhost%3D${host}%3Bpath%3D%2F${proxyPath}%2Fss%3Btls#${name}-ss2022`;
  const xhttpLink = `vless://${uuid}@${host}:443?encryption=none&security=tls&sni=${host}&type=xhttp&host=${host}&path=%2F${xhttpPath}&mode=stream-up#${name}-xhttp`;

  return `<!DOCTYPE html><html dir="rtl" lang="fa"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Cloudflare Worker Proxy PRO</title>
<style>body{font-family:system-ui;background:#0f172a;color:#e2e8f0;padding:24px;line-height:1.7;max-width:900px;margin:0 auto}
h1{color:#60a5fa;border-bottom:2px solid #334155;padding-bottom:8px}
h2{color:#a78bfa;margin-top:32px}
pre{background:#1e293b;padding:14px;border-radius:8px;overflow-x:auto;direction:ltr;border:1px solid #334155;font-size:11px}
code{color:#fbbf24}
.box{background:#1e293b;border:1px solid #334155;padding:16px;border-radius:8px;margin:12px 0}
button{background:#3b82f6;color:white;border:none;padding:8px 16px;border-radius:6px;cursor:pointer;font-family:inherit;margin-top:8px}
.tag{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;background:#065f46;color:#a7f3d0}
</style></head><body>
<h1>Cloudflare Worker Proxy PRO <span class="tag">v3 — ۵ پروتکل + KV + DO</span></h1>
<p>پروتکل‌ها: <strong>VLESS</strong>, <strong>Trojan</strong>, <strong>Shadowsocks</strong>, <strong>Shadowsocks 2022</strong>, <strong>XHTTP (stream-up)</strong>.</p>

<h2>۱) VLESS (WS+TLS)</h2><div class="box"><pre>${vlessLink}</pre><button onclick="navigator.clipboard.writeText('${vlessLink}');this.textContent='کپی شد!'">کپی</button></div>
<h2>۲) Trojan (WS+TLS)</h2><div class="box"><pre>${trojanLink}</pre><button onclick="navigator.clipboard.writeText('${trojanLink}');this.textContent='کپی شد!'">کپی</button></div>
<h2>۳) Shadowsocks (aes-128-gcm)</h2><div class="box"><pre>${ssLink}</pre><button onclick="navigator.clipboard.writeText('${ssLink}');this.textContent='کپی شد!'">کپی</button></div>
<h2>۴) Shadowsocks 2022 (blake3-aes-256-gcm) <span class="tag">جدید</span></h2><div class="box"><pre>${ss2022Link}</pre><button onclick="navigator.clipboard.writeText('${ss2022Link}');this.textContent='کپی شد!'">کپی</button></div>
<h2>۵) XHTTP (stream-up با Durable Object) <span class="tag">جدید</span></h2><div class="box"><pre>${xhttpLink}</pre><button onclick="navigator.clipboard.writeText('${xhttpLink}');this.textContent='کپی شد!'">کپی</button></div>

<h2>ساب‌لینک</h2><div class="box"><pre>https://${host}/${subPath}</pre><button onclick="navigator.clipboard.writeText('https://${host}/${subPath}');this.textContent='کپی شد!'">کپی</button></div>

<h2>پنل مدیریت</h2><div class="box"><pre>https://${host}/${adminPath}?token=YOUR_ADMIN_TOKEN</pre><p>برای مدیریت کاربران و مشاهده آمار مصرف.</p></div>

<h2>🔍 بخش Clean IP</h2><div class="box"><pre>https://${host}/cleanip</pre><p>جستجو و تست IP تمیز برای Netflix, ChatGPT, Disney+, Spotify, TikTok و Cloudflare. شامل تولید IP تصادفی از رنج‌های Cloudflare.</p></div>

<h2>نکات</h2><ul>
<li>برای فعال‌سازی کامل چندکاربره و آمار، KV namespaces <code>USERS_KV</code> و <code>STATS_KV</code> را در Wrangler config اضافه کنید.</li>
<li>برای XHTTP stream-up، Durable Object <code>XHTTP_SESSION</code> را اضافه کنید.</li>
<li>ADMIN_TOKEN را به یک مقدار قوی تغییر دهید.</li>
</ul>
</body></html>`;
}

// ===== ساب‌لینک =====
function buildSubscription(env, host) {
  const uuid = (env && env.UUID) || DEFAULTS.UUID;
  const trojanPass = (env && env.TROJAN_PASSWORD) || DEFAULTS.TROJAN_PASSWORD;
  const ssPass = (env && env.SS_PASSWORD) || DEFAULTS.SS_PASSWORD;
  const ss2022Pass = (env && env.SS2022_PASSWORD) || DEFAULTS.SS2022_PASSWORD;
  const proxyPath = (env && env.PROXY_PATH) || DEFAULTS.PROXY_PATH;
  const xhttpPath = (env && env.XHTTP_PATH) || DEFAULTS.XHTTP_PATH;
  const name = (env && env.NAME) || DEFAULTS.NAME;

  const vlessLink = `vless://${uuid}@${host}:443?encryption=none&security=tls&sni=${host}&type=ws&host=${host}&path=%2F${proxyPath}%2Fvless#${name}-vless`;
  const trojanLink = `trojan://${trojanPass}@${host}:443?security=tls&sni=${host}&type=ws&host=${host}&path=%2F${proxyPath}%2Ftrojan#${name}-trojan`;
  const ssBase64 = btoa(`aes-128-gcm:${ssPass}`);
  const ssLink = `ss://${ssBase64}@${host}:443/?plugin=v2ray-plugin&plugin-opts=mode%3Dwebsocket%3Bhost%3D${host}%3Bpath%3D%2F${proxyPath}%2Fss%3Btls#${name}-ss`;
  const ss2022Link = `ss://2022-blake3-aes-256-gcm:${ss2022Pass}@${host}:443/?plugin=v2ray-plugin&plugin-opts=mode%3Dwebsocket%3Bhost%3D${host}%3Bpath%3D%2F${proxyPath}%2Fss%3Btls#${name}-ss2022`;
  const xhttpLink = `vless://${uuid}@${host}:443?encryption=none&security=tls&sni=${host}&type=xhttp&host=${host}&path=%2F${xhttpPath}&mode=stream-up#${name}-xhttp`;

  return btoa(`${vlessLink}\n${trojanLink}\n${ssLink}\n${ss2022Link}\n${xhttpLink}`);
}

// ===== تابع اصلی fetch =====
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const host = url.hostname;

    const proxyPath = (env && env.PROXY_PATH) || DEFAULTS.PROXY_PATH;
    const xhttpPath = (env && env.XHTTP_PATH) || DEFAULTS.XHTTP_PATH;
    const subPath = (env && env.SUB_PATH) || DEFAULTS.SUB_PATH;
    const adminPath = (env && env.ADMIN_PATH) || DEFAULTS.ADMIN_PATH;
    const cleanIpPath = (env && env.CLEANIP_PATH) || DEFAULTS.CLEANIP_PATH;

    // بخش Clean IP
    if (url.pathname === `/${cleanIpPath}` || url.pathname.startsWith(`/${cleanIpPath}/`)) {
      return handleCleanIp(request, env, ctx);
    }

    // پنل مدیریت
    if (url.pathname === `/${adminPath}` || url.pathname.startsWith(`/${adminPath}/`)) {
      return handleAdmin(request, env);
    }

    // VLESS روی WS
    if (url.pathname === `/${proxyPath}/vless`) {
      const upgrade = request.headers.get('Upgrade');
      if (upgrade !== 'websocket') return new Response('Expected WebSocket', { status: 426 });
      const pair = new WebSocketPair();
      const [client, server] = Object.values(pair);
      ctx.waitUntil(handleVless(server, env, ctx));
      return new Response(null, { status: 101, webSocket: client });
    }

    // Trojan روی WS
    if (url.pathname === `/${proxyPath}/trojan`) {
      const upgrade = request.headers.get('Upgrade');
      if (upgrade !== 'websocket') return new Response('Expected WebSocket', { status: 426 });
      const pair = new WebSocketPair();
      const [client, server] = Object.values(pair);
      ctx.waitUntil(handleTrojan(server, env, ctx));
      return new Response(null, { status: 101, webSocket: client });
    }

    // Shadowsocks (کلاسیک + 2022) روی WS
    if (url.pathname === `/${proxyPath}/ss`) {
      const upgrade = request.headers.get('Upgrade');
      if (upgrade !== 'websocket') return new Response('Expected WebSocket', { status: 426 });
      const pair = new WebSocketPair();
      const [client, server] = Object.values(pair);
      // در حالت تک‌کاربره، userCfg از env می‌آید
      const userCfg = await getUserConfig(env, (env && env.UUID) || DEFAULTS.UUID);
      if (!userCfg) return new Response('Unauthorized', { status: 401 });
      ctx.waitUntil(handleShadowsocks(server, userCfg, env, ctx));
      return new Response(null, { status: 101, webSocket: client });
    }

    // XHTTP (با Durable Object)
    if (url.pathname === `/${xhttpPath}` || url.pathname.startsWith(`/${xhttpPath}/`)) {
      if (request.method !== 'POST' && request.method !== 'GET' && request.method !== 'DELETE') {
        return new Response('Method Not Allowed', { status: 405 });
      }
      if (!env.XHTTP_SESSION) {
        return new Response('XHTTP_SESSION Durable Object not bound', { status: 500 });
      }
      return handleXhttpRequest(request, env, ctx);
    }

    // ساب‌لینک
    if (url.pathname === `/${subPath}`) {
      const sub = buildSubscription(env, host);
      return new Response(sub, {
        headers: {
          'Content-Type': 'text/plain; charset=utf-8',
          'Content-Disposition': 'attachment; filename="sub.txt"',
          'Profile-Update-Interval': '24',
          'Subscription-Userinfo': 'upload=0; download=0; total=107374182400; expire=0',
        },
      });
    }

    // صفحه راهنما
    if (url.pathname === '/') {
      return new Response(buildConfigPage(env, host), {
        headers: { 'Content-Type': 'text/html; charset=utf-8' },
      });
    }

    return new Response('Not Found', { status: 404 });
  },
};
