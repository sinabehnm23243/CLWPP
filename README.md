# Cloudflare Worker Proxy PRO v3 (۵ پروتکل + KV + Durable Objects)

نسخه‌ی حرفه‌ای Worker سفارشی با ویژگی‌های پیشرفته.

## ویژگی‌های اضافه‌شده نسبت به v2

| ویژگی | توضیح |
|---|---|
| **احراز هویت چندکاربره** | با Workers KV — هر کاربر UUID/رمز اختصاصی |
| **آمار مصرف** | آپلود/دانلود/کل به تفکیک کاربر، در KV |
| **XHTTP stream-up** | با Durable Object برای stateful sessions |
| **Shadowsocks 2022** | با blake3 + aes-256-gcm (کلاینت‌های 2022) |
| **پنل مدیریت** | رابط وب برای افزودن/حذف کاربران و مشاهده آمار |

## فایل‌ها

- [_worker.js](_worker.js) — کد اصلی Worker (۹۷۱ خط)
- [blake3.js](blake3.js) — پیاده‌سازی Blake3 برای SS 2022 (۲۵۰ خط)
- [wrangler.toml](wrangler.toml) — پیکربندی Wrangler با KV و DO bindings

## پروتکل‌های پشتیبانی‌شده

| # | پروتکل | مسیر | متد |
|---|---|---|---|
| ۱ | VLESS | `/ws/vless` | WebSocket |
| ۲ | Trojan | `/ws/trojan` | WebSocket |
| ۳ | Shadowsocks (aes-128-gcm) | `/ws/ss` | WebSocket |
| ۴ | Shadowsocks 2022 (blake3-aes-256-gcm) | `/ws/ss` | WebSocket |
| ۵ | XHTTP (stream-up) | `/xhttp` | HTTP POST/GET/DELETE |

## منابع مورد نیاز در Cloudflare

### KV Namespaces

۱) `USERS_KV` — احراز هویت کاربران
۲) `STATS_KV` — آمار مصرف

### Durable Object

`XHTTP_SESSION` — برای XHTTP stream-up

## نصب و راه‌اندازی

### مرحله ۱: ایجاد KV Namespaces

۱) وارد [Cloudflare Dashboard](https://dash.cloudflare.com) شوید.
۲) به **Storage & Databases** → **KV** بروید.
۳) **Create a namespace** → نام: `users` → **Add**.
۴) **Create a namespace** → نام: `stats` → **Add**.
۵) ID هر دو را ذخیره کنید.

### مرحله ۲: ایجاد Worker

۱) به **Workers & Pages** → **Create** بروید.
۲) نام: `cf-proxy-pro` → **Deploy**.
۳) **Edit code** → محتوای `_worker.js` و `blake3.js` را در دو فایل جداگانه کپی کنید.
۴) **Save and deploy**.

### مرحله ۳: افزودن Bindings

در صفحه Worker → **Settings** → **Bindings**:

۱) **Add binding** → **KV namespace** → Variable name: `USERS_KV` → namespace: `users`.
۲) **Add binding** → **KV namespace** → Variable name: `STATS_KV` → namespace: `stats`.
۳) **Add binding** → **Durable Object namespace** → Variable name: `XHTTP_SESSION` → class: `XhttpSession`.

### مرحله ۴: افزودن متغیرهای محیطی

در **Settings** → **Variables**:

- `UUID` → یک UUID جدید (با `uuidgen`)
- `TROJAN_PASSWORD` → رمز قوی
- `SS_PASSWORD` → رمز قوی (متفاوت)
- `SS2022_PASSWORD` → base64 یک کلید ۳۲ بایتی (با `openssl rand -base64 32`)
- `ADMIN_TOKEN` → توکن قوی (با `openssl rand -hex 32`)
- `SUB_PATH`, `PROXY_PATH`, `XHTTP_PATH`, `ADMIN_PATH`, `NAME` (اختیاری)

### مرحله ۵: Deploy نهایی

روی **Save and Deploy** کلیک کنید.

## مسیرها پس از Deploy

| URL | کاربرد |
|---|---|
| `https://cf-proxy-pro.<user>.workers.dev/` | صفحه راهنما + کانفیگ‌ها |
| `https://cf-proxy-pro.<user>.workers.dev/ws/vless` | WebSocket VLESS |
| `https://cf-proxy-pro.<user>.workers.dev/ws/trojan` | WebSocket Trojan |
| `https://cf-proxy-pro.<user>.workers.dev/ws/ss` | WebSocket SS (auto-detect کلاسیک/2022) |
| `https://cf-proxy-pro.<user>.workers.dev/xhttp` | XHTTP (stream-up با DO) |
| `https://cf-proxy-pro.<user>.workers.dev/sub` | ساب‌لینک Base64 (شامل هر ۵ کانفیگ) |
| `https://cf-proxy-pro.<user>.workers.dev/admin?token=YOUR_TOKEN` | پنل مدیریت |

## استفاده از پنل مدیریت

۱) به `https://cf-proxy-pro.<user>.workers.dev/admin?token=YOUR_ADMIN_TOKEN` بروید.
۲) در فرم «افزودن کاربر جدید»:
   - UUID (با `uuidgen` یا uuidgenerator.org)
   - نام (اختیاری)
   - رمز Trojan
   - رمز Shadowsocks
۳) روی «افزودن» کلیک کنید.
۴) کاربر در `USERS_KV` ذخیره می‌شود.
۵) آمار مصرف هر کاربر در جدول اصلی نمایش داده می‌شود (آپلود/دانلود/کل به MB).

## ساختار داده در KV

### USERS_KV

```
key:   "d342d11e-d424-..."
value: {
  "trojanPass": "...",
  "ssPass": "...",
  "ss2022Pass": "...",   // یا null اگر غیرفعال
  "name": "...",
  "enabled": true
}
```

### STATS_KV

```
key:   "stats:<uuid>:current"
value: {
  "upload": 1234567,
  "download": 7654321,
  "total": 8888888,
  "lastReset": 1700000000000
}
```

## نکات فنی

### Shadowsocks 2022
- روش: `2022-blake3-aes-256-gcm`
- کلید: blake3(base64-decoded-password) با طول ۳۲ بایت
- هر بسته: nonce(12) + ciphertext با GCM tag
- کلاینت‌های پشتیبانی‌شده: Xray-core ≥ 1.8.0, sing-box ≥ 1.5, Shadowrocket ≥ 2.2.50

### XHTTP stream-up
- استفاده از Durable Object برای نگه‌داشتن state TCP بین درخواست‌های HTTP
- کلاینت POST می‌فرستد برای upload، GET برای download، DELETE برای بستن
- session id از query param `?session=...` یا هدر `X-Session-Id` خوانده می‌شود

### محدودیت‌ها
- سقف رایگان KV: ۱۰۰٬۰۰۰ reads و ۱٬۰۰۰ writes در روز
- سقف رایگان Durable Objects: ۱۰۰٬۰۰۰ requests در روز (در سطح رایگان)
- سقف رایگان Workers: ۱۰۰٬۰۰۰ requests در روز
- فقط TCP (UDP پشتیبانی نمی‌شود)

### امنیت
- ADMIN_TOKEN را قوی انتخاب کنید (`openssl rand -hex 32`)
- SS2022_PASSWORD باید base64 یک کلید ۳۲ بایتی باشد (`openssl rand -base64 32`)
- متغیرهای حساس را با نوع **Secret** در Dashboard ذخیره کنید
- برای محیط production، CORS و rate limiting را اضافه کنید

## Deploy با Wrangler CLI

```bash
npm install -g wrangler
wrangler login

# ایجاد KV namespaces
wrangler kv namespace create USERS_KV
wrangler kv namespace create STATS_KV

# کپی ID‌های دریافت‌شده در wrangler.toml

# Deploy
wrangler deploy
```

## لایسنس

MIT — آزاد برای استفاده و تغییر.
