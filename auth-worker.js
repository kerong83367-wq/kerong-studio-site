// ============================================================
// 持仓雷达 · 本站账号后端（Cloudflare Worker + KV，免费版可用）
// 部署：dash.cloudflare.com → Workers & Pages → 新建 Worker →
//      把本文件内容粘贴进去 → 先建一个 KV 命名空间（名字任意，
//      如 radar-auth），在 Worker 设置 → 变量里绑定 KV，变量名
//      必须是 AUTH_KV → 部署。部署后地址形如：
//      https://radar-auth.<你的workers子域>.workers.dev
//      再把 radar.html 顶部 AUTH_API 改成这个地址。
// 安全：密码用 PBKDF2（10 万次迭代 + 随机盐）存哈希，不存明文；
//      会话 token 32 字节随机，KV 里 30 天过期；注册/登录按 IP
//      限流。轻量系统，请勿与重要账号共用密码。
// ============================================================

const ALLOWED_ORIGIN = 'https://xiaoxiaoke.ccwu.cc';
const SESSION_DAYS = 30;
const PBKDF2_ITERS = 100000;

function corsHeaders(req) {
  const origin = req.headers.get('Origin');
  return {
    'Access-Control-Allow-Origin': origin === ALLOWED_ORIGIN ? origin : ALLOWED_ORIGIN,
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400',
    'Content-Type': 'application/json; charset=utf-8',
  };
}
const json = (req, obj, status = 200) =>
  new Response(JSON.stringify(obj), { status, headers: corsHeaders(req) });

function b64encode(bytes) {
  let s = '';
  bytes.forEach(b => (s += String.fromCharCode(b)));
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64decode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  const bin = atob(str);
  return Uint8Array.from(bin, c => c.charCodeAt(0));
}
function randBytes(n) {
  const a = new Uint8Array(n);
  crypto.getRandomValues(a);
  return a;
}
function hex(bytes) {
  return [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');
}
async function hashPassword(password, salt) {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITERS, hash: 'SHA-256' },
    key, 256
  );
  return new Uint8Array(bits);
}
function constTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
function validUsername(u) { return /^[\u4e00-\u9fa5A-Za-z0-9_]{2,20}$/.test(u); }
function validEmail(e) { return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(e); }

async function rateLimit(env, ip, action, max) {
  const key = `rl:${ip}:${action}`;
  const cur = parseInt((await env.AUTH_KV.get(key)) || '0', 10);
  if (cur >= max) return false;
  await env.AUTH_KV.put(key, String(cur + 1), { expirationTtl: 3600 });
  return true;
}
function clientIp(req) {
  return req.headers.get('CF-Connecting-IP') || req.headers.get('X-Forwarded-For') || 'unknown';
}

async function handleRegister(req, env) {
  const body = await req.json().catch(() => null);
  if (!body) return json(req, { ok: false, error: '请求格式不对。' });
  const username = String(body.username || '').trim();
  const email = String(body.email || '').trim().toLowerCase();
  const password = String(body.password || '');
  if (!validUsername(username)) return json(req, { ok: false, error: '用户名 2–20 个字符，可用字母、数字、下划线或中文。' });
  if (!validEmail(email)) return json(req, { ok: false, error: '邮箱格式不对。' });
  if (password.length < 8 || password.length > 128) return json(req, { ok: false, error: '密码至少 8 位。' });
  if (!(await rateLimit(env, clientIp(req), 'register', 10))) {
    return json(req, { ok: false, error: '注册太频繁，请 1 小时后再试。' }, 429);
  }
  const ukey = `user:${username.toLowerCase()}`;
  const ekey = `email:${email}`;
  if (await env.AUTH_KV.get(ukey)) return json(req, { ok: false, error: '这个用户名已被注册。' });
  if (await env.AUTH_KV.get(ekey)) return json(req, { ok: false, error: '这个邮箱已被注册。' });
  const salt = randBytes(16);
  const hash = await hashPassword(password, salt);
  await env.AUTH_KV.put(ukey, JSON.stringify({
    username, email,
    salt: b64encode(salt), hash: b64encode(hash),
    iters: PBKDF2_ITERS, createdAt: new Date().toISOString(),
  }));
  await env.AUTH_KV.put(ekey, username.toLowerCase());
  const token = hex(randBytes(32));
  await env.AUTH_KV.put(`sess:${token}`, JSON.stringify({ username }), { expirationTtl: SESSION_DAYS * 86400 });
  return json(req, { ok: true, token, username });
}

async function handleLogin(req, env) {
  const body = await req.json().catch(() => null);
  if (!body) return json(req, { ok: false, error: '请求格式不对。' });
  const account = String(body.account || '').trim().toLowerCase();
  const password = String(body.password || '');
  if (!account || !password) return json(req, { ok: false, error: '请输入账号和密码。' });
  if (!(await rateLimit(env, clientIp(req), 'login', 20))) {
    return json(req, { ok: false, error: '登录太频繁，请 1 小时后再试。' }, 429);
  }
  let ukey = `user:${account}`;
  let raw = await env.AUTH_KV.get(ukey);
  if (!raw && account.includes('@')) {
    const uname = await env.AUTH_KV.get(`email:${account}`);
    if (uname) { ukey = `user:${uname}`; raw = await env.AUTH_KV.get(ukey); }
  }
  // 账号或密码不对时返回同一句话，不透露是哪一个错了
  if (!raw) return json(req, { ok: false, error: '账号或密码不对。' });
  const user = JSON.parse(raw);
  const hash = await hashPassword(password, b64decode(user.salt));
  if (!constTimeEqual(hash, b64decode(user.hash))) {
    return json(req, { ok: false, error: '账号或密码不对。' });
  }
  const token = hex(randBytes(32));
  await env.AUTH_KV.put(`sess:${token}`, JSON.stringify({ username: user.username }), { expirationTtl: SESSION_DAYS * 86400 });
  return json(req, { ok: true, token, username: user.username });
}

async function handleMe(req, env) {
  const auth = req.headers.get('Authorization') || '';
  const token = auth.replace(/^Bearer\s+/i, '');
  if (!token) return json(req, { ok: false, error: '未登录。' }, 401);
  const sess = await env.AUTH_KV.get(`sess:${token}`);
  if (!sess) return json(req, { ok: false, error: '登录已过期，请重新登录。' }, 401);
  return json(req, { ok: true, username: JSON.parse(sess).username });
}

async function handleLogout(req, env) {
  const auth = req.headers.get('Authorization') || '';
  const token = auth.replace(/^Bearer\s+/i, '');
  if (token) await env.AUTH_KV.delete(`sess:${token}`);
  return json(req, { ok: true });
}

export default {
  async fetch(req, env) {
    if (req.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders(req) });
    }
    if (!env.AUTH_KV) {
      return json(req, { ok: false, error: '后端 KV 未绑定，请在 Worker 设置里绑定 AUTH_KV。' }, 500);
    }
    const url = new URL(req.url);
    try {
      if (req.method === 'POST' && url.pathname === '/api/register') return handleRegister(req, env);
      if (req.method === 'POST' && url.pathname === '/api/login') return handleLogin(req, env);
      if (req.method === 'POST' && url.pathname === '/api/logout') return handleLogout(req, env);
      if (req.method === 'GET' && url.pathname === '/api/me') return handleMe(req, env);
      return json(req, { ok: false, error: '接口不存在。' }, 404);
    } catch (e) {
      return json(req, { ok: false, error: '服务器开小差了，请稍后再试。' }, 500);
    }
  },
};
