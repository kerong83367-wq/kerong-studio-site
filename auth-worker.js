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

// ---- 直连上游：GET /api/radar ----
// 页面每 60 秒调它拿最新持仓，不再依赖 GitHub Actions 定时快照
// （定时任务从未自动跑过）。上游是公开接口，服务端直抓不怕 CORS。
// 同一个 Worker 实例内缓存 30 秒，避免多人同时刷新时反复抓上游。
const UPSTREAM = 'https://coin.911quant.com/api/public/traders/2';
const RADAR_CACHE_SECONDS = 30;
let radarCache = { at: 0, data: null };
// ---- 30 天表现数据（币安官方接口直取，无需 key）----
// 911quant 只有持仓/权益，没有收益率、盈亏、跟单者盈亏这些官方口径
// 数字，所以表现数据单独走币安自己的公开接口：
// GET /bapi/futures/v1/public/future/copy-trade/lead-portfolio/performance
// 注意：Kopyon 走不通——它匿名限流每天每 IP 只有 10 次（Worker 共享
// 出口 IP 额度一下就耗尽），而且不回 Access-Control-Allow-Origin，
// 浏览器直调会被 CORS 拦；币安官方接口没这些问题。
// 币安返回的是百分比数字（roi 169.8 即 +169.80%），这里统一换算成
// 小数再交给页面。10 分钟缓存，失败时用上一次的数据兜底。
const BINANCE_PERF = 'https://www.binance.com/bapi/futures/v1/public/future/copy-trade/lead-portfolio/performance?portfolioId=5075281354358777856&timeRange=30D';
const STATS_CACHE_SECONDS = 600;
let statsCache = { at: 0, data: null };
async function fetchStats() {
  const now = Date.now();
  if (statsCache.data && now - statsCache.at < STATS_CACHE_SECONDS * 1000) return statsCache.data;
  try {
    const r = await fetch(BINANCE_PERF, {
      headers: { 'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36' },
      signal: AbortSignal.timeout(10000),
    });
    if (!r.ok) return statsCache.data;
    const d = (await r.json()).data;
    if (!d || d.roi === undefined || d.pnl === undefined) return statsCache.data;
    const stats = {
      roi: d.roi / 100, pnl: d.pnl, maxDrawdown: d.mdd / 100,
      copierPnl: d.copierPnl, winRate: d.winRate / 100, wins: d.winOrders,
      trades: d.totalOrder, sharpeRatio: parseFloat(d.sharpRatio),
      statsFetchedAt: new Date(now + 8 * 3600 * 1000).toISOString().replace('Z', '+08:00'),
    };
    statsCache = { at: now, data: stats };
    return stats;
  } catch (e) {
    return statsCache.data;
  }
}
async function handleRadar(req) {
  const now = Date.now();
  if (radarCache.data && now - radarCache.at < RADAR_CACHE_SECONDS * 1000) {
    return json(req, radarCache.data);
  }
  try {
    const r = await fetch(UPSTREAM, {
      headers: { 'User-Agent': 'kerong-radar/1.0' },
      signal: AbortSignal.timeout(10000),
    });
    if (!r.ok) throw new Error('upstream HTTP ' + r.status);
    const d = await r.json();
    if (d.id !== 2 || d.name !== '熬鹰资本') throw new Error('upstream data mismatch');
    d.fetchedAt = new Date(now + 8 * 3600 * 1000).toISOString().replace('Z', '+08:00');
    d.source = UPSTREAM;
    d.live = true;
    const stats = await fetchStats();
    if (stats) d.stats = stats;
    radarCache = { at: now, data: d };
    return json(req, d);
  } catch (e) {
    return json(req, { ok: false, error: '上游暂不可用，请稍后再试。' }, 502);
  }
}

// ============================================================
// 实盘跟单（API 自动执行）
// ------------------------------------------------------------
// 路线：币安官方跟单名额已满（1000/1000），改走用户自己的币安
// API 密钥自动镜像。执行器挂在本 Worker 的 cron 上（需在
// Cloudflare 面板给本 Worker 加 Cron Trigger：*/1 * * * *）：
// 每分钟拉带单员持仓（911quant 上游）→ 拉用户币安合约账户持仓
// → 按「跟单资金上限 ÷ 带单员权益」的比例算目标仓位 → 市价单
// 把账户仓位对齐到目标（对账式镜像，漏掉的开仓事件会被下一轮
// 自动补齐，不靠逐条事件追赶）。
// 安全设计：
// - 密钥经子页面表单 HTTPS 直传本 Worker、存 KV，永不回传、
//   不进页面与日志；状态接口只回密钥后 4 位。
// - 默认演练模式（dryRun=true）：只算单、记日志，绝不下单；
//   用户在子页面明确切换后才实盘。
// - 护栏：跟单资金上限、单轮最多 10 单、小额调整（<15 USDT 名
//   义）不追、保证金不足时按比例缩小、数据源拉不到就整轮跳过
//   （绝不用旧数据下单）、一键平仓并停止、随时解绑。
// - 已知边界（子页面已向用户明示）：上游检出延迟 2–3 分钟、
//   市价单滑点、Cloudflare 出口 IP 不固定导致密钥无法设 IP 白
//   名单（务必只开合约交易权限、关闭提现）。
// ============================================================
const COPY_HOSTS = ['https://fapi.binance.com', 'https://www.binance.com/fapi'];
const COPY_MAX_ORDERS_PER_RUN = 10;
const COPY_MIN_ADJUST_NOTIONAL = 15; // 小于这个名义额的仓位偏差不追（省手续费、防抖动），全平除外

async function hmacHex(secret, msg) {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(msg));
  return hex(new Uint8Array(sig));
}
async function bnFetch(keys, host, method, path, params, signed) {
  const qs = new URLSearchParams(params || {});
  if (signed) {
    qs.set('timestamp', String(Date.now()));
    qs.set('recvWindow', '10000');
    qs.set('signature', await hmacHex(keys.secret, qs.toString()));
  }
  const r = await fetch(host + path + '?' + qs.toString(), {
    method,
    headers: { 'X-MBX-APIKEY': keys.key, 'User-Agent': 'kerong-radar-copy/1.0' },
    signal: AbortSignal.timeout(12000),
  });
  const text = await r.text();
  let data;
  try { data = JSON.parse(text); } catch (e) { data = { raw: text }; }
  if (!r.ok) {
    const err = new Error((data && data.msg) || ('币安接口 HTTP ' + r.status));
    err.code = data && data.code;
    err.status = r.status;
    throw err;
  }
  return data;
}
async function bnTryHosts(keys, method, path, params, signed) {
  // 先用存下来的可用 host；失败（网络/451/403）自动换另一个并回写
  const order = keys.host ? [keys.host, ...COPY_HOSTS.filter(h => h !== keys.host)] : COPY_HOSTS;
  let lastErr = null;
  for (const host of order) {
    try {
      const data = await bnFetch(keys, host, method, path, params, signed);
      keys.host = host;
      return data;
    } catch (e) {
      lastErr = e;
      if (e.code === -1022 || e.code === -2015) throw e; // 密钥本身的问题，换 host 没用
    }
  }
  throw lastErr || new Error('币安接口不可达');
}

/* COPYPURE:START —— 纯计算部分（无 IO，本地可单测） */
function copyRoundStep(qty, step) {
  if (!step || step <= 0) return qty;
  return parseFloat((Math.floor(qty / step) * step).toFixed(8));
}
function copyLeverageFor(settings, leaderEffLev) {
  if (settings.leverageMode === 'follow') {
    const v = Math.round(leaderEffLev || 5);
    return Math.min(10, Math.max(1, v));
  }
  return Math.min(10, Math.max(1, parseInt(settings.fixedLeverage, 10) || 5));
}
function copyDesiredPositions(leaderPositions, leaderEquity, capitalCap) {
  // 目标仓位（带符号：多 + / 空 −）= 带单员数量 × (资金上限 ÷ 带单员权益)
  const out = {};
  if (!leaderEquity || leaderEquity <= 0 || !capitalCap || capitalCap <= 0) return out;
  const ratio = capitalCap / leaderEquity;
  for (const p of leaderPositions || []) {
    const signed = (p.side === 'LONG' ? 1 : -1) * p.quantity * ratio;
    out[p.symbol + '_' + p.side] = { symbol: p.symbol, side: p.side, qty: signed, markPrice: p.markPrice, ratio };
  }
  return out;
}
function copyComputeOrders(desired, actual, marks, filters) {
  // desired/actual: {SYM_SIDE: {symbol, side, qty(带符号), markPrice?}}
  // 返回 intents: {symbol, side, kind: OPEN|ADJUST|CLOSE|WARN, orderSide, qty, reduceOnly, notional, note}
  const intents = [];
  const keys = new Set([...Object.keys(desired || {}), ...Object.keys(actual || {})]);
  const actualBySymbol = {};
  for (const k in actual || {}) actualBySymbol[actual[k].symbol] = actual[k];
  const desiredBySymbol = {};
  for (const k in desired || {}) desiredBySymbol[desired[k].symbol] = desired[k];
  for (const key of keys) {
    const d = desired[key];
    const a = actual[key];
    const symbol = (d || a).symbol;
    const side = (d || a).side;
    // 同品种反向：账户里还持着反方向的仓（一向持仓模式下同品种只能有一边）。
    // 本轮只平旧仓，新方向等下一轮再开，避免一张市价单把平仓和开仓搅在一起。
    if (!a && d && actualBySymbol[symbol] && actualBySymbol[symbol].side !== side) continue;
    const mark = (marks && marks[symbol]) || (d && d.markPrice) || (a && a.markPrice) || 0;
    const f = (filters && filters[symbol]) || {};
    const step = f.stepSize || 0;
    const minNotional = f.minNotional || 5;
    const dQty = d ? d.qty : 0;
    const aQty = a ? a.qty : 0;
    const delta = dQty - aQty;
    if (Math.abs(delta) < 1e-12 || !mark) continue;
    if (dQty === 0) {
      // 全平：不受最小调整额限制；数量按步进取整后仍须覆盖实际仓位（取整可能略小，剩余尘仓下一轮继续）
      const q = copyRoundStep(Math.abs(aQty), step) || Math.abs(aQty);
      const flip = desiredBySymbol[symbol] && desiredBySymbol[symbol].side !== side;
      intents.push({ symbol, side, kind: 'CLOSE', orderSide: aQty > 0 ? 'SELL' : 'BUY', qty: q, reduceOnly: true, notional: q * mark, note: flip ? '方向反转，先平仓，下一轮再开新方向' : '带单员已平仓，全平跟单仓' });
      continue;
    }
    if (aQty !== 0 && Math.sign(aQty) !== Math.sign(dQty)) {
      // 方向反转：本轮先全平，下一轮再按新方向开（避免一张单里又平又开说不清）
      const q = copyRoundStep(Math.abs(aQty), step) || Math.abs(aQty);
      intents.push({ symbol, side: aQty > 0 ? 'LONG' : 'SHORT', kind: 'CLOSE', orderSide: aQty > 0 ? 'SELL' : 'BUY', qty: q, reduceOnly: true, notional: q * mark, note: '方向反转，先平仓，下一轮再开新方向' });
      continue;
    }
    const rawQty = Math.abs(delta);
    const notionalRaw = rawQty * mark;
    if (notionalRaw < Math.max(minNotional, COPY_MIN_ADJUST_NOTIONAL)) continue; // 小偏差不追
    const q = copyRoundStep(rawQty, step);
    if (q <= 0 || q * mark < minNotional) continue;
    const reducing = aQty !== 0 && Math.sign(delta) !== Math.sign(aQty);
    intents.push({
      symbol, side, kind: aQty === 0 ? 'OPEN' : 'ADJUST',
      orderSide: delta > 0 ? 'BUY' : 'SELL', qty: q, reduceOnly: reducing,
      notional: q * mark, note: aQty === 0 ? '新开仓' : (reducing ? '减仓对齐' : '加仓对齐'),
    });
  }
  return intents;
}
/* COPYPURE:END */

async function copyGetJson(env, key, fallback) {
  const raw = await env.AUTH_KV.get(key);
  if (!raw) return fallback;
  try { return JSON.parse(raw); } catch (e) { return fallback; }
}
async function requireCopyUser(req, env) {
  const auth = req.headers.get('Authorization') || '';
  const token = auth.replace(/^Bearer\s+/i, '');
  if (!token) return null;
  const sess = await env.AUTH_KV.get(`sess:${token}`);
  return sess ? JSON.parse(sess).username : null;
}
function copyLog(state, entry) {
  state.log = state.log || [];
  state.log.unshift(Object.assign({ at: new Date().toISOString() }, entry));
  state.log = state.log.slice(0, 50);
}
async function copyFetchLeader() {
  const r = await fetch(UPSTREAM, { headers: { 'User-Agent': 'kerong-radar/1.0' }, signal: AbortSignal.timeout(10000) });
  if (!r.ok) throw new Error('上游 HTTP ' + r.status);
  const d = await r.json();
  if (d.id !== 2 || !Array.isArray(d.positions)) throw new Error('上游数据异常');
  return d;
}
async function copyFetchFilters(env, keys) {
  const cached = await copyGetJson(env, 'copy:exchangeinfo', null);
  if (cached && cached.at && Date.now() - cached.at < 24 * 3600 * 1000) return cached.filters;
  const info = await bnTryHosts(keys, 'GET', '/fapi/v1/exchangeInfo', {}, false);
  const filters = {};
  for (const s of info.symbols || []) {
    if (s.quoteAsset !== 'USDT' || s.contractType !== 'PERPETUAL') continue;
    const lot = (s.filters || []).find(x => x.filterType === 'LOT_SIZE');
    const notional = (s.filters || []).find(x => x.filterType === 'MIN_NOTIONAL');
    filters[s.symbol] = {
      stepSize: lot ? parseFloat(lot.stepSize) : 0,
      minQty: lot ? parseFloat(lot.minQty) : 0,
      minNotional: notional ? parseFloat(notional.notional) : 5,
    };
  }
  await env.AUTH_KV.put('copy:exchangeinfo', JSON.stringify({ at: Date.now(), filters }));
  return filters;
}
async function runCopyExecutor(env, username, opts) {
  opts = opts || {};
  const keys = await copyGetJson(env, `copy:${username}:keys`, null);
  if (!keys) return { ran: false, reason: '未绑定密钥' };
  const settings = await copyGetJson(env, `copy:${username}:settings`, null) ||
    { capitalCap: 300, leverageMode: 'fixed', fixedLeverage: 5, enabled: false, dryRun: true };
  if (!settings.enabled && !opts.manual) return { ran: false, reason: '未启用' };
  const state = await copyGetJson(env, `copy:${username}:state`, { log: [] });
  const runAt = new Date().toISOString();
  let ordersPlaced = 0;
  let changed = !!opts.manual; // 手动触发的一轮必落盘，状态页立刻能看到最新持仓
  try {
    const leader = await copyFetchLeader();
    const balances = await bnTryHosts(keys, 'GET', '/fapi/v2/balance', {}, true);
    const usdt = (balances || []).find(b => b.asset === 'USDT');
    if (!usdt) throw new Error('账户里没有 USDT 合约余额（或密钥没有合约读取权限）');
    const avail = parseFloat(usdt.availableBalance);
    const posRisk = await bnTryHosts(keys, 'GET', '/fapi/v2/positionRisk', {}, true);
    const filters = await copyFetchFilters(env, keys);
    const marks = {};
    (leader.positions || []).forEach(p => { marks[p.symbol] = p.markPrice; });
    // 账户实际仓位（带符号），只管理「带单员当前持有 ∪ 历史跟过的」品种，避免碰用户自己手动开的其他仓
    const tracked = new Set(Object.keys(state.mirrored || {}));
    (leader.positions || []).forEach(p => tracked.add(p.symbol + '_' + p.side));
    const actual = {};
    const posSnapshot = [];
    for (const pr of posRisk || []) {
      const amt = parseFloat(pr.positionAmt);
      if (!amt) continue;
      const side = amt > 0 ? 'LONG' : 'SHORT';
      const key = pr.symbol + '_' + side;
      const mark = parseFloat(pr.markPrice) || marks[pr.symbol] || 0;
      if (mark) marks[pr.symbol] = mark;
      posSnapshot.push({ symbol: pr.symbol, side, qty: Math.abs(amt), entryPrice: parseFloat(pr.entryPrice), markPrice: mark, unrealizedPnl: parseFloat(pr.unRealizedProfit), managed: tracked.has(key) });
      if (tracked.has(key)) actual[key] = { symbol: pr.symbol, side, qty: amt, markPrice: mark };
    }
    state.positions = posSnapshot;
    state.account = { usdtAvailable: avail, usdtBalance: parseFloat(usdt.balance) };
    // 目标仓位 + 保证金护栏：预计占用超过可用余额 95% 就等比缩小
    let desired = copyDesiredPositions(leader.positions, leader.equity, settings.capitalCap);
    const lev = copyLeverageFor(settings, leader.effectiveLeverage);
    let marginNeed = 0;
    for (const k in desired) marginNeed += Math.abs(desired[k].qty) * (marks[desired[k].symbol] || desired[k].markPrice || 0) / lev;
    if (marginNeed > avail * 0.95 && marginNeed > 0) {
      const scale = (avail * 0.95) / marginNeed;
      for (const k in desired) desired[k].qty *= scale;
      copyLog(state, { action: '护栏', note: '可用保证金不足以全额镜像，已按 ' + Math.round(scale * 100) + '% 比例缩小目标仓位' });
      changed = true;
    }
    const intents = copyComputeOrders(desired, actual, marks, filters);
    const levSetDone = {};
    for (const it of intents.slice(0, COPY_MAX_ORDERS_PER_RUN)) {
      if (settings.dryRun) {
        copyLog(state, { action: '演练', symbol: it.symbol, side: it.side, kind: it.kind, qty: it.qty, price: marks[it.symbol] || null, note: it.note + '（演练模式，未真实下单）' });
        changed = true;
        continue;
      }
      try {
        if (!levSetDone[it.symbol]) {
          levSetDone[it.symbol] = true;
          try { await bnTryHosts(keys, 'POST', '/fapi/v1/marginType', { symbol: it.symbol, marginType: 'CROSSED' }, true); } catch (e) { if (e.code !== -4046) throw e; }
          try { await bnTryHosts(keys, 'POST', '/fapi/v1/leverage', { symbol: it.symbol, leverage: lev }, true); } catch (e) { if (e.code !== -4059) throw e; }
        }
        const params = { symbol: it.symbol, side: it.orderSide, type: 'MARKET', quantity: String(it.qty), newClientOrderId: 'radar' + Date.now() + Math.floor(Math.random() * 1000) };
        if (it.reduceOnly) params.reduceOnly = 'true';
        const res = await bnTryHosts(keys, 'POST', '/fapi/v1/order', params, true);
        const execQty = parseFloat(res.executedQty || it.qty);
        const avg = parseFloat(res.avgPrice || 0) || (parseFloat(res.cumQuote || 0) > 0 && execQty > 0 ? parseFloat(res.cumQuote) / execQty : (marks[it.symbol] || 0));
        copyLog(state, { action: '下单', symbol: it.symbol, side: it.side, kind: it.kind, qty: execQty, price: avg, note: it.note, orderId: res.orderId });
        ordersPlaced++;
      } catch (e) {
        copyLog(state, { action: '下单失败', symbol: it.symbol, side: it.side, kind: it.kind, qty: it.qty, note: (e.code ? '[' + e.code + '] ' : '') + e.message });
      }
      changed = true;
    }
    if (intents.length > COPY_MAX_ORDERS_PER_RUN) {
      copyLog(state, { action: '护栏', note: '本轮订单数超过上限 ' + COPY_MAX_ORDERS_PER_RUN + '，其余下一轮继续' });
      changed = true;
    }
    // 记录本轮镜像目标（供下一轮 tracked 判断与状态展示）
    state.mirrored = {};
    for (const k in desired) state.mirrored[k] = desired[k].qty;
    state.lastRun = runAt;
    state.lastError = null;
    state.lastLev = lev;
  } catch (e) {
    state.lastRun = runAt;
    state.lastError = (e.code ? '[' + e.code + '] ' : '') + e.message;
    copyLog(state, { action: '异常', note: state.lastError });
    changed = true;
  }
  // KV 写节流：有动作/异常必写；否则最多 10 分钟写一次心跳
  const lastWrite = state._lastWrite || 0;
  if (changed || Date.now() - lastWrite > 10 * 60 * 1000) {
    state._lastWrite = Date.now();
    await env.AUTH_KV.put(`copy:${username}:state`, JSON.stringify(state));
    if (keys.host) await env.AUTH_KV.put(`copy:${username}:keys`, JSON.stringify(keys));
  }
  return { ran: true, ordersPlaced };
}
async function runAllCopyExecutors(env) {
  const users = await copyGetJson(env, 'copy:users', []);
  for (const u of users) {
    try { await runCopyExecutor(env, u, {}); } catch (e) { /* 单个用户失败不影响其他 */ }
  }
}

async function handleCopyBind(req, env) {
  const username = await requireCopyUser(req, env);
  if (!username) return json(req, { ok: false, error: '请先登录本站账号。' }, 401);
  const body = await req.json().catch(() => null);
  if (!body) return json(req, { ok: false, error: '请求格式不对。' });
  const key = String(body.apiKey || '').trim();
  const secret = String(body.apiSecret || '').trim();
  if (!/^[A-Za-z0-9]{32,128}$/.test(key) || !/^[A-Za-z0-9]{32,128}$/.test(secret)) {
    return json(req, { ok: false, error: 'API Key / Secret 格式不对（应为 32 位以上字母数字）。' });
  }
  if (!(await rateLimit(env, clientIp(req), 'copybind', 10))) {
    return json(req, { ok: false, error: '绑定尝试太频繁，请 1 小时后再试。' }, 429);
  }
  const keys = { key, secret, host: null, boundAt: new Date().toISOString() };
  // 探活：逐个 host 试签名读取合约余额，哪个通存哪个
  let usdt = null;
  let lastErr = null;
  for (const host of COPY_HOSTS) {
    try {
      const balances = await bnFetch(keys, host, 'GET', '/fapi/v2/balance', {}, true);
      usdt = (balances || []).find(b => b.asset === 'USDT');
      keys.host = host;
      lastErr = null;
      break;
    } catch (e) { lastErr = e; }
  }
  if (!keys.host) {
    const msg = lastErr && lastErr.code === -2015 ? '币安拒绝了这把密钥：可能没开合约权限、密钥无效，或 IP 受限（确认创建时不要勾「限制 IP」以外的异常设置）。'
      : lastErr && lastErr.code === -1022 ? 'Secret 不对，签名校验没通过，请重新复制完整的 Secret。'
      : '连不上币安合约接口（' + (lastErr ? lastErr.message : '未知错误') + '），请稍后再试。';
    return json(req, { ok: false, error: msg });
  }
  await env.AUTH_KV.put(`copy:${username}:keys`, JSON.stringify(keys));
  const users = await copyGetJson(env, 'copy:users', []);
  if (!users.includes(username)) { users.push(username); await env.AUTH_KV.put('copy:users', JSON.stringify(users)); }
  const existing = await copyGetJson(env, `copy:${username}:settings`, null);
  if (!existing) {
    await env.AUTH_KV.put(`copy:${username}:settings`, JSON.stringify({ capitalCap: 300, leverageMode: 'fixed', fixedLeverage: 5, enabled: false, dryRun: true }));
  }
  return json(req, {
    ok: true, host: keys.host,
    usdtBalance: usdt ? parseFloat(usdt.balance) : null,
    usdtAvailable: usdt ? parseFloat(usdt.availableBalance) : null,
    note: usdt ? '密钥可用，已读取到合约 USDT 余额。' : '密钥签名通过，但账户里没读到 USDT 合约余额（可能还没划转资金到合约账户）。',
  });
}
async function handleCopyStatus(req, env) {
  const username = await requireCopyUser(req, env);
  if (!username) return json(req, { ok: false, error: '请先登录本站账号。' }, 401);
  const keys = await copyGetJson(env, `copy:${username}:keys`, null);
  if (!keys) return json(req, { ok: true, bound: false });
  const settings = await copyGetJson(env, `copy:${username}:settings`, null);
  const state = await copyGetJson(env, `copy:${username}:state`, null);
  return json(req, {
    ok: true, bound: true, keyLast4: keys.key.slice(-4), host: keys.host, boundAt: keys.boundAt,
    settings, state: state ? { lastRun: state.lastRun, lastError: state.lastError, account: state.account, positions: state.positions, log: state.log, lastLev: state.lastLev } : null,
  });
}
async function handleCopySettings(req, env) {
  const username = await requireCopyUser(req, env);
  if (!username) return json(req, { ok: false, error: '请先登录本站账号。' }, 401);
  const keys = await copyGetJson(env, `copy:${username}:keys`, null);
  if (!keys) return json(req, { ok: false, error: '请先绑定 API 密钥。' });
  const body = await req.json().catch(() => null);
  if (!body) return json(req, { ok: false, error: '请求格式不对。' });
  const cur = await copyGetJson(env, `copy:${username}:settings`, null) ||
    { capitalCap: 300, leverageMode: 'fixed', fixedLeverage: 5, enabled: false, dryRun: true };
  if (body.capitalCap !== undefined) {
    const v = parseFloat(body.capitalCap);
    if (!isFinite(v) || v < 50 || v > 100000) return json(req, { ok: false, error: '跟单资金上限要在 50–100,000 USDT 之间。' });
    cur.capitalCap = v;
  }
  if (body.leverageMode !== undefined) {
    if (!['fixed', 'follow'].includes(body.leverageMode)) return json(req, { ok: false, error: '杠杆模式不对。' });
    cur.leverageMode = body.leverageMode;
  }
  if (body.fixedLeverage !== undefined) {
    const v = parseInt(body.fixedLeverage, 10);
    if (!isFinite(v) || v < 1 || v > 10) return json(req, { ok: false, error: '固定杠杆要在 1–10 倍之间。' });
    cur.fixedLeverage = v;
  }
  if (body.enabled !== undefined) cur.enabled = !!body.enabled;
  if (body.dryRun !== undefined) cur.dryRun = !!body.dryRun;
  await env.AUTH_KV.put(`copy:${username}:settings`, JSON.stringify(cur));
  return json(req, { ok: true, settings: cur });
}
async function handleCopyRun(req, env) {
  const username = await requireCopyUser(req, env);
  if (!username) return json(req, { ok: false, error: '请先登录本站账号。' }, 401);
  const r = await runCopyExecutor(env, username, { manual: true });
  return json(req, { ok: true, result: r });
}
async function handleCopyCloseAll(req, env) {
  const username = await requireCopyUser(req, env);
  if (!username) return json(req, { ok: false, error: '请先登录本站账号。' }, 401);
  const keys = await copyGetJson(env, `copy:${username}:keys`, null);
  if (!keys) return json(req, { ok: false, error: '请先绑定 API 密钥。' });
  // 先停跟单，防止平完又被下一轮 cron 重新开回去
  const settings = await copyGetJson(env, `copy:${username}:settings`, null);
  if (settings) { settings.enabled = false; await env.AUTH_KV.put(`copy:${username}:settings`, JSON.stringify(settings)); }
  const state = await copyGetJson(env, `copy:${username}:state`, { log: [] });
  const results = [];
  try {
    const posRisk = await bnTryHosts(keys, 'GET', '/fapi/v2/positionRisk', {}, true);
    const tracked = new Set(Object.keys(state.mirrored || {}));
    for (const pr of posRisk || []) {
      const amt = parseFloat(pr.positionAmt);
      if (!amt) continue;
      const side = amt > 0 ? 'LONG' : 'SHORT';
      if (!tracked.has(pr.symbol + '_' + side)) continue; // 只平跟单管的仓，不动用户手动仓
      const filters = await copyFetchFilters(env, keys);
      const f = filters[pr.symbol] || {};
      const q = copyRoundStep(Math.abs(amt), f.stepSize) || Math.abs(amt);
      try {
        const res = await bnTryHosts(keys, 'POST', '/fapi/v1/order', { symbol: pr.symbol, side: amt > 0 ? 'SELL' : 'BUY', type: 'MARKET', quantity: String(q), reduceOnly: 'true', newClientOrderId: 'radarclose' + Date.now() }, true);
        results.push({ symbol: pr.symbol, side, qty: q, ok: true, orderId: res.orderId });
        copyLog(state, { action: '一键平仓', symbol: pr.symbol, side, qty: q, note: '用户手动触发一键平仓并停止跟单' });
      } catch (e) {
        results.push({ symbol: pr.symbol, side, qty: q, ok: false, error: e.message });
        copyLog(state, { action: '平仓失败', symbol: pr.symbol, side, qty: q, note: e.message });
      }
    }
    state.mirrored = {};
    state.lastRun = new Date().toISOString();
    state._lastWrite = Date.now();
    await env.AUTH_KV.put(`copy:${username}:state`, JSON.stringify(state));
    if (keys.host) await env.AUTH_KV.put(`copy:${username}:keys`, JSON.stringify(keys));
  } catch (e) {
    return json(req, { ok: false, error: '平仓执行失败：' + e.message });
  }
  return json(req, { ok: true, results, note: '跟单已停止；上面是跟单仓位的平仓结果。' });
}
async function handleCopyUnbind(req, env) {
  const username = await requireCopyUser(req, env);
  if (!username) return json(req, { ok: false, error: '请先登录本站账号。' }, 401);
  await env.AUTH_KV.delete(`copy:${username}:keys`);
  await env.AUTH_KV.delete(`copy:${username}:settings`);
  await env.AUTH_KV.delete(`copy:${username}:state`);
  const users = await copyGetJson(env, 'copy:users', []);
  await env.AUTH_KV.put('copy:users', JSON.stringify(users.filter(u => u !== username)));
  return json(req, { ok: true });
}

export default {
  async scheduled(event, env, ctx) {
    ctx.waitUntil(runAllCopyExecutors(env));
  },
  async fetch(req, env) {
    if (req.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders(req) });
    }
    const url = new URL(req.url);
    // 直连接口不依赖 KV，放前面
    if (req.method === 'GET' && url.pathname === '/api/radar') return handleRadar(req);
    if (!env.AUTH_KV) {
      return json(req, { ok: false, error: '后端 KV 未绑定，请在 Worker 设置里绑定 AUTH_KV。' }, 500);
    }
    try {
      if (req.method === 'POST' && url.pathname === '/api/register') return handleRegister(req, env);
      if (req.method === 'POST' && url.pathname === '/api/login') return handleLogin(req, env);
      if (req.method === 'POST' && url.pathname === '/api/logout') return handleLogout(req, env);
      if (req.method === 'GET' && url.pathname === '/api/me') return handleMe(req, env);
      if (req.method === 'POST' && url.pathname === '/api/copy/bind') return handleCopyBind(req, env);
      if (req.method === 'GET' && url.pathname === '/api/copy/status') return handleCopyStatus(req, env);
      if (req.method === 'POST' && url.pathname === '/api/copy/settings') return handleCopySettings(req, env);
      if (req.method === 'POST' && url.pathname === '/api/copy/run') return handleCopyRun(req, env);
      if (req.method === 'POST' && url.pathname === '/api/copy/closeall') return handleCopyCloseAll(req, env);
      if (req.method === 'POST' && url.pathname === '/api/copy/unbind') return handleCopyUnbind(req, env);
      return json(req, { ok: false, error: '接口不存在。' }, 404);
    } catch (e) {
      return json(req, { ok: false, error: '服务器开小差了，请稍后再试。' }, 500);
    }
  },
};
