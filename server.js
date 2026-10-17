'use strict';
/*
 * free-max —— 把 Render 免费档（0.1 CPU / 512MB / 无 SSH / 无 worker / 无 cron）榨成一个全能节点：
 *
 *   1) Web    : 对外 HTTP 服务（免费档唯一的公网入口，固定 443 → PORT）
 *   2) Worker : 进程内 worker_threads 池，顶掉「背景 worker 没有免费档、最低 $7/月」
 *   3) Cron   : 进程内 5 段 cron 解析器，顶掉「cron job 按分钟计费」
 *   4) Shell  : token 保护的 /admin/exec，顶掉「Shell/SSH 只有付费实例才有」
 *   5) 持久化 : 零依赖 Postgres 客户端（SCRAM-SHA-256）+ 零依赖 Key Value（RESP），
 *              顶掉「免费档没有持久盘」——重启后数据仍在（看 /admin/stats 的 db.boots）
 *
 * 零 npm 依赖 → 构建几乎不烧 pipeline minutes，冷启动更快，512MB 里更省。
 *
 * 关掉任一项（都在环境变量里，改完 Render 自动重新部署）：
 *   ADMIN_TOKEN 不设      → /admin/* 全部返回 404（Shell + 任务管理一起关）
 *   WORKER_POOL=0         → 不起 worker 线程
 *   CRON_JOBS 留空        → 不跑任何定时任务
 *   RSS_LIMIT_MB 不设/0   → 关掉内存看门狗
 *   DATABASE_URL 不设     → /admin/persist 与 /admin/deps 的 db 段返回明确错误，其余照常
 *   REDIS_URL 不设        → /admin/kv 同上
 */

const http = require('node:http');
const net = require('node:net');
const tls = require('node:tls');
const crypto = require('node:crypto');
const { execFile } = require('node:child_process');
const { Worker, isMainThread, parentPort, threadId } = require('node:worker_threads');

const PORT = Number(process.env.PORT || 10000);
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || '';
const WORKER_POOL = Math.max(0, Number(process.env.WORKER_POOL ?? 2));
const EXEC_TIMEOUT_MS = Number(process.env.EXEC_TIMEOUT_MS || 20000);
const EXEC_MAX_BUFFER = Number(process.env.EXEC_MAX_BUFFER || 1024 * 1024);
const RSS_LIMIT_MB = Number(process.env.RSS_LIMIT_MB || 0);
const CRON_TICK_MS = Number(process.env.CRON_TICK_MS || 20000);
// Render 上是 Linux（/bin/sh）；本机 Windows 上跑得通才方便验证
const IS_WIN = process.platform === 'win32';
const SHELL_BIN = process.env.SHELL_BIN || (IS_WIN ? 'cmd.exe' : '/bin/sh');
const SHELL_FLAG = process.env.SHELL_FLAG || (SHELL_BIN.indexOf('cmd') >= 0 ? '/c' : '-c');
const MAX_JOBS_KEPT = 200;
const DEFAULT_CRON = 'keepalive=*/10 * * * *';
// 免费 Postgres（1GB / 30 天到期）与免费 Key Value（25MB）连接串，由 Render 注入。
// 不设时下面所有持久化端点返回明确错误，其余功能完全不受影响（本地 P0/P3 判据因此照旧全绿）。
const PG_URL = process.env.DATABASE_URL || '';
const KV_URL = process.env.REDIS_URL || '';

// ============================ worker 侧 ============================
// 同一个文件既是主进程也是 worker：省一个文件，也让镜像更小。
if (!isMainThread) {
  parentPort.on('message', (job) => {
    try {
      parentPort.postMessage({ id: job.id, ok: true, out: runJob(job) });
    } catch (err) {
      parentPort.postMessage({ id: job.id, ok: false, err: String((err && err.stack) || err) });
    }
  });
}

// 这里放你原本要丢给「背景 worker」的活。默认实现只回执，方便先验证链路。
function runJob(job) {
  const started = Date.now();
  return {
    name: job.name,
    payload: job.payload === undefined ? null : job.payload,
    threadId,
    at: new Date().toISOString(),
    ms: Date.now() - started,
  };
}

// ============================ 零依赖 Postgres ============================
// 免费档没有装 npm 依赖的余量，也不引 pg 驱动：直接说 Postgres 线协议
// （StartupMessage + SCRAM-SHA-256 认证 + 简单查询）。只实现「够用且不越权」的部分：
// 只有下面两个函数能发 SQL，全是本文件里写死的语句，不暴露任意 SQL 入口。
const pgState = { ok: false, boots: null, lastError: PG_URL ? null : 'DATABASE_URL 未设置', lastQueryMs: null };

function cstr(s) { return Buffer.concat([Buffer.from(String(s), 'utf8'), Buffer.from([0])]); }
function i32(n) { const b = Buffer.alloc(4); b.writeInt32BE(n); return b; }
function i16(n) { const b = Buffer.alloc(2); b.writeInt16BE(n); return b; }
function pgFrame(type, payload) { return Buffer.concat([Buffer.from(type, 'ascii'), i32(payload.length + 4), payload]); }
function sqlLit(s) { return "'" + String(s).replace(/'/g, "''") + "'"; }

function parsePgUrl(raw) {
  const u = new URL(raw);
  const sslmode = u.searchParams.get('sslmode') || process.env.PGSSLMODE || '';
  return {
    host: u.hostname,
    port: Number(u.port || 5432),
    user: decodeURIComponent(u.username || ''),
    password: decodeURIComponent(u.password || ''),
    database: decodeURIComponent((u.pathname || '').replace(/^\//, '')) || 'postgres',
    ssl: /require|verify/i.test(sslmode),
  };
}

function pgOpen(cfg) {
  return new Promise((resolve, reject) => {
    const sock = cfg.ssl
      ? tls.connect({ host: cfg.host, port: cfg.port, servername: cfg.host, ALPNProtocols: ['http/1.1'], rejectUnauthorized: false })
      : net.connect({ host: cfg.host, port: cfg.port });
    let buf = Buffer.alloc(0);
    const queue = [];
    const waiters = [];
    let failure = null;
    const fail = (e) => {
      failure = failure || e;
      while (waiters.length) waiters.shift()(Promise.reject(failure));
    };
    sock.on('data', (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      for (;;) {
        if (buf.length < 5) break;
        const len = buf.readInt32BE(1);
        if (buf.length < 1 + len) break;
        const msg = { type: String.fromCharCode(buf[0]), payload: buf.subarray(5, 1 + len) };
        buf = buf.subarray(1 + len);
        const w = waiters.shift();
        if (w) w(Promise.resolve(msg)); else queue.push(msg);
      }
    });
    sock.on('error', (e) => fail(e));
    sock.on('close', () => fail(new Error('pg 连接被关闭')));
    sock.setTimeout(20000, () => fail(new Error('pg 空闲超时')));
    const next = (timeoutMs = 20000) => {
      if (queue.length) return Promise.resolve(queue.shift());
      if (failure) return Promise.reject(failure);
      return new Promise((res, rej) => {
        const t = setTimeout(() => rej(new Error('pg 等消息超时')), timeoutMs);
        waiters.push((p) => { clearTimeout(t); p.then(res, rej); });
      });
    };
    const startup = Buffer.concat([
      i32(196608),
      cstr('user'), cstr(cfg.user),
      cstr('database'), cstr(cfg.database),
      cstr('client_encoding'), cstr('UTF8'),
      cstr('application_name'), cstr('free-max'),
      Buffer.from([0]),
    ]);
    sock.write(Buffer.concat([i32(startup.length + 4), startup]));
    resolve({ sock, next, write: (b) => sock.write(b), close: () => { try { sock.end(); } catch { /* 已关 */ } } });
  });
}

function pgErrorOf(payload) {
  // ErrorResponse: 一串 (byte code, cstr value)，以 0 结尾
  const parts = [];
  let i = 0;
  while (i < payload.length && payload[i] !== 0) {
    const code = String.fromCharCode(payload[i]);
    const end = payload.indexOf(0, i + 1);
    if (end < 0) break;
    parts.push(code + '=' + payload.subarray(i + 1, end).toString('utf8'));
    i = end + 1;
  }
  return parts.join(' ') || 'pg 未知错误';
}

function parseScramFields(text) {
  const out = {};
  for (const kv of String(text).split(',')) {
    const eq = kv.indexOf('=');
    if (eq > 0) out[kv.slice(0, eq)] = kv.slice(eq + 1);
  }
  return out;
}

async function pgAuth(conn, cfg) {
  const nonce = crypto.randomBytes(18).toString('base64');
  const clientFirstBare = 'n=,r=' + nonce;
  let authMessage = '';
  let authDone = false;
  for (;;) {
    const m = await conn.next();
    if (m.type === 'E') throw new Error(pgErrorOf(m.payload));
    // 认证完成后服务端还会发 ParameterStatus/BackendKeyData，最后是 ReadyForQuery。
    // 必须一路读到那个 'Z' 才返回：否则启动阶段的 'Z' 会被查询循环当成「结果结束」，
    // 于是每条 SELECT 都读回 0 行（本地 PG 实测抓到的坑）。
    if (m.type === 'Z') {
      if (authDone) return;
      continue;
    }
    if (m.type !== 'R') continue;
    const code = m.payload.readInt32BE(0);
    if (code === 0) { authDone = true; continue; } // AuthenticationOk
    if (code === 10) {
      // SASL：挑 SCRAM-SHA-256（PG 10+ 默认）
      const mechs = m.payload.subarray(4).toString('utf8').split('\0').filter(Boolean);
      if (!mechs.includes('SCRAM-SHA-256')) throw new Error('服务端只支持 ' + mechs.join('/') + '，本客户端只实现 SCRAM-SHA-256');
      const init = Buffer.concat([cstr('SCRAM-SHA-256'), i32(Buffer.byteLength('n,,' + clientFirstBare)), Buffer.from('n,,' + clientFirstBare, 'utf8')]);
      conn.write(pgFrame('p', init));
      continue;
    }
    if (code === 11) {
      // SASLContinue：r=<server nonce>, s=<salt b64>, i=<iterations>
      const f = parseScramFields(m.payload.subarray(4).toString('utf8'));
      const serverNonce = f.r || '';
      if (!serverNonce.startsWith(nonce)) throw new Error('SCRAM nonce 不匹配');
      const salt = Buffer.from(f.s || '', 'base64');
      const iters = Number(f.i || 4096);
      const salted = crypto.pbkdf2Sync(Buffer.from(cfg.password, 'utf8'), salt, iters, 32, 'sha256');
      const clientKey = crypto.createHmac('sha256', salted).update('Client Key').digest();
      const storedKey = crypto.createHash('sha256').update(clientKey).digest();
      const clientFinalNoProof = 'c=biws,r=' + serverNonce;
      authMessage = clientFirstBare + ',' + m.payload.subarray(4).toString('utf8') + ',' + clientFinalNoProof;
      const clientSig = crypto.createHmac('sha256', storedKey).update(authMessage).digest();
      const proof = Buffer.alloc(32);
      for (let i = 0; i < 32; i++) proof[i] = clientKey[i] ^ clientSig[i];
      conn.write(pgFrame('p', Buffer.from(clientFinalNoProof + ',p=' + proof.toString('base64'), 'utf8')));
      conn.scram = { salted, authMessage };
      continue;
    }
    if (code === 12) {
      // SASLFinal：校验服务端签名（双向认证）
      const f = parseScramFields(m.payload.subarray(4).toString('utf8'));
      if (conn.scram) {
        const serverKey = crypto.createHmac('sha256', conn.scram.salted).update('Server Key').digest();
        const expect = crypto.createHmac('sha256', serverKey).update(conn.scram.authMessage).digest('base64');
        if (f.v && f.v !== expect) throw new Error('SCRAM 服务端签名不符');
      }
      continue;
    }
    if (code === 5) {
      // AuthenticationMD5Password（Render 的 Postgres 实测用这个，不是 SCRAM）：
      // 应答 = "md5" + md5( md5(password+user) + salt4 )
      const salt = m.payload.subarray(4, 8);
      const inner = crypto.createHash('md5').update(cfg.password + cfg.user).digest('hex');
      const outer = 'md5' + crypto.createHash('md5').update(Buffer.concat([Buffer.from(inner, 'ascii'), salt])).digest('hex');
      conn.write(pgFrame('p', cstr(outer)));
      continue;
    }
    if (code === 3 || code === 7) throw new Error('服务端要求明文/GSS 认证（code=' + code + '），本客户端只做 MD5 与 SCRAM-SHA-256');
  }
}

function parseRowDescription(payload) {
  const n = payload.readInt16BE(0);
  const fields = [];
  let i = 2;
  for (let k = 0; k < n; k++) {
    const end = payload.indexOf(0, i);
    fields.push(payload.subarray(i, end).toString('utf8'));
    i = end + 1 + 4 + 2 + 4 + 2 + 4 + 2;
  }
  return fields;
}

function parseDataRow(payload, fields) {
  const n = payload.readInt16BE(0);
  const row = {};
  let i = 2;
  for (let k = 0; k < n; k++) {
    const len = payload.readInt32BE(i);
    i += 4;
    const name = fields[k] || String(k);
    if (len < 0) { row[name] = null; continue; }
    row[name] = payload.subarray(i, i + len).toString('utf8');
    i += len;
  }
  return row;
}

async function pgQuery(sql, timeoutMs = 20000) {
  if (!PG_URL) throw new Error('DATABASE_URL 未设置');
  const cfg = parsePgUrl(PG_URL);
  const t0 = Date.now();
  const conn = await pgOpen(cfg);
  try {
    await pgAuth(conn, cfg);
    conn.write(pgFrame('Q', Buffer.concat([Buffer.from(sql, 'utf8'), Buffer.from([0])])));
    let fields = [];
    const rows = [];
    let command = '';
    let err = null;
    for (;;) {
      const m = await conn.next(timeoutMs);
      if (m.type === 'T') fields = parseRowDescription(m.payload);
      else if (m.type === 'D') rows.push(parseDataRow(m.payload, fields));
      else if (m.type === 'C') command = m.payload.toString('utf8').replace(/\0+$/, '');
      else if (m.type === 'E') err = pgErrorOf(m.payload);
      else if (m.type === 'Z') break;
    }
    if (err) throw new Error(err);
    pgState.ok = true;
    pgState.lastError = null;
    pgState.lastQueryMs = Date.now() - t0;
    return { rows, fields, command, ms: Date.now() - t0 };
  } catch (e) {
    pgState.ok = false;
    pgState.lastError = String((e && e.message) || e);
    throw e;
  } finally {
    conn.close();
  }
}

// 启动时记一次「开机」：重启后这个计数会 +1 —— 持久化的可翻牌证据之一
async function pgRecordBoot() {
  if (!PG_URL) return;
  try {
    await pgQuery('CREATE TABLE IF NOT EXISTS free_max_boot (name text PRIMARY KEY, boots integer NOT NULL DEFAULT 0, last_boot timestamptz NOT NULL DEFAULT now())');
    const r = await pgQuery(
      "INSERT INTO free_max_boot (name, boots, last_boot) VALUES ('free-max', 1, now()) " +
      'ON CONFLICT (name) DO UPDATE SET boots = free_max_boot.boots + 1, last_boot = now() ' +
      'RETURNING boots, last_boot'
    );
    pgState.boots = r.rows[0] ? Number(r.rows[0].boots) : null;
    console.log('[pg] 开机计数 boots=' + pgState.boots + ' (' + r.ms + 'ms)');
  } catch (e) {
    console.error('[pg] 开机记录失败: ' + ((e && e.message) || e));
  }
}

// ============================ 零依赖 Key Value（RESP）============================
function respParse(buf) {
  if (!buf.length) return null;
  const t = buf[0];
  const nl = buf.indexOf('\r\n', 1);
  if (nl < 0) return null;
  const line = buf.subarray(1, nl).toString('utf8');
  const rest = buf.subarray(nl + 2);
  if (t === 43) return { value: line, rest };                                   // +simple
  if (t === 45) return { value: new Error(line), rest };                        // -error
  if (t === 58) return { value: Number(line), rest };                           // :int
  if (t === 36) {                                                               // $bulk
    const n = Number(line);
    if (n === -1) return { value: null, rest };
    if (rest.length < n + 2) return null;
    return { value: rest.subarray(0, n).toString('utf8'), rest: rest.subarray(n + 2) };
  }
  if (t === 42) {                                                               // *array
    const n = Number(line);
    if (n === -1) return { value: null, rest };
    const out = [];
    let cur = rest;
    for (let i = 0; i < n; i++) {
      const p = respParse(cur);
      if (!p) return null;
      out.push(p.value);
      cur = p.rest;
    }
    return { value: out, rest: cur };
  }
  return null;
}

function kvCommand(args, timeoutMs = 8000) {
  return new Promise((resolve, reject) => {
    if (!KV_URL) return reject(new Error('REDIS_URL 未设置'));
    const u = new URL(KV_URL);
    const port = Number(u.port || 6379);
    const sock = u.protocol === 'rediss:'
      ? tls.connect({ host: u.hostname, port, rejectUnauthorized: false })
      : net.connect({ host: u.hostname, port });
    const t0 = Date.now();
    let buf = Buffer.alloc(0);
    let needed = 0;
    let done = false;
    const encode = (a) => Buffer.concat([
      Buffer.from('*' + a.length + '\r\n', 'utf8'),
      ...a.map((x) => Buffer.concat([Buffer.from('$' + Buffer.byteLength(String(x)) + '\r\n', 'utf8'), Buffer.from(String(x), 'utf8'), Buffer.from('\r\n')])),
    ]);
    const finish = (err, val) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      try { sock.end(); } catch { /* 已关 */ }
      if (err) reject(err); else resolve({ value: val, ms: Date.now() - t0 });
    };
    const timer = setTimeout(() => finish(new Error('kv 超时')), timeoutMs);
    sock.on('connect', () => {
      // 内网连接串没有密码；有密码时把 AUTH 与命令一起发，按顺序收两个应答
      needed = u.password ? 2 : 1;
      if (u.password) sock.write(encode(['AUTH', decodeURIComponent(u.password)]));
      sock.write(encode(args));
    });
    sock.on('data', (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      for (;;) {
        const p = respParse(buf);
        if (!p) return;
        buf = p.rest;
        needed--;
        if (needed > 0) continue;          // 这是 AUTH 的应答
        if (p.value instanceof Error) return finish(p.value);
        return finish(null, p.value);
      }
    });
    sock.on('error', (e) => finish(e));
    sock.on('close', () => finish(new Error('kv 连接被关闭')));
  });
}

// ============================ WebSocket（零依赖，服务端）============================
// 用途：把本该"从本机出去"的流量改从 Render 节点出去（出口 IP 换成 Render 的共享 NAT），
// 以及反向：让本机借节点的 443 入站口做隧道。只做最必要的帧处理。
const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
function wsAccept(key) { return crypto.createHash('sha1').update(key + WS_GUID).digest('base64'); }

function wsEncode(payload, opcode = 2) {
  const len = payload.length;
  let header;
  if (len < 126) { header = Buffer.from([0x80 | opcode, len]); }
  else if (len < 65536) { header = Buffer.alloc(4); header[0] = 0x80 | opcode; header[1] = 126; header.writeUInt16BE(len, 2); }
  else { header = Buffer.alloc(10); header[0] = 0x80 | opcode; header[1] = 127; header.writeBigUInt64BE(BigInt(len), 2); }
  return Buffer.concat([header, payload]);
}

// 增量帧解析：返回一个喂数据的函数
function makeWsParser(onText, onBinary, onClose, onPing) {
  let buf = Buffer.alloc(0);
  let frags = [];
  let fragOp = 0;
  return (chunk) => {
    buf = Buffer.concat([buf, chunk]);
    for (;;) {
      if (buf.length < 2) return;
      const b0 = buf[0];
      const b1 = buf[1];
      const fin = (b0 & 0x80) !== 0;
      const opcode = b0 & 0x0f;
      const masked = (b1 & 0x80) !== 0;
      let len = b1 & 0x7f;
      let off = 2;
      if (len === 126) { if (buf.length < 4) return; len = buf.readUInt16BE(2); off = 4; }
      else if (len === 127) { if (buf.length < 10) return; len = Number(buf.readBigUInt64BE(2)); off = 10; }
      let mask = null;
      if (masked) { if (buf.length < off + 4) return; mask = buf.subarray(off, off + 4); off += 4; }
      if (buf.length < off + len) return;
      let payload = buf.subarray(off, off + len);
      if (mask) {
        const p = Buffer.allocUnsafe(len);
        for (let i = 0; i < len; i++) p[i] = payload[i] ^ mask[i & 3];
        payload = p;
      }
      buf = buf.subarray(off + len);
      if (opcode === 0x8) { onClose(); return; }
      if (opcode === 0x9) { if (onPing) onPing(payload); continue; }
      if (opcode === 0xa) continue;                       // pong
      if (opcode === 0x0) {                               // 续帧
        frags.push(payload);
        if (fin) { const whole = Buffer.concat(frags); frags = []; if (fragOp === 1) onText(whole); else onBinary(whole); }
        continue;
      }
      if (!fin) { frags = [payload]; fragOp = opcode; continue; }
      if (opcode === 1) onText(payload); else onBinary(payload);
    }
  };
}

// ============================ headless 浏览器（懒加载单例）============================
// 免费档实测（2026-10-17）：512MB / **0.15 核**（cgroup cpu.max=15000/100000）能跑完整 chromium，
// 2 页并发无 OOM（Wikipedia 24s、HN 19.6s，都是 0.15 核下的真实速度）。
// 关键前提：403MB 的浏览器必须在**构建期**装好（package.json 的 postinstall），否则每次冷启动要重下 191MB。
// 内存策略：单浏览器 + 串行（一次一页）+ 空闲 90s 自动关。
// 浏览器安装路径必须**固定且构建/运行一致**：实测踩过 —— 默认 `~/.cache/ms-playwright` 在构建期
// 装到了构建用户的 HOME，运行期看不到（`browser.available` 一直是 false）。这里统一钉到应用目录内。
// 构建命令必须用同一个路径：PLAYWRIGHT_BROWSERS_PATH=$PWD/.pw-browsers npx playwright-core@1.64.1 install chromium
process.env.PLAYWRIGHT_BROWSERS_PATH = process.env.PLAYWRIGHT_BROWSERS_PATH || require('node:path').join(__dirname, '.pw-browsers');
const browserState = { proc: null, busy: false, lastUse: 0, launches: 0, pages: 0, lastError: null };
const BROWSE_TIMEOUT_MS = Number(process.env.BROWSE_TIMEOUT_MS || 60000);
const BROWSER_IDLE_MS = Number(process.env.BROWSER_IDLE_MS || 90000);
// 「可用」判据必须是**浏览器二进制真在**，不能只看 playwright-core 能不能 require ——
// 实测踩过：postinstall 在构建期被跳过，包在、浏览器不在，启动时才炸。
const browserAvailable = () => {
  try { require.resolve('playwright-core'); } catch { return false; }
  const fs = require('node:fs');
  const roots = [process.env.PLAYWRIGHT_BROWSERS_PATH, require('node:path').join(__dirname, '.pw-browsers'), require('node:path').join(require('node:os').homedir(), '.cache', 'ms-playwright')].filter(Boolean);
  for (const r of roots) {
    try {
      if (fs.readdirSync(r).some((d) => /^chromium/.test(d))) return true;
    } catch { /* 目录不存在就继续找 */ }
  }
  return false;
};

async function browserGet() {
  if (browserState.proc) return browserState.proc;
  const { chromium } = require('playwright-core');
  browserState.proc = await chromium.launch({
    channel: 'chromium',
    args: ['--no-sandbox', '--disable-dev-shm-usage', '--disable-gpu', '--disable-extensions'],
  });
  browserState.launches++;
  console.log('[browser] launched (#' + browserState.launches + ')');
  return browserState.proc;
}

async function browse(target, opts = {}) {
  if (!browserAvailable()) throw new Error('playwright-core 未安装（构建期 postinstall 未跑？）');
  if (browserState.busy) throw new Error('浏览器忙（免费档一次一页）');
  browserState.busy = true;
  const t0 = Date.now();
  let ctx = null;
  try {
    const b = await browserGet();
    ctx = await b.newContext({ viewport: { width: 900, height: 650 }, userAgent: opts.userAgent });
    const page = await ctx.newPage();
    const resp = await page.goto(target, { timeout: BROWSE_TIMEOUT_MS, waitUntil: opts.waitUntil || 'domcontentloaded' });
    const title = await page.title();
    const text = String(await page.evaluate(() => (document.body ? document.body.innerText : ''))).replace(/[ \t]+\n/g, '\n').slice(0, 4000);
    const out = { url: page.url(), status: resp ? resp.status() : null, title, text, ms: Date.now() - t0, launches: browserState.launches };
    if (opts.links) out.links = await page.evaluate(() => Array.from(document.querySelectorAll('a[href]')).map((a) => a.href).slice(0, 200));
    if (opts.shot) out.png = (await page.screenshot({ type: 'png' })).toString('base64');
    browserState.pages++;
    return out;
  } catch (e) {
    browserState.lastError = String((e && e.message) || e).slice(0, 300);
    throw e;
  } finally {
    browserState.busy = false;
    browserState.lastUse = Date.now();
    if (ctx) { try { await ctx.close(); } catch { /* 已关 */ } }
  }
}

// ============================ 主进程 ============================
if (isMainThread) main();

function main() {
  // ---------- worker 池 ----------
  const pool = [];
  const idle = [];
  const pending = [];
  const jobs = [];
  let jobSeq = 0;
  let shuttingDown = false;
  let workerCrashes = 0;

  function makeWorker(slot) {
    const w = new Worker(__filename, { workerData: { slot } });
    w.slot = slot;
    w.busy = null;
    w.dead = false;

    w.on('message', (msg) => {
      if (w.busy) {
        const job = w.busy;
        job.status = msg && msg.ok ? 'ok' : 'error';
        job.result = msg && msg.ok ? msg.out : msg && msg.err;
        job.finishedAt = new Date().toISOString();
        w.busy = null;
      }
      if (!w.dead) { idle.push(w); pump(); }
    });

    w.on('error', (err) => {
      w.dead = true;
      const i = idle.indexOf(w);
      if (i >= 0) idle.splice(i, 1);
      if (w.busy) {
        w.busy.status = 'error';
        w.busy.result = String((err && err.stack) || err);
        w.busy.finishedAt = new Date().toISOString();
        w.busy = null;
      }
      pump();
    });

    w.on('exit', (code) => {
      w.dead = true;
      const i = idle.indexOf(w);
      if (i >= 0) idle.splice(i, 1);
      const j = pool.indexOf(w);
      if (j >= 0) pool.splice(j, 1);
      if (!shuttingDown && pool.length < WORKER_POOL) {
        if (code === 0) {
          workerCrashes = 0;
          pool.push(makeWorker(w.slot));
        } else {
          // 崩溃补位要退避：否则「worker 一启动就崩」= 烧满那 0.1 CPU 的重启风暴
          workerCrashes++;
          const delay = Math.min(30000, 250 * Math.pow(2, Math.min(workerCrashes, 7)));
          console.error('[pool] worker 退出 code=' + code + '，第 ' + workerCrashes + ' 次，' + delay + 'ms 后补位');
          setTimeout(() => {
            if (!shuttingDown && pool.length < WORKER_POOL) {
              pool.push(makeWorker(w.slot));
              pump();
            }
          }, delay).unref();
        }
      }
      pump();
    });

    return w;
  }

  function pump() {
    while (pending.length) {
      let w = null;
      while (idle.length) {
        const cand = idle.pop();
        if (!cand.dead) { w = cand; break; }
      }
      if (!w) return;
      const job = pending.shift();
      job.status = 'running';
      job.startedAt = new Date().toISOString();
      w.busy = job;
      w.postMessage(job);
    }
  }

  function enqueue(name, payload) {
    const job = {
      id: ++jobSeq,
      name: String(name || 'job'),
      payload: payload === undefined ? null : payload,
      status: 'queued',
      createdAt: new Date().toISOString(),
    };
    jobs.push(job);
    if (jobs.length > MAX_JOBS_KEPT) jobs.splice(0, jobs.length - MAX_JOBS_KEPT);
    if (WORKER_POOL === 0) {
      // 没开线程池就地同步跑，别让任务悄悄躺在队列里
      try {
        job.status = 'ok';
        job.result = runJob(job);
      } catch (err) {
        job.status = 'error';
        job.result = String((err && err.stack) || err);
      }
      job.finishedAt = new Date().toISOString();
      return job;
    }
    pending.push(job);
    pump();
    return job;
  }

  for (let s = 0; s < WORKER_POOL; s++) pool.push(makeWorker(s));
  for (const w of pool) idle.push(w); // 开局把线程都算成空闲，否则任务只会躺在队列里
  pump();

  // ---------- 进程内 cron ----------
  // 硬校验：不校验的话 `POST /admin/cron?spec=0-999999999 * * * *` 会让下面这个 for 循环
  // 在唯一那 0.1 CPU 上跑十亿圈 —— 健康检查超时、服务被判不健康。这是自伤式 DoS。
  function parseCronField(field, min, max) {
    const out = new Set();
    for (const part of String(field).split(',')) {
      let step = 1;
      let body = part;
      const slash = part.indexOf('/');
      if (slash >= 0) {
        body = part.slice(0, slash);
        step = Number(part.slice(slash + 1));
      }
      let lo = min;
      let hi = max;
      if (body !== '*') {
        const dash = body.indexOf('-');
        if (dash >= 0) {
          lo = Number(body.slice(0, dash));
          hi = Number(body.slice(dash + 1));
        } else {
          lo = Number(body);
          hi = Number(body);
        }
      }
      if (!Number.isInteger(lo) || !Number.isInteger(hi)) throw new Error('cron 字段不是整数: ' + part);
      if (!Number.isInteger(step) || step < 1) throw new Error('cron 步长非法: ' + part);
      if (lo < min || hi > max || lo > hi) throw new Error('cron 字段越界（允许 ' + min + '-' + max + '）: ' + part);
      for (let v = lo; v <= hi; v += step) out.add(v);
    }
    if (!out.size) throw new Error('cron 字段为空: ' + field);
    return out;
  }

  function compileCron(spec) {
    const f = String(spec).trim().split(/\s+/);
    if (f.length !== 5) throw new Error('cron 要 5 段（分 时 日 月 周），收到: ' + spec);
    return {
      spec: f.join(' '),
      minute: parseCronField(f[0], 0, 59),
      hour: parseCronField(f[1], 0, 23),
      dom: parseCronField(f[2], 1, 31),
      month: parseCronField(f[3], 1, 12),
      dow: parseCronField(f[4], 0, 6),
    };
  }

  // 注意：日/周为「与」语义（Vixie cron 是「或」），够用且不会误触发
  function cronMatches(c, d) {
    return (
      c.minute.has(d.getMinutes()) &&
      c.hour.has(d.getHours()) &&
      c.dom.has(d.getDate()) &&
      c.month.has(d.getMonth() + 1) &&
      c.dow.has(d.getDay())
    );
  }

  const tasks = [];
  const MAX_CRON_TASKS = Number(process.env.MAX_CRON_TASKS || 50);
  function addTask(name, spec) {
    const clean = String(name).trim();
    if (!clean) throw new Error('任务名不能为空');
    if (clean.length > 64) throw new Error('任务名太长');
    if (tasks.length >= MAX_CRON_TASKS) throw new Error('定时任务已达上限 ' + MAX_CRON_TASKS);
    if (tasks.some((t) => t.name === clean)) throw new Error('任务名重复: ' + clean);
    const c = compileCron(spec);
    const t = { name: clean, cron: c, lastKey: null, lastRun: null, runs: 0, addedAt: new Date().toISOString() };
    tasks.push(t);
    console.log('[cron] + ' + t.name + ' @ ' + c.spec);
    return t;
  }

  const rawCron = process.env.CRON_JOBS === undefined ? DEFAULT_CRON : process.env.CRON_JOBS;
  for (const entry of String(rawCron).split(';')) {
    const item = entry.trim();
    if (!item) continue;
    const eq = item.indexOf('=');
    if (eq < 0) { console.error('[cron] 跳过（要 name=spec）: ' + item); continue; }
    try {
      addTask(item.slice(0, eq).trim(), item.slice(eq + 1).trim());
    } catch (err) {
      console.error('[cron] 跳过 ' + item + ' → ' + err.message);
    }
  }

  let lastTickAt = null;
  setInterval(() => {
    const now = new Date();
    const key = now.toISOString().slice(0, 16);
    lastTickAt = now.toISOString();
    for (const t of tasks) {
      if (t.lastKey === key) continue;
      if (!cronMatches(t.cron, now)) continue;
      t.lastKey = key;
      t.lastRun = now.toISOString();
      t.runs++;
      const job = enqueue(t.name, { source: 'cron', spec: t.cron.spec });
      console.log('[cron] fired ' + t.name + ' → job#' + job.id);
    }
  }, CRON_TICK_MS).unref();

  // ---------- token 保护的 shell ----------
  let execBusy = false;
  function authed(req) {
    if (!ADMIN_TOKEN) return false;
    // 只认 header：token 走 ?token= 会被 Render 记进 HTTP 请求日志（等于把钥匙写进日志）
    const got = req.headers['x-admin-token'] || '';
    const a = Buffer.from(String(got));
    const b = Buffer.from(ADMIN_TOKEN);
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  }

  function runShell(cmd, cb) {
    if (execBusy) return cb({ code: 429, body: { error: 'exec 忙，稍后再试' } });
    execBusy = true;
    console.log('[exec] ' + new Date().toISOString() + ' ' + String(cmd).slice(0, 200)); // 审计行：出事后能看到跑过什么
    execFile(
      SHELL_BIN,
      [SHELL_FLAG, cmd],
      { timeout: EXEC_TIMEOUT_MS, maxBuffer: EXEC_MAX_BUFFER, env: process.env },
      (err, stdout, stderr) => {
        execBusy = false;
        cb({
          code: 200,
          body: {
            cmd,
            exit: err ? (err.code === undefined ? 1 : err.code) : 0,
            timedOut: !!(err && err.killed),
            stdout: String(stdout || ''),
            stderr: String(stderr || ''),
          },
        });
      }
    );
  }

  // ---------- HTTP ----------
  const startedAt = Date.now();
  let requests = 0;

  function json(res, code, obj) {
    const body = JSON.stringify(obj, null, 2);
    res.writeHead(code, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
    res.end(body);
  }

  const MAX_BODY = Number(process.env.MAX_BODY_BYTES || 65536);

  function readBody(req, cb) {
    let data = '';
    let over = false;
    req.on('data', (c) => {
      if (over) return; // 超限后继续排空但不再累积（不能 pause，否则 'end' 不来、413 发不出去）
      data += c;
      if (data.length > MAX_BODY) { over = true; data = ''; }
    });
    req.on('end', () => cb(over ? null : data)); // null = 超限，交给调用方回 413
  }

  const server = http.createServer((req, res) => {
    requests++;
    const url = new URL(req.url, 'http://localhost');

    // 保活/健康检查：公开端点，只回一个「活着」，不泄漏任何内部结构
    if (url.pathname === '/healthz') {
      return json(res, 200, { ok: true, upSec: Math.round((Date.now() - startedAt) / 1000) });
    }

    if (url.pathname === '/') {
      res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' });
      // 不带 token 的访问者只看到一行；端点清单是给管理员看的
      if (!authed(req)) return res.end('free-max 在跑\n');
      return res.end(
        [
          'free-max 在跑',
          '',
          'GET  /healthz                      健康检查（保活打这个，公开）',
          'GET  /admin/stats                  进程/队列/内存/线程崩溃数',
          'POST /admin/job?name=x             入队一个 worker 任务',
          'GET  /admin/jobs                   最近任务',
          'GET  /admin/cron                   定时任务列表',
          'POST /admin/cron?name=x&spec=...   运行时加定时任务',
          'POST /admin/cron/delete?name=x     删定时任务',
          'GET  /admin/exec?cmd=ls -la        执行 shell 命令（= 没有 SSH 时的替代品）',
          'GET  /admin/deps                   探活 Postgres / Key Value（含协议耗时）',
          'GET  /admin/net                    网络身份自报：出口 IP / 监听端口 / 主机名',
          'POST /admin/persist?key=k&value=v  Postgres 落一行（重启后仍在）',
          'GET  /admin/persist[?key=k]        读回（不带 key = 列最近 50 行 + 开机次数）',
          'POST /admin/kv?key=k&value=v       Key Value 写（免费档 persistenceMode=off，重启即丢）',
          'GET  /admin/kv[?key=k]             Key Value 读（不带 key = DBSIZE）',
          '',
          '鉴权：只认 header `x-admin-token`（不再支持 ?token=，避免密钥进请求日志）',
        ].join('\n')
      );
    }

    if (url.pathname.startsWith('/admin/')) {
      if (!authed(req)) return json(res, 404, { error: 'not found' }); // 没配 token 就当这组路由不存在

      if (url.pathname === '/admin/exec') {
        let cmd = url.searchParams.get('cmd');
        if (!cmd && req.method === 'POST') {
          return readBody(req, (body) => {
            if (body === null) return json(res, 413, { error: 'body 太大（上限 ' + MAX_BODY + ' 字节）' });
            try {
              cmd = JSON.parse(body || '{}').cmd;
            } catch {
              cmd = body;
            }
            if (!cmd) return json(res, 400, { error: '要 cmd' });
            runShell(cmd, (r) => json(res, r.code, r.body));
          });
        }
        if (!cmd) return json(res, 400, { error: '要 cmd' });
        return runShell(cmd, (r) => json(res, r.code, r.body));
      }

      if (url.pathname === '/admin/stats') {
        const m = process.memoryUsage();
        return json(res, 200, {
          ok: true,
          pid: process.pid,
          node: process.version,
          upSec: Math.round((Date.now() - startedAt) / 1000),
          requests,
          rssMB: Math.round(m.rss / 1048576),
          heapUsedMB: Math.round(m.heapUsed / 1048576),
          rssLimitMB: RSS_LIMIT_MB || null,
          workerPool: WORKER_POOL,
          workerCrashes,
          pool: { size: pool.length, idle: idle.length, queued: pending.length },
          jobs: { total: jobSeq, kept: jobs.length, byStatus: countBy(jobs, 'status') },
          cron: tasks.map((t) => ({ name: t.name, spec: t.cron.spec, runs: t.runs, lastRun: t.lastRun })),
          lastTickAt,
          loadavg: require('node:os').loadavg(),
          // 免费档榨干项：有没有真接到持久层（重启后数据仍在的判据看 boots）
          db: { configured: !!PG_URL, ok: pgState.ok, boots: pgState.boots, lastQueryMs: pgState.lastQueryMs, error: pgState.lastError },
          kv: { configured: !!KV_URL },
          browser: { available: browserAvailable(), launches: browserState.launches, pages: browserState.pages, busy: browserState.busy, lastError: browserState.lastError },
        });
      }

      // 异步端点的兜底：把 rejection 变成 500。**必须在任何用到它的分支之前声明** ——
      // 实测教训：声明在使用之后 → 请求处理器抛 `Cannot access 'guard' before initialization`
      // （TDZ ReferenceError），未捕获异常直接**把整个实例搞退出**，而健康检查打 /healthz 查不出来。
      const guard = (p) => p.catch((e) => json(res, 500, { error: String((e && e.message) || e) }));

      // ---- 网络身份自报：出口 IP / 监听端口 / 主机名（免费档没有 Dashboard Shell，这是替代品）----
      // 全部只读、只查本文件写死的语句、不向任何第三方站点发请求。
      if (url.pathname === '/admin/net') {
        return guard((async () => {
          const os = require('node:os');
          const fs = require('node:fs');
          const out = {
            hostname: os.hostname(),
            listenPort: PORT,
            podIPv4: Object.values(os.networkInterfaces()).flat().filter((i) => i && i.family === 'IPv4' && !i.internal).map((i) => i.address),
            uptimeSec: Math.round(process.uptime()),
          };
          // 监听端口：直接读 /proc/net/tcp 与 /proc/net/tcp6（容器里没有 ss/netstat）。
          // Node 绑 ::（IPv6）时监听项只出现在 tcp6 —— 只读 tcp 会得到空列表（实测踩过）。
          try {
            const readListen = (file, family) => {
              const txt = String(fs.readFileSync(file, 'utf8')).trim().split('\n').slice(1);
              return txt
                .map((l) => l.trim().split(/\s+/))
                .filter((f) => f[3] === '0A')
                .map((f) => ({ family, addr: f[1].split(':')[0], port: parseInt(f[1].split(':')[1], 16) }));
            };
            out.listenSockets = [...readListen('/proc/net/tcp', 'v4'), ...readListen('/proc/net/tcp6', 'v6')];
            out.listenSocketsError = null;
          } catch (e) {
            out.listenSockets = null;
            out.listenSocketsError = String((e && e.message) || e);
          }
          // 出口 IP：Postgres 眼中的对端地址 = 本服务的出口 IP（共享网段）；顺带拿服务端地址
          if (PG_URL) {
            try {
              const r = await pgQuery('SELECT inet_client_addr()::text AS outbound_ip, inet_server_addr()::text AS pg_ip, inet_server_port() AS pg_port, current_user AS db_user');
              out.pgClientAddr = r.rows[0] && r.rows[0].outbound_ip;
              out.pgServerAddr = r.rows[0] && r.rows[0].pg_ip;
              out.pgServerPort = r.rows[0] && r.rows[0].pg_port;
              out.pgUser = r.rows[0] && r.rows[0].db_user;
            } catch (e) { out.pgError = String((e && e.message) || e); }
          }
          json(res, 200, out);
        })());
      }

      // ---- 出网端口矩阵 + 出口 IP：回答「这个节点能当什么用」----
      // open=TCP 握手成功（这一跳被放行）；refused=网络可达但对面没监听；timeout=大概率被平台过滤。
      if (url.pathname === '/admin/probe') {
        return guard((async () => {
          const host = url.searchParams.get('host') || 'portquiz.net';
          const ports = (url.searchParams.get('ports') || '22,25,53,80,110,143,443,465,587,993,1080,3128,3306,5432,6379,8080,8443,9000,10000,27017')
            .split(',').map((x) => Number(x.trim())).filter((n) => n > 0 && n < 65536);
          const timeout = Math.min(15000, Number(url.searchParams.get('timeout') || 5000));
          const matrix = await Promise.all(ports.map((port) => new Promise((resolve) => {
            const started = Date.now();
            const sock = net.connect({ host, port });
            let done = false;
            const finish = (status, extra) => {
              if (done) return;
              done = true;
              try { sock.destroy(); } catch { /* 已关 */ }
              resolve({ port, status, ms: Date.now() - started, ...extra });
            };
            sock.setTimeout(timeout, () => finish('timeout'));
            sock.on('connect', () => finish('open'));
            sock.on('error', (e) => finish(e.code === 'ECONNREFUSED' ? 'refused' : 'error', { code: e.code }));
          })));
          let egress = null;
          // echo 支持逗号分隔多个：用来判「出口 IP 是否随目的地变化」与「有没有 IPv6 出口」
          const echoList = (url.searchParams.get('echo') || '').split(',').map((x) => x.trim()).filter(Boolean);
          if (echoList.length) {
            const list = [];
            for (const e of echoList) {
              try {
                const r = await fetch(e, { signal: AbortSignal.timeout(10000) });
                list.push({ url: e, body: (await r.text()).trim().slice(0, 160) });
              } catch (err) { list.push({ url: e, error: String((err && err.message) || err) }); }
            }
            egress = list[0];
            json(res, 200, { host, timeoutMs: timeout, egress, egressList: list, matrix });
            return;
          }
          json(res, 200, { host, timeoutMs: timeout, egress, matrix });
        })());
      }

      // ---- 远程 headless 浏览器：/admin/browse?url=&shot=1&links=1 ----
      // 把「免费节点能跑真浏览器」变成产线可调的端点：JS 重的页面也能渲染后取文本/链接/截图。
      if (url.pathname === '/admin/browse') {
        const target = url.searchParams.get('url');
        if (!target) return json(res, 400, { error: '要 url' });
        if (!/^https?:\/\//i.test(target)) return json(res, 400, { error: '只接受 http(s)://' });
        return guard((async () => {
          const r = await browse(target, {
            shot: url.searchParams.get('shot') === '1',
            links: url.searchParams.get('links') === '1',
            waitUntil: url.searchParams.get('wait') || undefined,
            userAgent: url.searchParams.get('ua') || undefined,
          });
          if (r.png && r.png.length > 1500000) r.png = r.png.slice(0, 1500000);  // 别把响应撑爆
          json(res, 200, r);
        })());
      }

      // ---- 持久化端点：Postgres（重启后仍在）/ Key Value（缓存、队列）----
      // 只走本文件里写死的语句，不接受任意 SQL；值做单引号转义与长度上限。

      if (url.pathname === '/admin/deps') {
        return guard((async () => {
          const out = {
            db: { configured: !!PG_URL, ok: false, boots: pgState.boots, ms: null, error: pgState.lastError },
            kv: { configured: !!KV_URL, ok: false, ms: null, error: null },
          };
          if (PG_URL) {
            try {
              const r = await pgQuery('SELECT now() AS now, current_database() AS db, version() AS version');
              out.db.ok = true; out.db.ms = r.ms;
              out.db.now = r.rows[0] && r.rows[0].now;
              out.db.name = r.rows[0] && r.rows[0].db;
              out.db.version = String((r.rows[0] && r.rows[0].version) || '').split(' ').slice(0, 2).join(' ');
            } catch (e) { out.db.error = String((e && e.message) || e); }
          }
          if (KV_URL) {
            try {
              const r = await kvCommand(['PING']);
              out.kv.ok = r.value === 'PONG';
              out.kv.ms = r.ms;
              out.kv.ping = r.value;
            } catch (e) { out.kv.error = String((e && e.message) || e); }
          }
          json(res, 200, out);
        })());
      }

      if (url.pathname === '/admin/persist') {
        const key = (url.searchParams.get('key') || '').trim();
        const value = url.searchParams.get('value');
        if (req.method === 'POST') {
          if (!key || value === null) return json(res, 400, { error: '要 key 与 value（query 参数）' });
          if (key.length > 128 || !/^[A-Za-z0-9_.:-]+$/.test(key)) return json(res, 400, { error: 'key 只允许 128 字符内的 [A-Za-z0-9_.:-]' });
          if (value.length > 4000) return json(res, 413, { error: 'value 上限 4000 字符' });
          return guard((async () => {
            await pgQuery('CREATE TABLE IF NOT EXISTS free_max_persist (key text PRIMARY KEY, value text NOT NULL, at timestamptz NOT NULL DEFAULT now(), writes integer NOT NULL DEFAULT 0)');
            const r = await pgQuery(
              'INSERT INTO free_max_persist (key, value, at, writes) VALUES (' + sqlLit(key) + ', ' + sqlLit(value) + ', now(), 1) ' +
              'ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, at = now(), writes = free_max_persist.writes + 1 ' +
              'RETURNING key, value, at, writes'
            );
            json(res, 200, { row: r.rows[0], ms: r.ms });
          })());
        }
        return guard((async () => {
          if (key) {
            const r = await pgQuery('SELECT key, value, at, writes FROM free_max_persist WHERE key = ' + sqlLit(key));
            return json(res, r.rows.length ? 200 : 404, { row: r.rows[0] || null, ms: r.ms });
          }
          const r = await pgQuery('SELECT key, value, at, writes FROM free_max_persist ORDER BY at DESC LIMIT 50');
          const c = await pgQuery('SELECT count(*)::int AS n FROM free_max_persist');
          json(res, 200, { rows: r.rows, count: c.rows[0] ? Number(c.rows[0].n) : null, boots: pgState.boots, ms: r.ms });
        })());
      }

      if (url.pathname === '/admin/kv') {
        const key = (url.searchParams.get('key') || '').trim();
        const value = url.searchParams.get('value');
        if (req.method === 'POST') {
          if (!key || value === null) return json(res, 400, { error: '要 key 与 value' });
          if (key.length > 128) return json(res, 400, { error: 'key 上限 128 字符' });
          if (value.length > 4000) return json(res, 413, { error: 'value 上限 4000 字符' });
          return guard((async () => {
            const r = await kvCommand(['SET', key, value]);
            json(res, 200, { set: r.value, ms: r.ms, note: '免费 Key Value 默认 persistenceMode=off，重启即丢；要跨重启只能放 Postgres' });
          })());
        }
        if (!key) {
          return guard((async () => {
            const r = await kvCommand(['DBSIZE']);
            json(res, 200, { dbsize: r.value, ms: r.ms });
          })());
        }
        return guard((async () => {
          const r = await kvCommand(['GET', key]);
          json(res, r.value === null ? 404 : 200, { key, value: r.value, ms: r.ms });
        })());
      }

      if (url.pathname === '/admin/job' && req.method === 'POST') {
        const name = url.searchParams.get('name') || 'manual';
        const job = enqueue(name, { source: 'http' });
        return json(res, 202, { job });
      }

      if (url.pathname === '/admin/jobs') {
        const limit = Math.min(200, Number(url.searchParams.get('limit') || 20));
        return json(res, 200, { jobs: jobs.slice(-limit) });
      }

      if (url.pathname === '/admin/cron' && req.method === 'GET') {
        return json(res, 200, { tasks: tasks.map((t) => ({ name: t.name, spec: t.cron.spec, runs: t.runs, lastRun: t.lastRun })) });
      }

      if (url.pathname === '/admin/cron' && req.method === 'POST') {
        const name = url.searchParams.get('name');
        const spec = url.searchParams.get('spec');
        if (!name || !spec) return json(res, 400, { error: '要 name 和 spec' });
        try {
          const t = addTask(name, spec);
          return json(res, 201, { task: { name: t.name, spec: t.cron.spec } });
        } catch (err) {
          return json(res, 400, { error: err.message });
        }
      }

      if (url.pathname === '/admin/cron/delete' && req.method === 'POST') {
        const name = url.searchParams.get('name');
        const i = tasks.findIndex((t) => t.name === name);
        if (i < 0) return json(res, 404, { error: '没有这个任务' });
        tasks.splice(i, 1);
        return json(res, 200, { deleted: name });
      }

      return json(res, 404, { error: 'not found' });
    }

    json(res, 404, { error: 'not found' });
  });

  // 内存看门狗：免费档 512MB，超了就自己退出让 Render 重启，比被 OOM 杀掉干净
  setInterval(() => {
    const rssMB = Math.round(process.memoryUsage().rss / 1048576);
    if (RSS_LIMIT_MB > 0 && rssMB > RSS_LIMIT_MB) {
      console.error('[watchdog] rss ' + rssMB + 'MB > ' + RSS_LIMIT_MB + 'MB，主动退出交给 Render 重启');
      process.exit(1);
    }
  }, 30000).unref();

  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
  function shutdown() {
    if (shuttingDown) return;
    shuttingDown = true;
    console.log('[shutdown] 停止接收新请求');
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 5000).unref();
  }

  // 隧道节点必须扛得住单个坏 socket：实测客户端粗暴断开会让 upgrade socket 抛未捕获 ECONNRESET，
  // **整个实例直接退出**（等于一条烂连接打掉全池）。这里兜底记录并继续服务，不退出。
  process.on('uncaughtException', (e) => {
    console.error('[fatal-keepalive] ' + String((e && e.stack) || e).split('\n').slice(0, 3).join(' | '));
  });
  process.on('unhandledRejection', (e) => {
    console.error('[fatal-keepalive] unhandledRejection ' + String((e && e.message) || e));
  });

  // ---- WebSocket 隧道：/proxy?… ----
  // 两种模式：
  //   ① 单流（首帧 TEXT = {"host","port"}）—— 兼容早期客户端；
  //   ② 多路复用（首帧 TEXT = {"mux":1}）：之后每帧二进制，格式
  //        [type(1B)][sid(4B)][payload]   type: 1=open(payload=JSON{host,port}) 2=data 3=close 4=ok/err(JSON)
  //      **一条 WS 扛多路 TCP/UDP 流** —— 省掉每请求一次 TLS+WS 握手（实测这是主要延迟来源）。
  server.on('upgrade', (req, socket, head) => {
    const url = new URL(req.url, 'http://localhost');
    if (url.pathname !== '/proxy') return socket.destroy();
    if (!authed(req)) return socket.end('HTTP/1.1 404 Not Found\r\n\r\n');
    const key = req.headers['sec-websocket-key'];
    if (!key) return socket.destroy();
    socket.write(
      'HTTP/1.1 101 Switching Protocols\r\n' +
      'Upgrade: websocket\r\nConnection: Upgrade\r\n' +
      'Sec-WebSocket-Accept: ' + wsAccept(key) + '\r\n\r\n'
    );
    socket.on('error', () => { /* 立刻兜住：见上面 fatal-keepalive 的注释 */ });
    let upstream = null;
    let target = null;
    let queue = [];
    let mux = false;
    const streams = new Map();   // sid -> {sock, proto, host, port}
    const toClient = (payload, opcode = 2) => { try { socket.write(wsEncode(payload, opcode)); } catch { /* 已关 */ } };
    const muxFrame = (type, sid, payload) => {
      const b = Buffer.alloc(5 + (payload ? payload.length : 0));
      b[0] = type;
      b.writeUInt32BE(sid >>> 0, 1);
      if (payload) payload.copy(b, 5);
      toClient(b);
    };
    const openMuxStream = (sid, spec) => {
      const proto = spec && spec.proto === 'udp' ? 'udp' : 'tcp';
      const host = String(spec && spec.host);
      const port = Number(spec && spec.port);
      if (proto === 'udp') {
        const dg = require('node:dgram').createSocket('udp4');
        dg.on('message', (msg) => muxFrame(2, sid, msg));
        dg.on('error', (e) => { muxFrame(4, sid, Buffer.from(JSON.stringify({ ok: false, error: String(e.code || e.message) }))); streams.delete(sid); try { dg.close(); } catch { /* 已关 */ } });
        dg.bind(0, () => { streams.set(sid, { sock: dg, proto, host, port }); muxFrame(4, sid, Buffer.from(JSON.stringify({ ok: true, proto: 'udp' }))); });
        return;
      }
      const s = net.connect({ host, port });
      s.on('connect', () => { streams.set(sid, { sock: s, proto, host, port }); muxFrame(4, sid, Buffer.from(JSON.stringify({ ok: true }))); });
      s.on('data', (d) => muxFrame(2, sid, d));
      s.on('end', () => { muxFrame(3, sid); streams.delete(sid); });
      s.on('error', (e) => { muxFrame(4, sid, Buffer.from(JSON.stringify({ ok: false, error: String(e.code || e.message) }))); muxFrame(3, sid); streams.delete(sid); });
    };
    const handleMux = (buf) => {
      let off = 0;
      while (off + 5 <= buf.length) {
        const type = buf[off];
        const sid = buf.readUInt32BE(off + 1);
        const payload = buf.subarray(off + 5);
        off = buf.length;                       // 目前每个 WS 帧就是一个 mux 帧
        if (type === 1) { try { openMuxStream(sid, JSON.parse(payload.toString('utf8'))); } catch (e) { muxFrame(4, sid, Buffer.from(JSON.stringify({ ok: false, error: String(e.message) }))); } continue; }
        const st = streams.get(sid);
        if (type === 2) {
          if (!st) continue;
          if (st.proto === 'udp') st.sock.send(payload, st.port, st.host, () => {});
          else if (st.sock.writable) st.sock.write(payload);
          continue;
        }
        if (type === 3) {
          if (!st) continue;
          try { if (st.proto === 'udp') st.sock.close(); else st.sock.end(); } catch { /* 已关 */ }
          streams.delete(sid);
          continue;
        }
      }
    };
    const parse = makeWsParser(
      (t) => {
        if (mux) return;
        if (target) return;
        try {
          const j = JSON.parse(t.toString('utf8'));
          if (j && j.mux) { mux = true; console.log('[proxy] mux 已开'); return; }
          if (!j || !j.host || !j.port) throw new Error('要 host/port');
          target = { host: String(j.host), port: Number(j.port), proto: j.proto === 'udp' ? 'udp' : 'tcp' };
          if (target.proto === 'udp') {
            // UDP 中继：**一帧 = 一个数据报**（保留边界），双向直通
            const dg = require('node:dgram').createSocket('udp4');
            dg.on('message', (msg) => toClient(msg));
            dg.on('error', (e) => {
              toClient(Buffer.from(JSON.stringify({ ok: false, error: String(e.code || e.message) })), 1);
              toClient(Buffer.alloc(0), 0x8);
              try { socket.end(); } catch { /* 已关 */ }
            });
            dg.bind(0, () => {
              console.log('[proxy] → udp://' + target.host + ':' + target.port);
              toClient(Buffer.from(JSON.stringify({ ok: true, proto: 'udp', to: target.host + ':' + target.port })), 1);
              for (const q of queue) dg.send(q, target.port, target.host, () => {});
              queue = [];
            });
            upstream = dg;
            return;
          }
          upstream = net.connect({ host: target.host, port: target.port });
          upstream.on('connect', () => {
            console.log('[proxy] → ' + target.host + ':' + target.port);
            toClient(Buffer.from(JSON.stringify({ ok: true, to: target.host + ':' + target.port })), 1);
            for (const q of queue) upstream.write(q);
            queue = [];
          });
          upstream.on('data', (d) => toClient(d));
          upstream.on('end', () => { toClient(Buffer.alloc(0), 0x8); try { socket.end(); } catch { /* 已关 */ } });
          upstream.on('error', (e) => {
            toClient(Buffer.from(JSON.stringify({ ok: false, error: String(e.code || e.message) })), 1);
            toClient(Buffer.alloc(0), 0x8);
            try { socket.end(); } catch { /* 已关 */ }
          });
        } catch (e) {
          toClient(Buffer.from(JSON.stringify({ ok: false, error: String((e && e.message) || e) })), 1);
          try { socket.end(); } catch { /* 已关 */ }
        }
      },
      (b) => {
        if (mux) return handleMux(b);
        if (!upstream) { queue.push(b); return; }
        if (target && target.proto === 'udp') upstream.send(b, target.port, target.host, () => {});
        else if (upstream.writable) upstream.write(b);
        else queue.push(b);
      },
      () => { try { socket.end(); } catch { /* 已关 */ } if (upstream) upstream.destroy(); },
      (p) => { try { socket.write(wsEncode(p, 0xa)); } catch { /* 已关 */ } }
    );
    socket.on('data', (c) => parse(c));
    if (head && head.length) parse(head);
    // UDP 用 dgram.close()，TCP 用 destroy() —— 分开收尾；mux 模式下把名下所有流一起收
    const closeUpstream = () => {
      for (const st of streams.values()) {
        try { if (st.proto === 'udp') st.sock.close(); else st.sock.destroy(); } catch { /* 已关 */ }
      }
      streams.clear();
      if (!upstream) return;
      try { if (target && target.proto === 'udp') upstream.close(); else upstream.destroy(); } catch { /* 已关 */ }
    };
    socket.on('error', closeUpstream);
    socket.on('close', closeUpstream);
  });

  server.listen(PORT, () => {
    console.log(
      '[free-max] listen :' + PORT +
      ' pool=' + WORKER_POOL +
      ' admin=' + (ADMIN_TOKEN ? 'on' : 'off') +
      ' cronTasks=' + tasks.length +
      ' node=' + process.version
    );
    // 开机计数：重启后 free_max_boot.boots 会 +1 —— 「数据真的在库里」的可翻牌证据
    pgRecordBoot();
  });
}

function countBy(arr, key) {
  const out = {};
  for (const it of arr) out[it[key]] = (out[it[key]] || 0) + 1;
  return out;
}
