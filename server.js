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
      ? tls.connect({ host: cfg.host, port: cfg.port, rejectUnauthorized: false })
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
        });
      }

      // ---- 持久化端点：Postgres（重启后仍在）/ Key Value（缓存、队列）----
      // 只走本文件里写死的语句，不接受任意 SQL；值做单引号转义与长度上限。
      const guard = (p) => p.catch((e) => json(res, 500, { error: String((e && e.message) || e) }));

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
