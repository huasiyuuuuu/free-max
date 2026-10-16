'use strict';
/*
 * free-max —— 把 Render 免费档（0.1 CPU / 512MB / 无 SSH / 无 worker / 无 cron）榨成一个全能节点：
 *
 *   1) Web    : 对外 HTTP 服务（免费档唯一的公网入口，固定 443 → PORT）
 *   2) Worker : 进程内 worker_threads 池，顶掉「背景 worker 没有免费档、最低 $7/月」
 *   3) Cron   : 进程内 5 段 cron 解析器，顶掉「cron job 按分钟计费」
 *   4) Shell  : token 保护的 /admin/exec，顶掉「Shell/SSH 只有付费实例才有」
 *
 * 零 npm 依赖 → 构建几乎不烧 pipeline minutes，冷启动更快，512MB 里更省。
 *
 * 关掉任一项（都在环境变量里，改完 Render 自动重新部署）：
 *   ADMIN_TOKEN 不设      → /admin/* 全部返回 404（Shell + 任务管理一起关）
 *   WORKER_POOL=0         → 不起 worker 线程
 *   CRON_JOBS 留空        → 不跑任何定时任务
 *   RSS_LIMIT_MB 不设/0   → 关掉内存看门狗
 */

const http = require('node:http');
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
        });
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
  });
}

function countBy(arr, key) {
  const out = {};
  for (const it of arr) out[it[key]] = (out[it[key]] || 0) + 1;
  return out;
}
