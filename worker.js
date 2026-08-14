const DEFAULT_MAX_HTML_BYTES = 5 * 1024 * 1024;
const RATE_WINDOW_SECONDS = 60;
const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const PBKDF2_ITERATIONS = 210000;

function corsHeaders(request, env) {
  const origin = request.headers.get("Origin");
  const allowed = String(env.ALLOWED_ORIGINS || "").split(",").map((value) => value.trim()).filter(Boolean);
  const headers = {
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin"
  };
  if (origin && (allowed.includes("*") || allowed.includes(origin))) headers["Access-Control-Allow-Origin"] = origin;
  return headers;
}

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json;charset=UTF-8", "Cache-Control": "no-store", ...headers }
  });
}

function getExpireAt(plan, duration, from = new Date()) {
  if (plan === "count" || plan === "forever") return null;
  const result = new Date(from);
  if (plan === "hour") result.setHours(result.getHours() + duration);
  if (plan === "day") result.setDate(result.getDate() + duration);
  if (plan === "week") result.setDate(result.getDate() + duration * 7);
  if (plan === "month") result.setMonth(result.getMonth() + duration);
  return result.toISOString();
}

function randomCode(prefix = "HTML", groupSize = 4, groups = 4) {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const bytes = new Uint8Array(groupSize * groups);
  crypto.getRandomValues(bytes);
  const parts = [];
  let offset = 0;
  for (let i = 0; i < groups; i++) {
    let part = "";
    for (let j = 0; j < groupSize; j++) part += chars[bytes[offset++] % chars.length];
    parts.push(part);
  }
  return `${prefix}-${parts.join("-")}`;
}

function randomHex(length = 32) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function pageKey(id) { return `pages/${id}/index.html`; }

function pageUrl(request, env, id) {
  const origin = String(env.PUBLIC_PAGE_ORIGIN || new URL(request.url).origin).replace(/\/$/, "");
  return `${origin}/p/${id}`;
}

function clientIp(request) {
  return request.headers.get("CF-Connecting-IP") || request.headers.get("X-Forwarded-For") || "unknown";
}

function maxHtmlBytes(env) {
  const configured = Number(env.MAX_HTML_BYTES);
  return Number.isFinite(configured) && configured > 0 ? configured : DEFAULT_MAX_HTML_BYTES;
}

function byteLength(text) { return new TextEncoder().encode(text).byteLength; }

async function digest(value) {
  const data = new TextEncoder().encode(value);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hash), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function passwordHash(password, saltHex) {
  const salt = Uint8Array.from(saltHex.match(/.{2}/g), (value) => Number.parseInt(value, 16));
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: PBKDF2_ITERATIONS }, key, 256);
  return Array.from(new Uint8Array(bits), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function safeEqual(left, right) {
  if (typeof left !== "string" || typeof right !== "string") return false;
  const [a, b] = await Promise.all([digest(left), digest(right)]);
  return a === b;
}

async function checkAdmin(request, env) {
  const auth = request.headers.get("Authorization") || "";
  if (!auth.startsWith("Bearer ") || !env.ADMIN_PASSWORD) return false;
  return safeEqual(auth.slice(7), String(env.ADMIN_PASSWORD));
}

function bearerToken(request) {
  const auth = request.headers.get("Authorization") || "";
  return auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";
}

function licenseStub(env, name) {
  if (!env.LICENSE_GUARD) throw new Error("缺少 LICENSE_GUARD Durable Object 绑定");
  return env.LICENSE_GUARD.get(env.LICENSE_GUARD.idFromName(name));
}

function accountStub(env) {
  if (!env.ACCOUNT_REGISTRY) throw new Error("缺少 ACCOUNT_REGISTRY Durable Object 绑定");
  return env.ACCOUNT_REGISTRY.get(env.ACCOUNT_REGISTRY.idFromName("global"));
}

async function objectRequest(stub, payload) {
  const response = await stub.fetch("https://durable-object/internal", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
  return { response, data: await response.json() };
}

async function licenseRequest(env, code, payload) {
  return objectRequest(licenseStub(env, `license:${code}`), payload);
}

async function accountRequest(env, payload) {
  return objectRequest(accountStub(env), payload);
}

async function enforceRateLimit(request, env, scope, limit) {
  const salt = env.SECURITY_HASH_SALT || env.ADMIN_PASSWORD || "html-cloud";
  const ipHash = await digest(`${clientIp(request)}:${salt}`);
  const { response, data } = await objectRequest(licenseStub(env, `rate:${scope}:${ipHash}`), {
    action: "rate_limit",
    limit,
    window_seconds: RATE_WINDOW_SECONDS
  });
  return response.ok ? null : data;
}

function publicPageHeaders(object) {
  const headers = new Headers();
  object.writeHttpMetadata(headers);
  headers.set("Content-Type", "text/html;charset=UTF-8");
  headers.set("Content-Security-Policy", "sandbox allow-scripts allow-forms allow-modals allow-popups allow-popups-to-escape-sandbox allow-downloads");
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("Referrer-Policy", "no-referrer");
  headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()");
  headers.set("Cache-Control", "public, max-age=300");
  if (object.httpEtag) headers.set("ETag", object.httpEtag);
  return headers;
}

function licenseError(info) {
  if (!info) return "激活码不存在";
  if (info.status === "revoked") return "激活码已作废";
  if (info.expire_at && new Date(info.expire_at).getTime() <= Date.now()) return "激活码已过期";
  if (info.plan === "count" && Number(info.remaining) <= 0) return "次数已用完";
  return "";
}

function publicLicense(info) {
  return {
    code: info.code,
    plan: info.plan,
    remaining: info.remaining,
    used: Number(info.used || 0),
    expire_at: info.expire_at || null,
    activated_at: info.activated_at || null,
    status: info.status,
    batch: info.batch || ""
  };
}

function titleFromHtml(html) {
  const match = html.match(/<title[^>]*>([^<]*)<\/title>/i);
  return (match?.[1] || "未命名页面").trim().slice(0, 120) || "未命名页面";
}

export class LicenseGuard {
  constructor(state, env) { this.state = state; this.env = env; }

  async loadLicense(code) {
    const stored = await this.state.storage.get("license");
    if (stored) return stored;
    const raw = await this.env.LICENSE_KV.get(code);
    if (!raw) return null;
    try {
      const info = JSON.parse(raw);
      await this.state.storage.put("license", info);
      return info;
    } catch { return null; }
  }

  async saveLicense(info) {
    await this.state.storage.put("license", info);
    try { await this.env.LICENSE_KV.put(info.code, JSON.stringify(info)); }
    catch (error) { console.error("LICENSE_KV mirror write failed", error); }
  }

  async handleRateLimit(payload) {
    const now = Date.now();
    const windowMs = Math.max(1, Number(payload.window_seconds) || 60) * 1000;
    const limit = Math.max(1, Number(payload.limit) || 20);
    let bucket = await this.state.storage.get("rate");
    if (!bucket || now - bucket.started_at >= windowMs) bucket = { started_at: now, count: 0 };
    bucket.count++;
    await this.state.storage.put("rate", bucket);
    if (bucket.count > limit) return json({ success: false, error: "请求过于频繁，请稍后再试" }, 429);
    return json({ success: true });
  }

  async handleInitialize(payload) {
    if (!payload.info?.code) return json({ success: false, error: "激活码数据错误" }, 400);
    if (await this.loadLicense(payload.info.code)) return json({ success: false, error: "激活码冲突，请重试" }, 409);
    await this.saveLicense(payload.info);
    return json({ success: true });
  }

  async handleInspect(payload) {
    const info = await this.loadLicense(payload.code);
    if (!info) return json({ success: false, error: "激活码不存在" }, 404);
    return json({ success: true, data: info });
  }

  async handleBindAccount(payload) {
    const info = await this.loadLicense(payload.code);
    const invalid = licenseError(info);
    if (invalid) return json({ success: false, error: invalid }, 403);
    if (info.account_id) return json({ success: false, error: "此激活码已绑定账号，不能再次注册" }, 409);
    const now = new Date();
    info.account_id = payload.account_id;
    info.account_username = payload.username;
    info.account_bound_at = now.toISOString();
    info.activated_at ||= now.toISOString();
    if (!info.expire_at && info.plan !== "count" && info.plan !== "forever") {
      info.expire_at = getExpireAt(info.plan, Number(info.duration) || 1, now);
    }
    delete info.bound_device_hash;
    delete info.bound_ip_hash;
    delete info.bound_at;
    await this.saveLicense(info);
    return json({ success: true, license: publicLicense(info) });
  }

  async handleRollbackBind(payload) {
    const info = await this.loadLicense(payload.code);
    if (!info || info.account_id !== payload.account_id) return json({ success: false }, 409);
    delete info.account_id;
    delete info.account_username;
    delete info.account_bound_at;
    if (!info.used) {
      info.activated_at = null;
      info.expire_at = null;
    }
    await this.saveLicense(info);
    return json({ success: true });
  }

  async handleAdminAction(payload) {
    const info = await this.loadLicense(payload.code);
    if (!info) return json({ success: false, error: "激活码不存在" }, 404);
    if (payload.operation === "revoke") info.status = "revoked";
    else if (payload.operation === "activate") info.status = "active";
    else return json({ success: false, error: "不支持的管理操作" }, 400);
    info.updated_at = new Date().toISOString();
    await this.saveLicense(info);
    return json({ success: true, data: info });
  }

  async handlePublish(payload) {
    const info = await this.loadLicense(payload.code);
    const invalid = licenseError(info);
    if (invalid) return json({ success: false, error: invalid }, 403);
    if (!info.account_id || info.account_id !== payload.account_id) {
      return json({ success: false, error: "激活码与当前账号不匹配" }, 403);
    }

    const id = payload.id || crypto.randomUUID();
    const createdAt = new Date().toISOString();
    await this.env.UPLOAD_BUCKET.put(pageKey(id), payload.html, {
      httpMetadata: { contentType: "text/html;charset=UTF-8" }
    });
    const recordResult = await accountRequest(this.env, {
      action: "record_page",
      account_id: info.account_id,
      page: {
        id,
        title: titleFromHtml(payload.html),
        url: payload.url,
        size_bytes: byteLength(payload.html),
        created_at: createdAt
      }
    });
    if (!recordResult.response.ok) return json({ success: false, error: "页面记录保存失败，请重试" }, 503);

    if (info.plan === "count") {
      info.remaining = Number(info.remaining) - 1;
      info.used = Number(info.used || 0) + 1;
    }
    await this.saveLicense(info);
    return json({ success: true, id, remaining: info.remaining });
  }

  async fetch(request) {
    if (request.method !== "POST") return json({ success: false, error: "Method Not Allowed" }, 405);
    let payload;
    try { payload = await request.json(); }
    catch { return json({ success: false, error: "请求数据错误" }, 400); }
    if (payload.action === "rate_limit") return this.handleRateLimit(payload);
    if (payload.action === "initialize") return this.handleInitialize(payload);
    if (payload.action === "inspect") return this.handleInspect(payload);
    if (payload.action === "bind_account") return this.handleBindAccount(payload);
    if (payload.action === "rollback_bind") return this.handleRollbackBind(payload);
    if (payload.action === "admin_action") return this.handleAdminAction(payload);
    if (payload.action === "publish") return this.handlePublish(payload);
    return json({ success: false, error: "未知操作" }, 400);
  }
}

export class AccountRegistry {
  constructor(state, env) { this.state = state; this.env = env; }

  async userById(id) {
    const username = await this.state.storage.get(`user-id:${id}`);
    return username ? this.state.storage.get(`user:${username}`) : null;
  }

  publicUser(user) {
    return { id: user.id, username: user.username, license: user.license, created_at: user.created_at };
  }

  async issueSession(user, device, ipHash) {
    if (user.session_hash) await this.state.storage.delete(`session:${user.session_hash}`);
    const token = randomHex(32);
    const sessionHash = await digest(token);
    const expiresAt = new Date(Date.now() + SESSION_TTL_MS).toISOString();
    user.session_hash = sessionHash;
    user.session_expires_at = expiresAt;
    user.last_device = String(device || "").slice(0, 160);
    user.last_ip_hash = ipHash;
    user.last_login_at = new Date().toISOString();
    await this.state.storage.put(`user:${user.username}`, user);
    await this.state.storage.put(`session:${sessionHash}`, user.id);
    return { token, expires_at: expiresAt };
  }

  async authenticate(token) {
    if (!token) return null;
    const sessionHash = await digest(token);
    const userId = await this.state.storage.get(`session:${sessionHash}`);
    if (!userId) return null;
    const user = await this.userById(userId);
    if (!user || user.status !== "active" || user.session_hash !== sessionHash) return null;
    if (new Date(user.session_expires_at).getTime() <= Date.now()) {
      await this.state.storage.delete(`session:${sessionHash}`);
      return null;
    }
    return user;
  }

  async handleRegister(payload) {
    const username = String(payload.username || "").trim().toLowerCase();
    const password = String(payload.password || "");
    const code = String(payload.license || "").trim().toUpperCase();
    if (!/^[a-z0-9_]{4,32}$/.test(username)) return json({ success: false, error: "账号需为 4-32 位字母、数字或下划线" }, 400);
    if (password.length < 8 || password.length > 72) return json({ success: false, error: "密码长度需为 8-72 位" }, 400);
    if (!code) return json({ success: false, error: "请输入激活码" }, 400);
    if (await this.state.storage.get(`user:${username}`)) return json({ success: false, error: "账号已存在" }, 409);

    const accountId = crypto.randomUUID();
    const binding = await licenseRequest(this.env, code, {
      action: "bind_account", code, account_id: accountId, username
    });
    if (!binding.response.ok) return json(binding.data, binding.response.status);

    const salt = randomHex(16);
    const user = {
      id: accountId,
      username,
      password_salt: salt,
      password_hash: await passwordHash(password, salt),
      license_code: code,
      license: binding.data.license,
      status: "active",
      created_at: new Date().toISOString()
    };
    try {
      await this.state.storage.put(`user:${username}`, user);
      await this.state.storage.put(`user-id:${accountId}`, username);
      await this.state.storage.put(`license:${code}`, accountId);
    } catch (error) {
      await licenseRequest(this.env, code, { action: "rollback_bind", code, account_id: accountId });
      throw error;
    }
    const session = await this.issueSession(user, payload.device, payload.ip_hash);
    return json({ success: true, token: session.token, session_expires_at: session.expires_at, user: this.publicUser(user) });
  }

  async handleLogin(payload) {
    const username = String(payload.username || "").trim().toLowerCase();
    const password = String(payload.password || "");
    const user = await this.state.storage.get(`user:${username}`);
    if (!user || !(await safeEqual(await passwordHash(password, user.password_salt), user.password_hash))) {
      return json({ success: false, error: "账号或密码错误" }, 401);
    }
    if (user.status !== "active") return json({ success: false, error: "账号已停用" }, 403);
    const licenseInfo = await licenseRequest(this.env, user.license_code, { action: "inspect", code: user.license_code });
    if (!licenseInfo.response.ok) return json({ success: false, error: "账号激活信息异常" }, 403);
    user.license = publicLicense(licenseInfo.data.data);
    const session = await this.issueSession(user, payload.device, payload.ip_hash);
    return json({ success: true, token: session.token, session_expires_at: session.expires_at, user: this.publicUser(user) });
  }

  async handleAuthenticate(payload) {
    const user = await this.authenticate(payload.token);
    if (!user) return json({ success: false, error: "登录已失效，请重新登录" }, 401);
    const licenseInfo = await licenseRequest(this.env, user.license_code, { action: "inspect", code: user.license_code });
    if (!licenseInfo.response.ok) return json({ success: false, error: "账号激活信息异常" }, 403);
    user.license = publicLicense(licenseInfo.data.data);
    await this.state.storage.put(`user:${user.username}`, user);
    return json({ success: true, user: this.publicUser(user), license_code: user.license_code });
  }

  async handleLogout(payload) {
    const user = await this.authenticate(payload.token);
    if (!user) return json({ success: true });
    await this.state.storage.delete(`session:${user.session_hash}`);
    delete user.session_hash;
    delete user.session_expires_at;
    await this.state.storage.put(`user:${user.username}`, user);
    return json({ success: true });
  }

  async handleRecordPage(payload) {
    const user = await this.userById(payload.account_id);
    if (!user) return json({ success: false, error: "账号不存在" }, 404);
    const key = `page:${user.id}:${payload.page.created_at}:${payload.page.id}`;
    await this.state.storage.put(key, payload.page);
    return json({ success: true });
  }

  async pagesForUser(userId) {
    const records = await this.state.storage.list({ prefix: `page:${userId}:` });
    return Array.from(records.values()).sort((a, b) => b.created_at.localeCompare(a.created_at)).slice(0, 100);
  }

  async handleListPages(payload) {
    const user = await this.authenticate(payload.token);
    if (!user) return json({ success: false, error: "登录已失效，请重新登录" }, 401);
    return json({ success: true, pages: await this.pagesForUser(user.id) });
  }

  async handleAdminLookup(payload) {
    const query = String(payload.query || "").trim();
    let user = await this.state.storage.get(`user:${query.toLowerCase()}`);
    if (!user) {
      const userId = await this.state.storage.get(`license:${query.toUpperCase()}`);
      if (userId) user = await this.userById(userId);
    }
    if (!user) return json({ success: false, error: "未找到绑定账号" }, 404);
    return json({
      success: true,
      account: {
        id: user.id,
        username: user.username,
        status: user.status,
        license_code: user.license_code,
        created_at: user.created_at,
        last_login_at: user.last_login_at || null,
        last_device: user.last_device || "",
        last_ip_hash: user.last_ip_hash || ""
      },
      pages: await this.pagesForUser(user.id)
    });
  }

  async fetch(request) {
    if (request.method !== "POST") return json({ success: false, error: "Method Not Allowed" }, 405);
    let payload;
    try { payload = await request.json(); }
    catch { return json({ success: false, error: "请求数据错误" }, 400); }
    if (payload.action === "register") return this.handleRegister(payload);
    if (payload.action === "login") return this.handleLogin(payload);
    if (payload.action === "authenticate") return this.handleAuthenticate(payload);
    if (payload.action === "logout") return this.handleLogout(payload);
    if (payload.action === "record_page") return this.handleRecordPage(payload);
    if (payload.action === "list_pages") return this.handleListPages(payload);
    if (payload.action === "admin_lookup") return this.handleAdminLookup(payload);
    return json({ success: false, error: "未知操作" }, 400);
  }
}

async function parseJson(request) {
  try { return { data: await request.json() }; }
  catch { return { error: "请求数据错误" }; }
}

async function adminGuard(request, env, headers) {
  if (!(await checkAdmin(request, env))) return json({ success: false, error: "管理员密码错误" }, 401, headers);
  const limited = await enforceRateLimit(request, env, "admin", 20);
  return limited ? json(limited, 429, headers) : null;
}

async function authenticateRequest(request, env) {
  return accountRequest(env, { action: "authenticate", token: bearerToken(request) });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const headers = corsHeaders(request, env);
    try {
      if (request.method === "OPTIONS") {
        const origin = request.headers.get("Origin");
        if (origin && !headers["Access-Control-Allow-Origin"]) return json({ success: false, error: "来源未获允许" }, 403, headers);
        return new Response(null, { status: 204, headers });
      }

      if (url.pathname === "/" && request.method === "GET") {
        return json({
          success: true,
          message: "HTML Cloud Worker is running",
          account_mode: "one_license_one_account_single_session",
          max_html_bytes: maxHtmlBytes(env),
          bindings: {
            license: Boolean(env.LICENSE_KV), storage: Boolean(env.UPLOAD_BUCKET),
            license_guard: Boolean(env.LICENSE_GUARD), account_registry: Boolean(env.ACCOUNT_REGISTRY)
          }
        }, 200, headers);
      }

      if (url.pathname.startsWith("/p/") && request.method === "GET") {
        const id = url.pathname.slice(3).split("/")[0];
        if (!/^[0-9a-f-]{36}$/i.test(id)) return new Response("网页不存在", { status: 404 });
        const object = await env.UPLOAD_BUCKET.get(pageKey(id));
        if (!object) return new Response("网页不存在", { status: 404 });
        return new Response(object.body, { headers: publicPageHeaders(object) });
      }

      if (["/auth/register", "/auth/login"].includes(url.pathname) && request.method === "POST") {
        const limited = await enforceRateLimit(request, env, "auth", 20);
        if (limited) return json(limited, 429, headers);
        const parsed = await parseJson(request);
        if (parsed.error) return json({ success: false, error: parsed.error }, 400, headers);
        const salt = env.SECURITY_HASH_SALT || env.ADMIN_PASSWORD || "html-cloud";
        const ipHash = await digest(`${salt}:${clientIp(request)}`);
        const action = url.pathname.endsWith("register") ? "register" : "login";
        const { response, data } = await accountRequest(env, {
          action,
          username: parsed.data.username,
          password: parsed.data.password,
          license: parsed.data.license,
          device: request.headers.get("User-Agent") || "",
          ip_hash: ipHash
        });
        return json(data, response.status, headers);
      }

      if (url.pathname === "/auth/logout" && request.method === "POST") {
        const { response, data } = await accountRequest(env, { action: "logout", token: bearerToken(request) });
        return json(data, response.status, headers);
      }

      if (url.pathname === "/me" && request.method === "GET") {
        const { response, data } = await authenticateRequest(request, env);
        return json(data, response.status, headers);
      }

      if (url.pathname === "/me/pages" && request.method === "GET") {
        const { response, data } = await accountRequest(env, { action: "list_pages", token: bearerToken(request) });
        return json(data, response.status, headers);
      }

      if (url.pathname === "/admin/generate" && request.method === "POST") {
        const blocked = await adminGuard(request, env, headers);
        if (blocked) return blocked;
        const parsed = await parseJson(request);
        if (parsed.error) return json({ success: false, error: parsed.error }, 400, headers);
        const body = parsed.data;
        const allowedPlans = ["count", "hour", "day", "week", "month", "forever"];
        const plan = String(body.plan || "count");
        if (!allowedPlans.includes(plan)) return json({ success: false, error: "卡类型错误" }, 400, headers);
        const prefix = String(body.prefix || "HTML").toUpperCase().replace(/[^A-Z0-9]/g, "").slice(0, 12) || "HTML";
        const count = Math.max(1, Math.min(Number(body.count) || 1, 50));
        const duration = Math.max(1, Math.min(Number(body.duration) || 1, 3650));
        const uses = Math.max(1, Math.min(Number(body.uses) || 1, 100000));
        const batch = String(body.batch || "default").slice(0, 80);
        const groupSize = Math.max(3, Math.min(Number(body.groupSize) || 4, 8));
        const groups = Math.max(3, Math.min(Number(body.groups) || 4, 8));
        const codes = [];
        for (let attempt = 0; codes.length < count && attempt < count * 4; attempt++) {
          const code = randomCode(prefix, groupSize, groups);
          const info = {
            code, plan, remaining: plan === "count" ? uses : null, expire_at: null, activated_at: null,
            duration, batch, status: "active", used: 0, account_id: null, created_at: new Date().toISOString()
          };
          const { response } = await licenseRequest(env, code, { action: "initialize", info });
          if (response.ok) codes.push(code);
        }
        if (codes.length !== count) return json({ success: false, error: `仅生成 ${codes.length} 个激活码，请重试`, codes }, 503, headers);
        return json({ success: true, codes }, 200, headers);
      }

      if (url.pathname === "/admin/check" && request.method === "POST") {
        const blocked = await adminGuard(request, env, headers);
        if (blocked) return blocked;
        const parsed = await parseJson(request);
        if (parsed.error) return json({ success: false, error: parsed.error }, 400, headers);
        const code = String(parsed.data.code || "").trim().toUpperCase();
        if (!code) return json({ success: false, error: "缺少激活码" }, 400, headers);
        const { response, data } = await licenseRequest(env, code, { action: "inspect", code });
        return json(data, response.status, headers);
      }

      if (url.pathname === "/admin/action" && request.method === "POST") {
        const blocked = await adminGuard(request, env, headers);
        if (blocked) return blocked;
        const parsed = await parseJson(request);
        if (parsed.error) return json({ success: false, error: parsed.error }, 400, headers);
        const code = String(parsed.data.code || "").trim().toUpperCase();
        const { response, data } = await licenseRequest(env, code, {
          action: "admin_action", code, operation: String(parsed.data.operation || "")
        });
        return json(data, response.status, headers);
      }

      if (url.pathname === "/admin/account" && request.method === "POST") {
        const blocked = await adminGuard(request, env, headers);
        if (blocked) return blocked;
        const parsed = await parseJson(request);
        if (parsed.error) return json({ success: false, error: parsed.error }, 400, headers);
        const { response, data } = await accountRequest(env, { action: "admin_lookup", query: parsed.data.query });
        return json(data, response.status, headers);
      }

      if (url.pathname === "/create" && request.method === "POST") {
        const limited = await enforceRateLimit(request, env, "publish", 30);
        if (limited) return json(limited, 429, headers);
        const contentLength = Number(request.headers.get("Content-Length") || 0);
        if (contentLength > maxHtmlBytes(env) + 100000) return json({ success: false, error: "HTML超过大小限制" }, 413, headers);
        const auth = await authenticateRequest(request, env);
        if (!auth.response.ok) return json(auth.data, auth.response.status, headers);
        const parsed = await parseJson(request);
        if (parsed.error) return json({ success: false, error: parsed.error }, 400, headers);
        const html = String(parsed.data.html || "");
        if (!html.trim()) return json({ success: false, error: "HTML为空" }, 400, headers);
        if (byteLength(html) > maxHtmlBytes(env)) return json({ success: false, error: "HTML超过大小限制" }, 413, headers);
        const user = auth.data.user;
        const id = crypto.randomUUID();
        const urlForRecord = pageUrl(request, env, id);
        const result = await licenseRequest(env, auth.data.license_code, {
          action: "publish", code: auth.data.license_code, account_id: user.id, html,
          id, url: urlForRecord
        });
        if (!result.response.ok) return json(result.data, result.response.status, headers);
        return json({ success: true, url: urlForRecord, remaining: result.data.remaining }, 200, headers);
      }

      if (url.pathname === "/upload" && request.method === "POST") {
        const limited = await enforceRateLimit(request, env, "publish", 30);
        if (limited) return json(limited, 429, headers);
        const contentLength = Number(request.headers.get("Content-Length") || 0);
        if (contentLength > maxHtmlBytes(env) + 100000) return json({ success: false, error: "文件超过大小限制" }, 413, headers);
        const auth = await authenticateRequest(request, env);
        if (!auth.response.ok) return json(auth.data, auth.response.status, headers);
        let form;
        try { form = await request.formData(); }
        catch { return json({ success: false, error: "上传数据错误" }, 400, headers); }
        const file = form.get("file");
        if (!(file instanceof File)) return json({ success: false, error: "没有上传文件" }, 400, headers);
        const extension = file.name.split(".").pop().toLowerCase();
        if (!["html", "htm"].includes(extension)) return json({ success: false, error: "只支持 HTML 或 HTM 文件" }, 400, headers);
        if (file.size > maxHtmlBytes(env)) return json({ success: false, error: "文件超过大小限制" }, 413, headers);
        const html = await file.text();
        if (!html.trim()) return json({ success: false, error: "HTML文件为空" }, 400, headers);
        const user = auth.data.user;
        const id = crypto.randomUUID();
        const urlForRecord = pageUrl(request, env, id);
        const result = await licenseRequest(env, auth.data.license_code, {
          action: "publish", code: auth.data.license_code, account_id: user.id, html,
          id, url: urlForRecord
        });
        if (!result.response.ok) return json(result.data, result.response.status, headers);
        return json({ success: true, url: urlForRecord, remaining: result.data.remaining }, 200, headers);
      }

      return json({ success: false, error: "Not Found" }, 404, headers);
    } catch (error) {
      console.error(error);
      return json({ success: false, error: error.message || "服务器内部错误" }, 500, headers);
    }
  }
};
