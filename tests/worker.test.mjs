import assert from "node:assert/strict";
import test from "node:test";
import worker, { AccountRegistry, LicenseGuard } from "../worker.js";

class MemoryStorage {
  constructor() { this.data = new Map(); }
  async get(key) { return this.data.get(key); }
  async put(key, value) {
    if (typeof key === "object") {
      for (const [itemKey, itemValue] of Object.entries(key)) this.data.set(itemKey, structuredClone(itemValue));
      return;
    }
    this.data.set(key, structuredClone(value));
  }
  async delete(key) { this.data.delete(key); }
  async list({ prefix = "" } = {}) { return new Map(Array.from(this.data).filter(([key]) => key.startsWith(prefix))); }
}

class MemoryKV {
  constructor() { this.data = new Map(); }
  async get(key) { return this.data.get(key) ?? null; }
  async put(key, value) { this.data.set(key, value); }
}

class MemoryR2 {
  constructor() { this.data = new Map(); this.failNextPut = false; }
  async put(key, value, options = {}) {
    if (this.failNextPut) { this.failNextPut = false; throw new Error("R2 write failed"); }
    this.data.set(key, { value, options });
  }
  async get(key) {
    const item = this.data.get(key);
    if (!item) return null;
    return {
      body: item.value,
      httpEtag: '"test-etag"',
      writeHttpMetadata(headers) {
        if (item.options.httpMetadata?.contentType) headers.set("Content-Type", item.options.httpMetadata.contentType);
      }
    };
  }
}

class MemoryNamespace {
  constructor(env, DurableObjectClass) { this.env = env; this.DurableObjectClass = DurableObjectClass; this.instances = new Map(); }
  idFromName(name) { return name; }
  get(id) {
    if (!this.instances.has(id)) this.instances.set(id, new this.DurableObjectClass({ storage: new MemoryStorage() }, this.env));
    const instance = this.instances.get(id);
    return { fetch: (url, init) => instance.fetch(new Request(url, init)) };
  }
}

function createEnv() {
  const env = {
    ADMIN_PASSWORD: "test-admin-password",
    SECURITY_HASH_SALT: "test-security-hash-salt",
    ALLOWED_ORIGINS: "https://frontend.example",
    PUBLIC_PAGE_ORIGIN: "https://pages.example",
    MAX_HTML_BYTES: "5242880",
    LICENSE_KV: new MemoryKV(),
    UPLOAD_BUCKET: new MemoryR2()
  };
  env.LICENSE_GUARD = new MemoryNamespace(env, LicenseGuard);
  env.ACCOUNT_REGISTRY = new MemoryNamespace(env, AccountRegistry);
  return env;
}

function apiRequest(path, { body: requestBody, ip = "203.0.113.10", token, admin = false, method } = {}) {
  const headers = { "CF-Connecting-IP": ip, "Origin": "https://frontend.example", "User-Agent": "HTMLCloud-Test/1.0" };
  if (requestBody !== undefined) headers["Content-Type"] = "application/json";
  if (token) headers.Authorization = `Bearer ${token}`;
  if (admin) headers.Authorization = "Bearer test-admin-password";
  return new Request(`https://api.example${path}`, {
    method: method || (requestBody !== undefined ? "POST" : "GET"), headers,
    body: requestBody !== undefined ? JSON.stringify(requestBody) : undefined
  });
}

async function responseBody(response) { return response.json(); }

async function generate(env, overrides = {}) {
  const response = await worker.fetch(apiRequest("/admin/generate", {
    admin: true,
    body: { prefix: "TEST", count: 1, plan: "count", uses: 2, duration: 1, batch: "unit", groupSize: 4, groups: 4, ...overrides }
  }), env);
  assert.equal(response.status, 200);
  return (await responseBody(response)).codes[0];
}

async function register(env, username, license, password = "password-123") {
  const response = await worker.fetch(apiRequest("/auth/register", { body: { username, password, license } }), env);
  return { response, data: await responseBody(response) };
}

test("one activation code registers one account and cannot be transferred", async () => {
  const env = createEnv();
  const code = await generate(env);
  assert.match(code, /^TEST(?:-[A-Z2-9]{4}){4}$/);

  const first = await register(env, "account_one", code);
  assert.equal(first.response.status, 200);
  assert.equal(first.data.user.username, "account_one");
  assert.equal(first.data.user.license.code, code);

  const reusedCode = await register(env, "account_two", code);
  assert.equal(reusedCode.response.status, 409);
  assert.match(reusedCode.data.error, /已绑定账号/);

  const secondCode = await generate(env, { prefix: "NEXT" });
  const reusedUsername = await register(env, "account_one", secondCode);
  assert.equal(reusedUsername.response.status, 409);
  assert.match(reusedUsername.data.error, /账号已存在/);
  assert.equal(JSON.parse(await env.LICENSE_KV.get(secondCode)).account_id, null);
});

test("new login invalidates the previous session", async () => {
  const env = createEnv();
  const code = await generate(env);
  const registered = await register(env, "single_session", code);
  const firstToken = registered.data.token;

  const loginResponse = await worker.fetch(apiRequest("/auth/login", {
    body: { username: "single_session", password: "password-123" }, ip: "198.51.100.20"
  }), env);
  assert.equal(loginResponse.status, 200);
  const secondToken = (await responseBody(loginResponse)).token;
  assert.notEqual(secondToken, firstToken);
  assert.equal((await worker.fetch(apiRequest("/me", { token: firstToken }), env)).status, 401);
  assert.equal((await worker.fetch(apiRequest("/me", { token: secondToken }), env)).status, 200);
});

test("publishes with an account session and exposes records to user and admin", async () => {
  const env = createEnv();
  const code = await generate(env);
  const registered = await register(env, "publisher", code);
  const token = registered.data.token;

  const publishResponse = await worker.fetch(apiRequest("/create", {
    token, body: { html: "<!doctype html><title>Account Page</title><h1>ok</h1>" }
  }), env);
  assert.equal(publishResponse.status, 200);
  const published = await responseBody(publishResponse);
  assert.match(published.url, /^https:\/\/pages\.example\/p\/[0-9a-f-]{36}$/);
  assert.equal(published.remaining, 1);

  const pagesResponse = await worker.fetch(apiRequest("/me/pages", { token }), env);
  assert.equal(pagesResponse.status, 200);
  const pages = (await responseBody(pagesResponse)).pages;
  assert.equal(pages.length, 1);
  assert.equal(pages[0].title, "Account Page");
  assert.equal(pages[0].url, published.url);

  const relogin = await worker.fetch(apiRequest("/auth/login", {
    body: { username: "publisher", password: "password-123" }
  }), env);
  assert.equal(relogin.status, 200);
  assert.equal((await responseBody(relogin)).user.license.remaining, 1);

  for (const query of ["publisher", code]) {
    const lookupResponse = await worker.fetch(apiRequest("/admin/account", { admin: true, body: { query } }), env);
    assert.equal(lookupResponse.status, 200);
    const lookup = await responseBody(lookupResponse);
    assert.equal(lookup.account.username, "publisher");
    assert.equal(lookup.pages[0].url, published.url);
    assert.equal(lookup.account.last_device, "HTMLCloud-Test/1.0");
    assert.match(lookup.account.last_ip_hash, /^[0-9a-f]{64}$/);
  }

  const page = await worker.fetch(apiRequest(new URL(published.url).pathname), env);
  assert.equal(page.status, 200);
  assert.match(page.headers.get("Content-Security-Policy"), /^sandbox/);
  assert.equal(page.headers.get("X-Content-Type-Options"), "nosniff");
});

test("does not consume usage when page storage fails", async () => {
  const env = createEnv();
  const code = await generate(env, { uses: 1 });
  const registered = await register(env, "storage_retry", code);
  env.UPLOAD_BUCKET.failNextPut = true;

  const originalConsoleError = console.error;
  console.error = () => {};
  let failed;
  try {
    failed = await worker.fetch(apiRequest("/create", {
      token: registered.data.token, body: { html: "<!doctype html><title>Failed</title>" }
    }), env);
  } finally {
    console.error = originalConsoleError;
  }
  assert.equal(failed.status, 500);
  assert.equal(JSON.parse(await env.LICENSE_KV.get(code)).remaining, 1);

  const retry = await worker.fetch(apiRequest("/create", {
    token: registered.data.token, body: { html: "<!doctype html><title>Saved</title>" }
  }), env);
  assert.equal(retry.status, 200);
  assert.equal((await responseBody(retry)).remaining, 0);
});

test("timed plan starts at registration and revoked license blocks publishing", async () => {
  const env = createEnv();
  const code = await generate(env, { prefix: "TIME", plan: "day", duration: 2 });
  assert.equal(JSON.parse(await env.LICENSE_KV.get(code)).expire_at, null);

  const registered = await register(env, "timed_user", code);
  assert.equal(registered.response.status, 200);
  const stored = JSON.parse(await env.LICENSE_KV.get(code));
  assert.ok(stored.activated_at);
  assert.ok(stored.expire_at);
  assert.equal(new Date(stored.expire_at).getTime() - new Date(stored.activated_at).getTime(), 2 * 24 * 60 * 60 * 1000);

  const revoke = await worker.fetch(apiRequest("/admin/action", {
    admin: true, body: { code, operation: "revoke" }
  }), env);
  assert.equal(revoke.status, 200);

  const publish = await worker.fetch(apiRequest("/create", {
    token: registered.data.token, body: { html: "<!doctype html><title>Blocked</title>" }
  }), env);
  assert.equal(publish.status, 403);
  assert.match((await responseBody(publish)).error, /已作废/);
  assert.equal(env.UPLOAD_BUCKET.data.size, 0);
});
