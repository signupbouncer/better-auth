// Mounts the plugin in a real Better Auth instance (memory adapter) and signs users up through auth.handler, with
// the signupbouncer API mocked. Only the signupbouncer URL is mocked; Better Auth itself runs unmodified.

import { assert, assertEquals } from "@std/assert";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { genericOAuth, magicLink } from "better-auth/plugins";
import { createAuthMiddleware } from "better-auth/api";
import {
  type CheckError,
  checkSignup,
  DEFAULT_BLOCK_MESSAGE,
  signupBouncer,
  type SignupBouncerOptions,
} from "../mod.ts";
import { providerFor } from "../internal.ts";
import { answer, answerBody, type Call, hang, json, mockFetch } from "./mock_fetch.ts";

const BASE = "http://localhost:3000";

function makeAuth(opts: Partial<SignupBouncerOptions> = {}, extra: Parameters<typeof betterAuth>[0] = {}) {
  const db = { user: [], session: [], account: [], verification: [] } as Record<string, Record<string, unknown>[]>;
  const auth = betterAuth({
    ...extra,
    baseURL: BASE,
    secret: "test-secret-test-secret-test-secret-0123",
    database: memoryAdapter(db),
    emailAndPassword: { enabled: true },
    rateLimit: { enabled: false },
    telemetry: { enabled: false },
    plugins: [signupBouncer({ apiKey: "sb_live_test", baseUrl: "https://sb.test", ...opts })],
  });
  return { auth, db };
}

function signUp(auth: ReturnType<typeof makeAuth>["auth"], email: string, headers: Record<string, string> = {}) {
  return auth.handler(
    new Request(`${BASE}/api/auth/sign-up/email`, {
      method: "POST",
      headers: { "content-type": "application/json", origin: BASE, ...headers },
      body: JSON.stringify({ email, password: "correct-horse-battery", name: "Test" }),
    }),
  );
}

/** Answers checks from the mocked signupbouncer API by email; lets anything else through to the real fetch. */
function mockApi(byEmail: (email: string, call: Call, signal?: AbortSignal) => Response | Promise<Response>) {
  return mockFetch((call, signal) => byEmail(String(call.body.email ?? ""), call, signal));
}

Deno.test("blocked email gets 400 with the block message; allowed email is created", async () => {
  const { auth, db } = makeAuth({ blockMessage: "No burners, please.", ipHeader: "x-forwarded-for" });
  const m = mockApi((email) => answer(email.endsWith("@mailinator.com") ? "block" : "allow"));
  try {
    const blocked = await signUp(auth, "farm1@mailinator.com", {
      "x-forwarded-for": "203.0.113.7, 10.0.0.1",
      "user-agent": "TestUA/1",
    });
    assertEquals(blocked.status, 400);
    const body = await blocked.json();
    assertEquals(body.message, "No burners, please.");
    assertEquals(body.code, "SIGNUP_BLOCKED");
    // One trusted proxy: the right-most entry, which the proxy appended; the first entry is the client's own claim.
    assertEquals(m.calls[0].body, { email: "farm1@mailinator.com", ip: "10.0.0.1", user_agent: "TestUA/1" });

    const allowed = await signUp(auth, "real.person@example.com");
    assertEquals(allowed.status, 200);
    assertEquals(db.user.map((u) => u.email), ["real.person@example.com"]);
  } finally {
    m.restore();
  }
});

Deno.test("challenge: allowed by default, blocked with challenge: 'block'", async () => {
  const m = mockApi(() => answer("challenge"));
  try {
    const lenient = makeAuth();
    assertEquals((await signUp(lenient.auth, "maybe@example.com")).status, 200);
    assertEquals(lenient.db.user.length, 1);

    const strict = makeAuth({ challenge: "block" });
    assertEquals((await signUp(strict.auth, "maybe@example.com")).status, 400);
    assertEquals(strict.db.user.length, 0);
  } finally {
    m.restore();
  }
});

Deno.test("API failures fail open and call onError", async () => {
  const cases: [string, Parameters<typeof mockApi>[0], CheckError["reason"]][] = [
    ["500", () => json({ error: "x" }, 500), "http_status"],
    ["bad json", () => new Response("not json", { status: 200 }), "bad_response"],
    ["timeout", (_e, _c, signal) => hang(_c, signal), "timeout"],
    ["network", () => Promise.reject(new TypeError("refused")), "network"],
    [
      "502 errored body",
      () => new Response(new ReadableStream({ start: (c) => c.error(new TypeError("reset")) }), { status: 502 }),
      "http_status",
    ],
  ];
  for (const [name, handler, reason] of cases) {
    const errors: CheckError[] = [];
    const { auth, db } = makeAuth({ timeoutMs: 50, onError: (e) => errors.push(e) });
    const m = mockApi(handler);
    try {
      const res = await signUp(auth, `user-${name.replaceAll(" ", "")}@example.com`);
      assertEquals(res.status, 200, name);
      assertEquals(db.user.length, 1, name);
      assertEquals(errors.map((e) => e.reason), [reason], name);
    } finally {
      m.restore();
    }
  }
});

Deno.test("no IP header: checks the email alone", async () => {
  const { auth } = makeAuth({ ipHeader: "x-real-ip" });
  const m = mockApi(() => answer("allow"));
  try {
    assertEquals((await signUp(auth, "a@example.com")).status, 200);
    assertEquals(m.calls.length, 1);
    assertEquals("ip" in m.calls[0].body, false);
  } finally {
    m.restore();
  }
});

Deno.test("default: no IP header is trusted, so spoofed headers never reach the check", async () => {
  const { auth } = makeAuth();
  const m = mockApi(() => answer("allow"));
  try {
    const res = await signUp(auth, "a@example.com", {
      "cf-connecting-ip": "198.51.100.66",
      "x-forwarded-for": "198.51.100.67",
      "x-real-ip": "198.51.100.68",
    });
    assertEquals(res.status, 200);
    assertEquals(m.calls[0].body, { email: "a@example.com" });
  } finally {
    m.restore();
  }
});

Deno.test("ipHeader: a caller-supplied cf-connecting-ip cannot replace the trusted header", async () => {
  const { auth, db } = makeAuth({ ipHeader: "x-real-ip" });
  const m = mockApi((_email, call) => answer(call.body.ip === "203.0.113.7" ? "block" : "allow"));
  try {
    const res = await signUp(auth, "farm@example.com", {
      "x-real-ip": "203.0.113.7",
      "cf-connecting-ip": "198.51.100.1",
    });
    assertEquals(res.status, 400);
    assertEquals(m.calls[0].body.ip, "203.0.113.7");
    assertEquals(db.user.length, 0);
  } finally {
    m.restore();
  }
});

Deno.test("getIp: wins over ipHeader; a throwing getIp checks the email alone", async () => {
  const seen: (Request | undefined)[] = [];
  const custom = makeAuth({
    ipHeader: "x-real-ip",
    getIp: (request, headers) => {
      seen.push(request);
      return headers?.get("x-my-proxy-ip") ?? undefined;
    },
  });
  const broken = makeAuth({
    getIp: () => {
      throw new Error("bug");
    },
  });
  const m = mockApi(() => answer("allow"));
  try {
    assertEquals(
      (await signUp(custom.auth, "a@example.com", { "x-my-proxy-ip": "203.0.113.9", "x-real-ip": "1.1.1.1" })).status,
      200,
    );
    assertEquals(m.calls[0].body.ip, "203.0.113.9");
    assert(seen[0] instanceof Request);
    assertEquals((await signUp(broken.auth, "b@example.com", { "x-real-ip": "1.1.1.1" })).status, 200);
    assertEquals(m.calls[1].body, { email: "b@example.com" });
  } finally {
    m.restore();
  }
});

Deno.test("checkOtherSignups: email sign-up is still checked exactly once", async () => {
  const { auth } = makeAuth({ checkOtherSignups: true, ipHeader: "cf-connecting-ip" });
  const m = mockApi(() => answer("allow"));
  try {
    assertEquals((await signUp(auth, "once@example.com", { "cf-connecting-ip": "198.51.100.9" })).status, 200);
    assertEquals(m.calls.length, 1);
    assertEquals(m.calls[0].body.ip, "198.51.100.9");
  } finally {
    m.restore();
  }
});

Deno.test("checkOtherSignups: a real magic-link sign-up is checked and blocked; off by default", async () => {
  for (const checkOtherSignups of [true, false]) {
    let link = "";
    const db = { user: [], session: [], account: [], verification: [] } as Record<string, Record<string, unknown>[]>;
    const auth = betterAuth({
      baseURL: BASE,
      secret: "test-secret-test-secret-test-secret-0123",
      database: memoryAdapter(db),
      rateLimit: { enabled: false },
      telemetry: { enabled: false },
      plugins: [
        magicLink({ sendMagicLink: ({ url }) => void (link = url) }),
        signupBouncer({ apiKey: "sb_live_test", baseUrl: "https://sb.test", checkOtherSignups, ipHeader: "x-real-ip" }),
      ],
    });
    const m = mockApi(() => answer("block"));
    try {
      const sent = await auth.handler(
        new Request(`${BASE}/api/auth/sign-in/magic-link`, {
          method: "POST",
          headers: { "content-type": "application/json", origin: BASE },
          body: JSON.stringify({ email: "farm2@mailinator.com" }),
        }),
      );
      assertEquals(sent.status, 200);
      assert(link, "magic link captured");
      const res = await auth.handler(new Request(link, { headers: { "x-real-ip": "203.0.113.60" } }));
      await res.body?.cancel();
      if (checkOtherSignups) {
        assertEquals(m.calls.map((c) => c.body), [{ email: "farm2@mailinator.com", ip: "203.0.113.60" }]);
        assertEquals(db.user.length, 0);
      } else {
        assertEquals(m.calls.length, 0);
        assertEquals(db.user.length, 1);
      }
    } finally {
      m.restore();
    }
  }
});

Deno.test("database hook: blocks other paths; verified OAuth sends the provider from ctx.params", async () => {
  const plugin = signupBouncer({
    apiKey: "sb_live_test",
    baseUrl: "https://sb.test",
    checkOtherSignups: true,
    ipHeader: "x-forwarded-for",
  });
  // deno-lint-ignore no-explicit-any
  const init = await (plugin.init as any)({});
  const before = init.options.databaseHooks.user.create.before as (
    user: { email: string; emailVerified?: boolean },
    ctx?: { path?: string; params?: Record<string, string>; headers?: Headers },
  ) => Promise<unknown>;
  const m = mockApi(() => answer("block"));
  try {
    const headers = new Headers({ "x-forwarded-for": "198.51.100.99, 203.0.113.50" });
    let threw = false;
    try {
      await before({ email: "x@mailinator.com" }, { path: "/magic-link/verify", headers });
    } catch (e) {
      threw = (e as { name?: string }).name === "APIError";
    }
    assert(threw, "magic-link signup should be blocked");
    assertEquals(m.calls[0].body, { email: "x@mailinator.com", ip: "203.0.113.50" });

    // Better Auth passes the route pattern as path and the provider in params (P2-5).
    threw = false;
    try {
      await before(
        { email: "x@gmail.com", emailVerified: true },
        { path: "/callback/:id", params: { id: "google" }, headers },
      );
    } catch {
      threw = true;
    }
    assert(threw, "oauth signup from a blocked IP should be blocked");
    assertEquals(m.calls[1].body, { email: "x@gmail.com", ip: "203.0.113.50", auth_provider: "google" });

    // An unverified OAuth email is checked as an email, with no auth_provider (P1-2).
    await before({ email: "y@mailinator.com", emailVerified: false }, {
      path: "/callback/:id",
      params: { id: "acme" },
      headers,
    }).catch(() => {});
    assertEquals(m.calls[2].body, { email: "y@mailinator.com", ip: "203.0.113.50" });

    // Skipped: no endpoint context (server code), admin-created users, anonymous users.
    await before({ email: "x@mailinator.com" });
    await before({ email: "x@mailinator.com" }, { path: "/admin/create-user", headers });
    await before({ email: "x@mailinator.com" }, { path: "/sign-in/anonymous", headers });
    assertEquals(m.calls.length, 3);

    // Without an IP source a verified OAuth sign-up is still sent (email + provider).
    const noIp = signupBouncer({ apiKey: "sb_live_test", baseUrl: "https://sb.test", checkOtherSignups: true });
    // deno-lint-ignore no-explicit-any
    const noIpBefore = (await (noIp.init as any)({})).options.databaseHooks.user.create.before;
    await noIpBefore({ email: "x@gmail.com", emailVerified: true }, {
      path: "/callback/:id",
      params: { id: "github" },
      headers,
    }).catch(() => {});
    assertEquals(m.calls[3].body, { email: "x@gmail.com", auth_provider: "github" });
  } finally {
    m.restore();
  }
});

Deno.test("providerFor: params id or providerId, One Tap, ID-token sign-in, fallback", () => {
  assertEquals(providerFor({ path: "/callback/:id", params: { id: "google" } }), "google");
  assertEquals(providerFor({ path: "/sso/callback/:providerId", params: { providerId: "okta" } }), "okta");
  assertEquals(providerFor({ path: "/one-tap/callback" }), "google");
  assertEquals(providerFor({ path: "/sign-in/social", body: { provider: "apple" } }), "apple");
  assertEquals(providerFor({ path: "/sign-in/social", body: { provider: "<script>" } }), "oauth");
  assertEquals(providerFor({ path: "/callback/:id", params: { id: ":id" } }), "oauth");
  assertEquals(providerFor({ path: "/callback/:id" }), "oauth");
});

Deno.test("checkSignup sends auth_provider only when given", async () => {
  const m = mockApi(() => answer("allow"));
  try {
    await checkSignup({ apiKey: "sb_live_test", baseUrl: "https://sb.test" }, { email: "a@b.com" });
    await checkSignup({ apiKey: "sb_live_test", baseUrl: "https://sb.test" }, {
      email: "a@b.com",
      authProvider: "github",
    });
    assertEquals(m.calls.map((c) => c.body), [{ email: "a@b.com" }, { email: "a@b.com", auth_provider: "github" }]);
  } finally {
    m.restore();
  }
});

// ---- regressions from earlier security reviews (#1 to #5) ----------------------------------------------------------

Deno.test("#1 a real sign-up is not refused by a partial answer ({ action: 'block' } alone)", async () => {
  const errors: CheckError[] = [];
  const { auth, db } = makeAuth({ onError: (e) => errors.push(e) });
  const m = mockApi(() => json({ action: "block" }));
  try {
    const res = await signUp(auth, "partial@example.com");
    assertEquals(res.status, 200);
    assertEquals(db.user.length, 1);
    assertEquals(errors, [{ reason: "bad_response", status: 200 }]);
  } finally {
    m.restore();
  }
});

Deno.test("#3 a real sign-up survives an async onError that rejects", async () => {
  const { auth, db } = makeAuth({
    onError: async () => {
      await Promise.resolve();
      throw new Error("logging service unavailable");
    },
  });
  const m = mockApi(() => json({ error: "x" }, 503));
  try {
    assertEquals((await signUp(auth, "logger-down@example.com")).status, 200);
    assertEquals(db.user.length, 1);
    await new Promise((r) => setTimeout(r, 20)); // an unhandled rejection would fail this test
  } finally {
    m.restore();
  }
});

// ---- Astra review fixes (P1-1, P1-2, P1-3, P2-5) --------------------------------------------------------------------

Deno.test("email sign-up makes exactly one check, with and without checkOtherSignups", async () => {
  for (const checkOtherSignups of [false, true]) {
    const { auth, db } = makeAuth({ checkOtherSignups });
    const m = mockApi(() => answer("allow"));
    try {
      assertEquals((await signUp(auth, "Once@Example.com")).status, 200);
      assertEquals(m.calls.map((c) => c.body.email), ["Once@Example.com"]);
      assertEquals(db.user.length, 1);
    } finally {
      m.restore();
    }
  }
});

Deno.test("P1-1 a 66k-character email is refused before any request and no user is saved", async () => {
  const { auth, db } = makeAuth();
  const m = mockApi(() => json({ error: "body_too_large" }, 413)); // what the real API answers to a 64 KiB+ body
  try {
    const email = "a".repeat(66_000) + "@mailinator.com";
    const res = await signUp(auth, email);
    assertEquals(res.status, 400);
    assertEquals((await res.json()).code, "SIGNUP_BLOCKED");
    assertEquals(m.calls.length, 0);
    assertEquals(db.user.length, 0);
  } finally {
    m.restore();
  }
});

Deno.test("P1-3 an app hook that rewrites the email cannot slip the rewritten address past the check", async () => {
  for (const checkOtherSignups of [false, true]) {
    const { auth, db } = makeAuth({ checkOtherSignups }, {
      hooks: {
        // deno-lint-ignore require-await
        before: createAuthMiddleware(async (ctx) => {
          if (ctx.path !== "/sign-up/email") return;
          return { context: { body: { ...(ctx.body as object), email: "blocked@mailinator.com" } } };
        }),
      },
    });
    const m = mockApi((email) => answer(email.endsWith("@mailinator.com") ? "block" : "allow"));
    try {
      const res = await signUp(auth, "innocent@example.com");
      assertEquals(res.status, 400, `checkOtherSignups: ${checkOtherSignups}`);
      assertEquals((await res.json()).code, "SIGNUP_BLOCKED");
      assertEquals(m.calls.map((c) => c.body.email), ["innocent@example.com", "blocked@mailinator.com"]);
      assertEquals(db.user.length, 0);
    } finally {
      m.restore();
    }
  }
});

/** Runs a real generic-OAuth sign-up (sign-in/social, then /callback/acme) with the IdP replaced by functions. */
async function oauthSignUp(emailVerified: boolean, email: string) {
  const db = { user: [], session: [], account: [], verification: [] } as Record<string, Record<string, unknown>[]>;
  const auth = betterAuth({
    baseURL: BASE,
    secret: "test-secret-test-secret-test-secret-0123",
    database: memoryAdapter(db),
    rateLimit: { enabled: false },
    telemetry: { enabled: false },
    plugins: [
      genericOAuth({
        config: [{
          providerId: "acme",
          clientId: "client",
          clientSecret: "secret",
          authorizationUrl: "https://idp.test/authorize",
          getToken: () => Promise.resolve({ accessToken: "at", tokenType: "Bearer" }),
          getUserInfo: () => Promise.resolve({ id: "idp-user-1", email, emailVerified, name: "Test" }),
        }],
      }),
      signupBouncer({ apiKey: "sb_live_test", baseUrl: "https://sb.test", checkOtherSignups: true }),
    ],
  });
  const start = await auth.handler(
    new Request(`${BASE}/api/auth/sign-in/social`, {
      method: "POST",
      headers: { "content-type": "application/json", origin: BASE },
      body: JSON.stringify({ provider: "acme", callbackURL: `${BASE}/done`, errorCallbackURL: `${BASE}/error` }),
    }),
  );
  assertEquals(start.status, 200);
  const { url } = await start.json();
  const state = new URL(url).searchParams.get("state");
  assert(state, "authorization URL carries a state");
  const cookie = start.headers.getSetCookie().map((c) => c.split(";")[0]).join("; ");
  const callback = await auth.handler(
    new Request(`${BASE}/api/auth/callback/acme?code=code-1&state=${encodeURIComponent(state)}`, {
      headers: { cookie },
    }),
  );
  await callback.body?.cancel();
  return { db, location: callback.headers.get("location") ?? "" };
}

Deno.test("P1-2 + P2-5 real OAuth callback: verified email sends the real provider id, unverified is checked as email", async () => {
  const m = mockApi((email) => answer(email.endsWith("@mailinator.com") ? "block" : "allow"));
  try {
    const verified = await oauthSignUp(true, "person@example.com");
    assertEquals(m.calls.map((c) => c.body), [{ email: "person@example.com", auth_provider: "acme" }]);
    assertEquals(verified.db.user.length, 1);
    assert(verified.location.startsWith(`${BASE}/done`), verified.location);

    const unverified = await oauthSignUp(false, "farm@mailinator.com");
    assertEquals(m.calls[1].body, { email: "farm@mailinator.com" });
    assertEquals(unverified.db.user.length, 0);
    assert(unverified.location.startsWith(`${BASE}/error`), unverified.location);
  } finally {
    m.restore();
  }
});

Deno.test("#40 a blocked sign-up shows the dashboard's block_message; blockMessage in code wins over it", async () => {
  const sent = "Did you mean ann@gmail.com?";
  const m = mockApi((email) =>
    email.startsWith("nomsg") ? answer("block") : json({ ...answerBody("block"), block_message: sent })
  );
  try {
    const cases: [Partial<SignupBouncerOptions>, string, string][] = [
      [{}, "ann@gmial.com", sent],
      [{ blockMessage: "No burners, please." }, "ann2@gmial.com", "No burners, please."],
      [{ blockMessage: "  " }, "ann3@gmial.com", sent],
      [{}, "nomsg@gmial.com", DEFAULT_BLOCK_MESSAGE],
    ];
    for (const [opts, email, expected] of cases) {
      const { auth, db } = makeAuth(opts);
      const res = await signUp(auth, email);
      assertEquals(res.status, 400);
      const body = await res.json();
      assertEquals([body.code, body.message], ["SIGNUP_BLOCKED", expected]);
      assertEquals(db.user.length, 0);
    }
  } finally {
    m.restore();
  }
});
