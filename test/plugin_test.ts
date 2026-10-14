// Mounts the plugin in a real Better Auth instance (memory adapter) and signs users up through auth.handler, with
// the signupbouncer API mocked. Only the signupbouncer URL is mocked; Better Auth itself runs unmodified.

import { assert, assertEquals } from "@std/assert";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { magicLink } from "better-auth/plugins";
import { type CheckError, checkSignup, providerFromPath, signupBouncer, type SignupBouncerOptions } from "../mod.ts";
import { answer, type Call, hang, json, mockFetch } from "./mock_fetch.ts";

const BASE = "http://localhost:3000";

function makeAuth(opts: Partial<SignupBouncerOptions> = {}) {
  const db = { user: [], session: [], account: [], verification: [] } as Record<string, Record<string, unknown>[]>;
  const auth = betterAuth({
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

Deno.test("checkOtherSignups: database hook blocks a non-email-signup path; OAuth sends the provider", async () => {
  const plugin = signupBouncer({
    apiKey: "sb_live_test",
    baseUrl: "https://sb.test",
    checkOtherSignups: true,
    ipHeader: "x-forwarded-for",
  });
  // deno-lint-ignore no-explicit-any
  const init = await (plugin.init as any)({});
  const before = init.options.databaseHooks.user.create.before as (
    user: { email: string },
    ctx?: { path?: string; headers?: Headers },
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

    threw = false;
    try {
      await before({ email: "x@gmail.com" }, { path: "/callback/google", headers });
    } catch {
      threw = true;
    }
    assert(threw, "oauth signup from a blocked IP should be blocked");
    // The provider-verified email goes with its provider, so the API scores IP only but keeps the domain.
    assertEquals(m.calls[1].body, { email: "x@gmail.com", ip: "203.0.113.50", auth_provider: "google" });

    // Skipped: no endpoint context (server code), the email sign-up path, admin-created users.
    await before({ email: "x@mailinator.com" });
    await before({ email: "x@mailinator.com" }, { path: "/sign-up/email", headers });
    await before({ email: "x@mailinator.com" }, { path: "/admin/create-user", headers });
    assertEquals(m.calls.length, 2);

    // Without an IP source an OAuth sign-up is still sent (email + provider), so an OAuth-only app's sign-ups count.
    const noIp = signupBouncer({ apiKey: "sb_live_test", baseUrl: "https://sb.test", checkOtherSignups: true });
    // deno-lint-ignore no-explicit-any
    const noIpBefore = (await (noIp.init as any)({})).options.databaseHooks.user.create.before;
    await noIpBefore({ email: "x@gmail.com" }, { path: "/callback/github", headers }).catch(() => {});
    assertEquals(m.calls[2].body, { email: "x@gmail.com", auth_provider: "github" });
  } finally {
    m.restore();
  }
});

Deno.test("providerFromPath: callback ids, One Tap, ID-token sign-in, fallback", () => {
  assertEquals(providerFromPath("/callback/google"), "google");
  assertEquals(providerFromPath("/oauth2/callback/acme-oidc"), "acme-oidc");
  assertEquals(providerFromPath("/sso/callback/okta"), "okta");
  assertEquals(providerFromPath("/one-tap/callback"), "google");
  assertEquals(providerFromPath("/sign-in/social", { provider: "apple" }), "apple");
  assertEquals(providerFromPath("/sign-in/social", { provider: "<script>" }), "oauth");
  assertEquals(providerFromPath("/callback"), "oauth");
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
