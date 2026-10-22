// finaldynamics/signupbouncer#248: the second look at email confirmation (POST /v1/confirm). With `secondLook: true`
// the plugin reports each click on Better Auth's verification link, record only: it never refuses one, and every failure
// lets the confirmation through. signupBouncerConfirm, in beforeEmailVerification, may refuse a button press or a typed
// code. Runs a real Better Auth instance (memory adapter) with only the SignupBouncer API mocked.

import { assert, assertEquals } from "@std/assert";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { emailOTP } from "better-auth/plugins";
import {
  type CheckError,
  CONFIRM_TIMEOUT_MS,
  confirmBlockMessage,
  confirmSignup,
  DEFAULT_CONFIRM_MESSAGE,
  signupBouncer,
  signupBouncerConfirm,
  type SignupBouncerOptions,
} from "../mod.ts";
import { answer, type Call, hang, json, mockFetch } from "./mock_fetch.ts";

const BASE = "http://localhost:3000";
const UA = "Mozilla/5.0 (X11; Linux x86_64) Firefox/140.0";
const CHECK_ID = "chk_0123456789abcdef01234567";
const BLOCK_MESSAGE = "We couldn't create your account. Please contact us if you need help.";
const SECRET = "test-secret-test-secret-test-secret-0123";

/** A body shaped like the real /v1/confirm answer (signupbouncer api/src/second_look.ts handleConfirm). */
function confirmBody(
  action: "allow" | "block",
  extra: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    verdict: action,
    action,
    mode: "enforce",
    score: action === "block" ? 85 : 45,
    check_id: CHECK_ID,
    first: { verdict: "challenge", score: 45 },
    reasons: [
      { code: "free_subdomain_mail", detail: "x", points: 45, tier: "free" },
      ...(action === "block" ? [{ code: "confirm_from_datacenter", detail: "y", points: 40, tier: "free" }] : []),
    ],
    shadow: [],
    second_look: true,
    replayed: false,
    latency_ms: 6.2,
    ...(action === "block" ? { block_message: BLOCK_MESSAGE } : {}),
    ...extra,
  };
}

type ConfirmHandler = (call: Call, signal?: AbortSignal) => Response | Promise<Response>;

/** /v1/check answers challenge (let through); /v1/confirm answers with `onConfirm`. */
function mockApi(onConfirm: ConfirmHandler) {
  const m = mockFetch((call, signal) =>
    call.url.endsWith("/v1/confirm") ? onConfirm(call, signal) : answer("challenge")
  );
  return { ...m, confirms: () => m.calls.filter((c) => c.url.endsWith("/v1/confirm")) };
}

type Db = Record<string, Record<string, unknown>[]>;

function makeAuth(
  opts: Partial<SignupBouncerOptions> = {},
  verification: { beforeEmailVerification?: (user: { email: string }, request?: Request) => Promise<void> } = {},
  adapter: (db: Db) => ReturnType<typeof memoryAdapter> = memoryAdapter,
) {
  const db = { user: [], session: [], account: [], verification: [] } as Db;
  const links: string[] = [];
  const auth = betterAuth({
    baseURL: BASE,
    secret: SECRET,
    database: adapter(db),
    emailAndPassword: { enabled: true, requireEmailVerification: true },
    emailVerification: {
      sendOnSignUp: true,
      sendVerificationEmail: ({ url }) => {
        links.push(url);
        return Promise.resolve();
      },
      ...verification,
    },
    rateLimit: { enabled: false },
    telemetry: { enabled: false },
    plugins: [signupBouncer({ apiKey: "sb_live_test", baseUrl: "https://sb.test", ipHeader: "x-real-ip", ...opts })],
  });
  return { auth, db, links };
}

/** Signs up, then opens the emailed verification link like a browser. Returns the link's response. */
async function signUpAndConfirm(
  { auth, links }: ReturnType<typeof makeAuth>,
  email: string,
  headers: Record<string, string> = { "user-agent": UA, "x-real-ip": "198.51.100.4" },
) {
  const signedUp = await auth.handler(
    new Request(`${BASE}/api/auth/sign-up/email`, {
      method: "POST",
      headers: { "content-type": "application/json", origin: BASE },
      body: JSON.stringify({ email, password: "correct-horse-battery", name: "Test" }),
    }),
  );
  assertEquals(signedUp.status, 200);
  await signedUp.body?.cancel();
  // Better Auth may send the mail in the background.
  for (let i = 0; i < 50 && links.length === 0; i++) await new Promise((r) => setTimeout(r, 10));
  const link = links.at(-1);
  assert(link, "verification link captured");
  const res = await auth.handler(new Request(link, { headers }));
  await res.body?.cancel();
  return res;
}

const verified = (db: Record<string, Record<string, unknown>[]>, email: string) =>
  db.user.find((u) => u.email === email)?.emailVerified === true;

Deno.test("secondLook: the click on the verification link is reported with via link, after the address is verified", async () => {
  const app = makeAuth({ secondLook: true });
  let verifiedWhenReported: boolean | undefined;
  const m = mockApi(() => {
    verifiedWhenReported = verified(app.db, "challenged@example.com");
    return json(confirmBody("allow"));
  });
  try {
    const res = await signUpAndConfirm(app, "challenged@example.com");
    assert(res.status === 302 || res.status === 200, `status ${res.status}`);
    assert(verified(app.db, "challenged@example.com"));
    assertEquals(m.confirms().map((c) => [c.url, c.body]), [[
      "https://sb.test/v1/confirm",
      { via: "link", email: "challenged@example.com", ip: "198.51.100.4", user_agent: UA },
    ]]);
    assertEquals(m.confirms()[0].headers.get("authorization"), "Bearer sb_live_test");
    assertEquals(m.confirms()[0].redirect, "manual");
    assertEquals(verifiedWhenReported, true);
  } finally {
    m.restore();
  }
});

Deno.test("secondLook: a block answer never refuses a link confirmation", async () => {
  const errors: CheckError[] = [];
  const app = makeAuth({ secondLook: true, onError: (e) => errors.push(e) });
  const m = mockApi(() => json(confirmBody("block")));
  try {
    const res = await signUpAndConfirm(app, "farm@example.com");
    assert(res.status === 302 || res.status === 200, `status ${res.status}`);
    assert(verified(app.db, "farm@example.com"));
    assertEquals(m.confirms().length, 1);
    assertEquals(errors, []);
  } finally {
    m.restore();
  }
});

Deno.test("secondLook: fails open on timeout, error status, network error and a bad answer", async () => {
  const cases: [string, ConfirmHandler, CheckError | null][] = [
    ["timeout", (c, s) => hang(c, s), { reason: "timeout", call: "confirm" }],
    ["500", () => json(confirmBody("block", { error: "x" }), 500), {
      reason: "http_status",
      status: 500,
      call: "confirm",
    }],
    ["429", () => json({ error: "rate_limited" }, 429), { reason: "http_status", status: 429, call: "confirm" }],
    ["network", () => Promise.reject(new TypeError("refused")), { reason: "network", call: "confirm" }],
    ["partial", () => json({ action: "block" }), { reason: "bad_response", status: 200, call: "confirm" }],
    ["not json", () => new Response("<html>", { status: 200 }), {
      reason: "bad_response",
      status: 200,
      call: "confirm",
    }],
    // No second look for this address: the first answer stands, and that is not a failure.
    ["404 unknown_check", () => json({ error: "unknown_check", message: "x" }, 404), null],
    ["410 check_expired", () => json({ error: "check_expired", message: "x" }, 410), null],
    // A 404 that is not unknown_check (an older server without /v1/confirm) is reported.
    ["404 not_found", () => json({ error: "not_found" }, 404), { reason: "http_status", status: 404, call: "confirm" }],
    [
      "internal_error",
      () => json({ ...confirmBody("allow"), check_id: null, first: null, error: "internal_error" }),
      null,
    ],
  ];
  for (const [name, handler, expected] of cases) {
    const errors: CheckError[] = [];
    const app = makeAuth({ secondLook: true, timeoutMs: 50, onError: (e) => errors.push(e) });
    const m = mockApi(handler);
    try {
      const email = `user-${name.replaceAll(" ", "-")}@example.com`;
      const res = await signUpAndConfirm(app, email);
      assert(res.status === 302 || res.status === 200, `${name}: status ${res.status}`);
      assert(verified(app.db, email), name);
      assertEquals(m.confirms().length, 1, name);
      assertEquals(errors, expected ? [expected] : [], name);
    } finally {
      m.restore();
    }
  }
});

Deno.test("secondLook: a hanging API holds the link click at most CONFIRM_TIMEOUT_MS", async () => {
  const errors: CheckError[] = [];
  const app = makeAuth({ secondLook: true, onError: (e) => errors.push(e) });
  const m = mockApi((c, s) => hang(c, s));
  try {
    const started = performance.now();
    await signUpAndConfirm(app, "slow@example.com");
    const took = performance.now() - started;
    assert(took >= CONFIRM_TIMEOUT_MS - 50 && took < CONFIRM_TIMEOUT_MS + 1000, `took ${took} ms`);
    assert(verified(app.db, "slow@example.com"));
    assertEquals(errors, [{ reason: "timeout", call: "confirm" }]);
  } finally {
    m.restore();
  }
});

Deno.test("secondLook off (the default): nothing is sent to /v1/confirm", async () => {
  for (const opts of [{}, { secondLook: false }]) {
    const app = makeAuth(opts);
    const m = mockApi(() => json(confirmBody("block")));
    try {
      await signUpAndConfirm(app, "nobody@example.com");
      assert(verified(app.db, "nobody@example.com"));
      assertEquals(m.calls.map((c) => new URL(c.url).pathname), ["/v1/check"]);
    } finally {
      m.restore();
    }
  }
});

Deno.test("C2 secondLook: a mail scanner's click first, then the person's own click: both are reported", async () => {
  const app = makeAuth({ secondLook: true });
  const m = mockApi((call) =>
    json(call.body.user_agent === UA ? confirmBody("allow") : confirmBody("allow", { second_look: false }))
  );
  try {
    const scanner = { "user-agent": "Microsoft Office Existence Discovery", "x-real-ip": "40.94.0.1" };
    await signUpAndConfirm(app, "person@example.com", scanner);
    assert(verified(app.db, "person@example.com"));
    // The address is verified now, so Better Auth answers the person's click without updating the user.
    const again = await app.auth.handler(
      new Request(app.links.at(-1)!, { headers: { "user-agent": UA, "x-real-ip": "198.51.100.4" } }),
    );
    await again.body?.cancel();
    assert(again.status === 302 || again.status === 200, `status ${again.status}`);
    assertEquals(m.confirms().map((c) => c.body), [
      { via: "link", email: "person@example.com", ip: "40.94.0.1", user_agent: scanner["user-agent"] },
      { via: "link", email: "person@example.com", ip: "198.51.100.4", user_agent: UA },
    ]);
  } finally {
    m.restore();
  }
});

/** An HS256 JWT like Better Auth's verification token, signed with `secret`. */
async function signToken(payload: Record<string, unknown>, secret = SECRET): Promise<string> {
  const b64 = (bytes: Uint8Array) =>
    btoa(String.fromCharCode(...bytes)).replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
  const part = (o: unknown) => b64(new TextEncoder().encode(JSON.stringify(o)));
  const unsigned = `${part({ alg: "HS256" })}.${part(payload)}`;
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return `${unsigned}.${
    b64(new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(unsigned))))
  }`;
}

Deno.test("secondLook: forged, expired and email-change tokens, and server code without headers, send nothing", async () => {
  const app = makeAuth({ secondLook: true });
  const m = mockApi(() => json(confirmBody("allow")));
  const headers = { "user-agent": UA, "x-real-ip": "198.51.100.4" };
  try {
    await signUpAndConfirm(app, "known@example.com", headers);
    assertEquals(m.confirms().length, 1);
    const exp = Math.floor(Date.now() / 1000) + 3600;
    // A token made with the app's secret is one Better Auth accepts too: reported (the address is verified).
    const crafted = await signToken({ email: "known@example.com", exp });
    const ok = await app.auth.handler(new Request(`${BASE}/api/auth/verify-email?token=${crafted}`, { headers }));
    await ok.body?.cancel();
    assertEquals(m.confirms().length, 2);
    // Server code verifying a valid token without request headers: no IP or User-Agent to send.
    const valid = new URL(app.links.at(-1)!).searchParams.get("token")!;
    await app.auth.api.verifyEmail({ query: { token: valid } });
    assertEquals(m.confirms().length, 2);
    // The same token with headers is reported (an address already verified still counts).
    await app.auth.api.verifyEmail({ query: { token: valid }, headers: new Headers(headers) });
    assertEquals(m.confirms().length, 3);
    const tokens = [
      await signToken({ email: "known@example.com", exp }, "not-the-secret-not-the-secret-not-the"),
      await signToken({ email: "known@example.com", exp: Math.floor(Date.now() / 1000) - 10 }),
      await signToken({ email: "known@example.com" }),
      await signToken({ email: "known@example.com", updateTo: "new@example.com", exp }),
      "not-a-token",
    ];
    for (const token of tokens) {
      const res = await app.auth.handler(new Request(`${BASE}/api/auth/verify-email?token=${token}`, { headers }));
      await res.body?.cancel();
    }
    // The email-change token above moved the user to new@example.com (Better Auth's own change), unreported.
    assertEquals(app.db.user.map((u) => u.email), ["new@example.com"]);
    assertEquals(m.confirms().length, 3);
    // Off: the plugin adds no after hook at all.
    assertEquals(signupBouncer({ apiKey: "sb_live_test" }).hooks?.after, undefined);
  } finally {
    m.restore();
  }
});

Deno.test("C3 auth.api.verifyEmail with both mechanisms and getIp: one report, at most CONFIRM_TIMEOUT_MS", async () => {
  const getIp = () => "198.51.100.9";
  const opts = { apiKey: "sb_live_test", baseUrl: "https://sb.test", getIp, onError: () => {} };
  const app = makeAuth({ ...opts, secondLook: true }, {
    beforeEmailVerification: signupBouncerConfirm({ ...opts, via: "button" }),
  });
  const m = mockApi((c, s) => hang(c, s));
  try {
    const signedUp = await app.auth.handler(
      new Request(`${BASE}/api/auth/sign-up/email`, {
        method: "POST",
        headers: { "content-type": "application/json", origin: BASE },
        body: JSON.stringify({ email: "server@example.com", password: "correct-horse-battery", name: "Test" }),
      }),
    );
    await signedUp.body?.cancel();
    for (let i = 0; i < 50 && app.links.length === 0; i++) await new Promise((r) => setTimeout(r, 10));
    const token = new URL(app.links.at(-1)!).searchParams.get("token")!;
    const started = performance.now();
    await app.auth.api.verifyEmail({ query: { token }, headers: new Headers({ "user-agent": UA }) });
    const took = performance.now() - started;
    assert(took < CONFIRM_TIMEOUT_MS + 500, `took ${took} ms`);
    assert(verified(app.db, "server@example.com"));
    assertEquals(m.confirms().map((c) => c.body.via), ["button"]);
  } finally {
    m.restore();
  }
});

Deno.test("signupBouncerConfirm (button): a second-look block refuses with 403 and leaves the address unverified", async () => {
  const opts = { apiKey: "sb_live_test", baseUrl: "https://sb.test", ipHeader: "x-real-ip" };
  const app = makeAuth({ secondLook: true }, {
    beforeEmailVerification: signupBouncerConfirm({ ...opts, via: "button" }),
  });
  const m = mockApi(() => json(confirmBody("block")));
  try {
    const res = await signUpAndConfirm(app, "farm@example.com");
    assertEquals(res.status, 403);
    assertEquals(verified(app.db, "farm@example.com"), false);
    // Reported once, by signupBouncerConfirm: the plugin's secondLook report skips the same request.
    assertEquals(m.confirms().map((c) => c.body), [
      { via: "button", email: "farm@example.com", ip: "198.51.100.4", user_agent: UA },
    ]);
  } finally {
    m.restore();
  }
});

Deno.test("signupBouncerConfirm: the refusal body carries SIGNUP_BLOCKED and the dashboard's message", async () => {
  const opts = { apiKey: "sb_live_test", baseUrl: "https://sb.test" };
  const m = mockApi(() => json(confirmBody("block")));
  try {
    for (
      const [extra, message] of [
        [{}, BLOCK_MESSAGE],
        [{ blockMessage: "Not this time." }, "Not this time."],
      ] as [Partial<SignupBouncerOptions>, string][]
    ) {
      const hook = signupBouncerConfirm({ ...opts, ...extra, via: "button" });
      const request = new Request(`${BASE}/api/auth/verify-email?token=t`, { headers: { "user-agent": UA } });
      let caught: { name?: string; statusCode?: number; body?: { code?: string; message?: string } } | undefined;
      try {
        await hook({ email: "farm@example.com" }, request);
      } catch (e) {
        caught = e as typeof caught;
      }
      assertEquals(caught?.name, "APIError");
      assertEquals(caught?.statusCode, 403);
      assertEquals([caught?.body?.code, caught?.body?.message], ["SIGNUP_BLOCKED", message]);
    }
  } finally {
    m.restore();
  }
});

Deno.test("signupBouncerConfirm: allow, shadow mode, no second look and failures let the confirmation through", async () => {
  const cases: [string, ConfirmHandler][] = [
    ["allow", () => json(confirmBody("allow"))],
    ["shadow", () => json(confirmBody("block", { action: "allow", mode: "shadow" }))],
    ["first stands", () => json(confirmBody("block", { second_look: false }))],
    ["error answer", () => json(confirmBody("block", { error: "internal_error" }))],
    ["timeout", (c, s) => hang(c, s)],
    ["503", () => json({ error: "x" }, 503)],
    ["404", () => json({ error: "unknown_check" }, 404)],
  ];
  for (const [name, handler] of cases) {
    const opts = { apiKey: "sb_live_test", baseUrl: "https://sb.test", timeoutMs: 50, onError: () => {} };
    const app = makeAuth({}, { beforeEmailVerification: signupBouncerConfirm({ ...opts, via: "button" }) });
    const m = mockApi(handler);
    try {
      const email = `user-${name.replaceAll(" ", "-")}@example.com`;
      const res = await signUpAndConfirm(app, email);
      assert(res.status === 302 || res.status === 200, `${name}: status ${res.status}`);
      assert(verified(app.db, email), name);
      assertEquals(m.confirms().length, 1, name);
    } finally {
      m.restore();
    }
  }
});

Deno.test("signupBouncerConfirm: email OTP sends via code; an email change through OTP sends nothing", async () => {
  const m = mockApi(() => json(confirmBody("allow")));
  try {
    const hook = signupBouncerConfirm({ apiKey: "sb_live_test", baseUrl: "https://sb.test", via: "code" });
    const at = (path: string) =>
      new Request(`${BASE}/api/auth${path}`, { method: "POST", headers: { "user-agent": UA } });
    await hook({ email: "otp@example.com" }, at("/email-otp/verify-email"));
    await hook({ email: "otp@example.com" }, at("/email-otp/change-email"));
    // No request (server code) and no address: nothing to report.
    await hook({ email: "otp@example.com" });
    await hook({ email: "" }, at("/email-otp/verify-email"));
    assertEquals(m.confirms().map((c) => c.body), [{ via: "code", email: "otp@example.com", user_agent: UA }]);
  } finally {
    m.restore();
  }
});

/** A Better Auth app with the email OTP plugin; the codes it sends are kept by type. */
function makeOtpAuth(
  beforeEmailVerification: ((user: { email: string }, request?: Request) => Promise<void>) | undefined,
  extra: {
    requireEmailVerification?: boolean;
    skipTrailingSlashes?: boolean;
    secondLook?: boolean;
    adapter?: (db: Db) => ReturnType<typeof memoryAdapter>;
  } = {},
) {
  const db = { user: [], session: [], account: [], verification: [] } as Db;
  const otps: Record<string, string> = {};
  const auth = betterAuth({
    baseURL: BASE,
    secret: SECRET,
    database: (extra.adapter ?? memoryAdapter)(db),
    emailAndPassword: { enabled: true, requireEmailVerification: extra.requireEmailVerification ?? true },
    emailVerification: beforeEmailVerification ? { beforeEmailVerification } : {},
    advanced: { skipTrailingSlashes: extra.skipTrailingSlashes ?? false },
    rateLimit: { enabled: false },
    telemetry: { enabled: false },
    plugins: [
      emailOTP({
        changeEmail: { enabled: true },
        sendVerificationOTP: ({ otp, type }) => {
          otps[type] = otp;
          return Promise.resolve();
        },
      }),
      signupBouncer({ apiKey: "sb_live_test", baseUrl: "https://sb.test", secondLook: extra.secondLook }),
    ],
  });
  const post = async (path: string, body: Record<string, unknown>, cookie = "") => {
    const res = await auth.handler(
      new Request(`${BASE}/api/auth${path}`, {
        method: "POST",
        headers: { "content-type": "application/json", origin: BASE, "user-agent": UA, ...(cookie ? { cookie } : {}) },
        body: JSON.stringify(body),
      }),
    );
    const cookies = res.headers.getSetCookie().map((c) => c.split(";")[0]).join("; ");
    await res.body?.cancel();
    return { status: res.status, cookies };
  };
  const signUp = (email: string) => post("/sign-up/email", { email, password: "correct-horse-battery", name: "T" });
  return { auth, db, otps, post, signUp };
}

const CODE_OPTS = { apiKey: "sb_live_test", baseUrl: "https://sb.test", onError: () => {} };

Deno.test("C1 signupBouncerConfirm: a refused person cannot verify through email OTP sign-in or password reset", async () => {
  const app = makeOtpAuth(signupBouncerConfirm({ ...CODE_OPTS, via: "code" }));
  const m = mockApi(() => json(confirmBody("block")));
  const email = "farm@example.com";
  try {
    assertEquals((await app.signUp(email)).status, 200);
    await app.post("/email-otp/send-verification-otp", { email, type: "email-verification" });
    assertEquals(
      (await app.post("/email-otp/verify-email", { email, otp: app.otps["email-verification"] })).status,
      403,
    );
    // Email OTP sign-in verifies an unverified user without calling beforeEmailVerification.
    await app.post("/email-otp/send-verification-otp", { email, type: "sign-in" });
    const signIn = await app.post("/sign-in/email-otp", { email: "Farm@Example.com", otp: app.otps["sign-in"] });
    assertEquals(signIn.status, 403);
    assertEquals(signIn.cookies.includes("session_token"), false);
    // So does password reset by email OTP.
    await app.post("/email-otp/send-verification-otp", { email, type: "forget-password" });
    const reset = await app.post("/email-otp/reset-password", {
      email,
      otp: app.otps["forget-password"],
      password: "another-horse-battery",
    });
    assertEquals(reset.status, 403);
    assertEquals(verified(app.db, email), false);
    assertEquals(app.db.session.length, 0);
    assertEquals(m.confirms().map((c) => [c.body.via, c.body.email]), [
      ["code", email],
      ["code", email],
      ["code", email],
    ]);
  } finally {
    m.restore();
  }
});

Deno.test("C1 email OTP sign-in: allowed when the second look allows; nothing sent without signupBouncerConfirm", async () => {
  for (const withHook of [true, false]) {
    const app = makeOtpAuth(withHook ? signupBouncerConfirm({ ...CODE_OPTS, via: "code" }) : undefined, {
      secondLook: true,
    });
    const m = mockApi(() => json(confirmBody("allow")));
    const email = `otp-${withHook}@example.com`;
    try {
      assertEquals((await app.signUp(email)).status, 200);
      await app.post("/email-otp/send-verification-otp", { email, type: "sign-in" });
      const signIn = await app.post("/sign-in/email-otp", { email, otp: app.otps["sign-in"] });
      assertEquals(signIn.status, 200, `withHook: ${withHook}`);
      assert(verified(app.db, email));
      assertEquals(m.confirms().map((c) => c.body.via), withHook ? ["code"] : [], `withHook: ${withHook}`);
    } finally {
      m.restore();
    }
  }
});

Deno.test("S1 signupBouncerConfirm: an email change through email OTP sends nothing, with a trailing slash too", async () => {
  for (const path of ["/email-otp/change-email", "/email-otp/change-email/"]) {
    const app = makeOtpAuth(signupBouncerConfirm({ ...CODE_OPTS, via: "code" }), {
      requireEmailVerification: false,
      skipTrailingSlashes: true,
    });
    const m = mockApi(() => json(confirmBody("block")));
    try {
      const { cookies } = await app.signUp("old@example.com");
      assert(cookies.includes("session_token"), "signed in after sign-up");
      assertEquals(
        (await app.post("/email-otp/request-email-change", { newEmail: "new@example.com" }, cookies)).status,
        200,
      );
      const changed = await app.post(path, { newEmail: "new@example.com", otp: app.otps["change-email"] }, cookies);
      assertEquals(changed.status, 200, path);
      assertEquals(app.db.user.map((u) => u.email), ["new@example.com"], path);
      assertEquals(m.confirms().length, 0, path);
    } finally {
      m.restore();
    }
  }
});

/**
 * The memory adapter, with what a real database does that it does not: a verification row's id is unique (Better
 * Auth's account clean-up lock relies on it), and user lookups can be made to stall.
 */
function realisticAdapter(control: { stallUsers?: boolean } = {}) {
  return (db: Db) => {
    const base = memoryAdapter(db) as unknown as (options: unknown) => Record<string, unknown>;
    return ((options: unknown) => {
      const adapter = base(options);
      const create = adapter.create as (args: { model: string; data: { id?: unknown } }) => Promise<unknown>;
      const findOne = adapter.findOne as (args: { model: string }) => Promise<unknown>;
      adapter.create = (args: { model: string; data: { id?: unknown } }) => {
        if (args.model === "verification" && db.verification.some((r) => r.id === args.data.id)) {
          return Promise.reject(new Error("UNIQUE constraint failed: verification.id"));
        }
        return create(args);
      };
      adapter.findOne = (args: { model: string }) =>
        control.stallUsers && args.model === "user" ? new Promise(() => {}) : findOne(args);
      return adapter;
    }) as unknown as ReturnType<typeof memoryAdapter>;
  };
}

/** Signs up without clicking, and returns the token from the emailed link. */
async function signUpForToken(app: ReturnType<typeof makeAuth>, email: string): Promise<string> {
  const signedUp = await app.auth.handler(
    new Request(`${BASE}/api/auth/sign-up/email`, {
      method: "POST",
      headers: { "content-type": "application/json", origin: BASE },
      body: JSON.stringify({ email, password: "correct-horse-battery", name: "Test" }),
    }),
  );
  await signedUp.body?.cancel();
  for (let i = 0; i < 50 && app.links.length === 0; i++) await new Promise((r) => setTimeout(r, 10));
  return new URL(app.links.at(-1)!).searchParams.get("token")!;
}

Deno.test("A1 server code confirming through auth.api: the forwarded headers are checked and a block refuses", async () => {
  const opts = { apiKey: "sb_live_test", baseUrl: "https://sb.test", ipHeader: "x-real-ip" };
  for (const secondLook of [false, true]) {
    const app = makeAuth({ ...opts, secondLook }, {
      beforeEmailVerification: signupBouncerConfirm({ ...opts, via: "button" }),
    });
    const m = mockApi(() => json(confirmBody("block")));
    try {
      const token = await signUpForToken(app, "farm@example.com");
      let status: number | undefined;
      try {
        await app.auth.api.verifyEmail({
          query: { token },
          headers: new Headers({ "user-agent": UA, "x-real-ip": "198.51.100.4" }),
        });
      } catch (e) {
        status = (e as { statusCode?: number }).statusCode;
      }
      assertEquals(status, 403, `secondLook: ${secondLook}`);
      assertEquals(verified(app.db, "farm@example.com"), false);
      assertEquals(m.confirms().map((c) => c.body), [
        { via: "button", email: "farm@example.com", ip: "198.51.100.4", user_agent: UA },
      ]);
    } finally {
      m.restore();
    }
  }
});

Deno.test("A1 server code confirming an email OTP through auth.api is checked too", async () => {
  const app = makeOtpAuth(signupBouncerConfirm({ ...CODE_OPTS, via: "code" }));
  const m = mockApi(() => json(confirmBody("block")));
  const email = "farm@example.com";
  try {
    await app.signUp(email);
    await app.post("/email-otp/send-verification-otp", { email, type: "email-verification" });
    let status: number | undefined;
    try {
      await app.auth.api.verifyEmailOTP({
        body: { email, otp: app.otps["email-verification"] },
        headers: new Headers({ "user-agent": UA }),
      });
    } catch (e) {
      status = (e as { statusCode?: number }).statusCode;
    }
    assertEquals(status, 403);
    assertEquals(verified(app.db, email), false);
    assertEquals(m.confirms().map((c) => [c.body.via, c.body.user_agent]), [["code", UA]]);
  } finally {
    m.restore();
  }
});

Deno.test("A2 two email OTP sign-ins at once: the second cannot get a session after the first is refused", async () => {
  const app = makeOtpAuth(signupBouncerConfirm({ ...CODE_OPTS, via: "code" }), { adapter: realisticAdapter() });
  let release = () => {};
  const firstHeld = new Promise<void>((r) => (release = r));
  let calls = 0;
  const m = mockApi(async () => {
    // The first confirmation is still being checked while the second sign-in arrives.
    if (calls++ === 0) await firstHeld;
    return json(confirmBody("block"));
  });
  const email = "farm@example.com";
  try {
    await app.signUp(email);
    await app.post("/email-otp/send-verification-otp", { email, type: "sign-in" });
    const first = app.post("/sign-in/email-otp", { email, otp: app.otps["sign-in"] });
    for (let i = 0; i < 100 && m.confirms().length === 0; i++) await new Promise((r) => setTimeout(r, 5));
    assertEquals(m.confirms().length, 1);
    await app.post("/email-otp/send-verification-otp", { email, type: "sign-in" });
    const second = app.post("/sign-in/email-otp", { email, otp: app.otps["sign-in"] });
    await new Promise((r) => setTimeout(r, 100)); // the second is now waiting for the first one's clean-up lock
    release();
    const [a, b] = await Promise.all([first, second]);
    assertEquals([a.status, b.status], [403, 403]);
    assertEquals(b.cookies.includes("session_token"), false);
    assertEquals(app.db.session.length, 0);
    assertEquals(verified(app.db, email), false);
  } finally {
    release();
    m.restore();
  }
});

Deno.test("A3 a stalled user lookup cannot hold a verified link click past CONFIRM_TIMEOUT_MS", async () => {
  const control = { stallUsers: false };
  const db = { user: [], session: [], account: [], verification: [] } as Db;
  const links: string[] = [];
  const auth = betterAuth({
    baseURL: BASE,
    secret: SECRET,
    database: realisticAdapter(control)(db),
    emailAndPassword: { enabled: true, requireEmailVerification: true },
    emailVerification: {
      sendOnSignUp: true,
      sendVerificationEmail: ({ url }) => void links.push(url) as unknown as Promise<void>,
    },
    // Once the address is verified, every later user lookup stalls: only the plugin's own lookup is left.
    databaseHooks: { user: { update: { after: () => Promise.resolve(void (control.stallUsers = true)) } } },
    rateLimit: { enabled: false },
    telemetry: { enabled: false },
    plugins: [
      signupBouncer({ apiKey: "sb_live_test", baseUrl: "https://sb.test", ipHeader: "x-real-ip", secondLook: true }),
    ],
  });
  const m = mockApi(() => json(confirmBody("allow")));
  try {
    const signedUp = await auth.handler(
      new Request(`${BASE}/api/auth/sign-up/email`, {
        method: "POST",
        headers: { "content-type": "application/json", origin: BASE },
        body: JSON.stringify({ email: "slow@example.com", password: "correct-horse-battery", name: "Test" }),
      }),
    );
    await signedUp.body?.cancel();
    for (let i = 0; i < 50 && links.length === 0; i++) await new Promise((r) => setTimeout(r, 10));
    const started = performance.now();
    const res = await auth.handler(new Request(links.at(-1)!, { headers: { "user-agent": UA } }));
    await res.body?.cancel();
    const took = performance.now() - started;
    assert(res.status === 302 || res.status === 200, `status ${res.status}`);
    assert(took < CONFIRM_TIMEOUT_MS + 500, `took ${took} ms`);
    assertEquals(db.user[0]?.emailVerified, true);
    assertEquals(m.confirms().length, 0);
  } finally {
    m.restore();
  }
});

Deno.test("A4 one app's signupBouncerConfirm never hides another app's secondLook report", async () => {
  const a = makeAuth({ apiKey: "sb_live_a" }, {
    beforeEmailVerification: signupBouncerConfirm({ apiKey: "sb_live_a", baseUrl: "https://sb.test", via: "button" }),
  });
  const b = makeAuth({ apiKey: "sb_live_b", secondLook: true });
  const m = mockApi(() => json(confirmBody("allow")));
  try {
    await signUpAndConfirm(a, "same@example.com");
    await signUpAndConfirm(b, "same@example.com");
    assertEquals(m.confirms().map((c) => [c.headers.get("authorization"), c.body.via]), [
      ["Bearer sb_live_a", "button"],
      ["Bearer sb_live_b", "link"],
    ]);
  } finally {
    m.restore();
  }
});

Deno.test("confirmSignup: only a complete enforce-mode second-look block on button or code refuses", async () => {
  const m = mockApi(() => json(confirmBody("block")));
  const opts = { apiKey: "sb_live_test", baseUrl: "https://sb.test", onError: () => {} };
  try {
    const input = { email: "a@example.com", userAgent: UA };
    assertEquals((await confirmSignup(opts, { ...input, via: "button" })).action, "block");
    assertEquals((await confirmSignup(opts, { ...input, via: "code" })).action, "block");
    // Link, the default, and anything else: record only.
    assertEquals((await confirmSignup(opts, { ...input, via: "link" })).action, "allow");
    assertEquals((await confirmSignup(opts, input)).action, "allow");
    assertEquals((await confirmSignup(opts, { ...input, via: "webhook" as "link" })).action, "allow");
    assertEquals(m.calls.map((c) => c.body.via), ["button", "code", "link", "link", "link"]);
  } finally {
    m.restore();
  }

  // Partial, mistyped or inconsistent block answers never refuse a button press.
  const full = confirmBody("block");
  const bad: unknown[] = [
    { action: "block" },
    null,
    [],
    "block",
    ...Object.keys(full).filter((k) => k !== "block_message").map((k) => {
      const copy = { ...full };
      delete copy[k];
      return copy;
    }),
    { ...full, verdict: "allow" },
    { ...full, verdict: "challenge", action: "challenge" },
    { ...full, mode: "shadow" },
    { ...full, second_look: false },
    { ...full, second_look: "true" },
    { ...full, replayed: null },
    { ...full, check_id: null },
    { ...full, error: "internal_error" },
    { ...full, score: "85" },
    { ...full, reasons: [{ code: "x" }] },
    { ...full, shadow: [null] },
    { ...full, first: { verdict: "nope", score: 1 } },
  ];
  for (const body of bad) {
    const m2 = mockFetch(() => json(body));
    try {
      const result = await confirmSignup(opts, { email: "a@example.com", userAgent: UA, via: "button" });
      assertEquals(result.action, "allow", JSON.stringify(body));
    } finally {
      m2.restore();
    }
  }
});

Deno.test("confirmSignup: sends check_id and app; refuses to send without an address or a request source", async () => {
  const errors: CheckError[] = [];
  const m = mockApi(() => json(confirmBody("allow", { replayed: true })));
  const opts = {
    apiKey: " sb_live_test ",
    baseUrl: "https://sb.test/",
    app: "app_x",
    onError: (e: CheckError) => errors.push(e),
  };
  try {
    const ok = await confirmSignup(opts, { checkId: CHECK_ID, ip: "198.51.100.4", userAgent: "u".repeat(600) });
    assert(ok.ok && ok.response.replayed === true);
    assertEquals(m.calls[0].url, "https://sb.test/v1/confirm");
    assertEquals(m.calls[0].headers.get("authorization"), "Bearer sb_live_test");
    assertEquals(m.calls[0].body, {
      via: "link",
      check_id: CHECK_ID,
      ip: "198.51.100.4",
      user_agent: "u".repeat(512),
      app: "app_x",
    });
    await confirmSignup(opts, { ip: "198.51.100.4" });
    await confirmSignup(opts, { email: "a@example.com" });
    await confirmSignup({ ...opts, apiKey: "" }, { email: "a@example.com", userAgent: UA });
    await confirmSignup({ ...opts, apiKey: "sb_live\nx" }, { email: "a@example.com", userAgent: UA });
    assertEquals(m.calls.length, 1);
    assertEquals(errors, [
      { reason: "no_input", call: "confirm" },
      { reason: "no_input", call: "confirm" },
      { reason: "missing_api_key", call: "confirm" },
      { reason: "malformed_api_key", call: "confirm" },
    ]);
  } finally {
    m.restore();
  }
});

Deno.test("confirmBlockMessage: the answer's message, or the default", () => {
  const response = confirmBody("block") as never;
  assertEquals(confirmBlockMessage({ ok: true, action: "block", response }), BLOCK_MESSAGE);
  const noMessage = confirmBody("block", { block_message: " " }) as never;
  assertEquals(confirmBlockMessage({ ok: true, action: "block", response: noMessage }), DEFAULT_CONFIRM_MESSAGE);
  assertEquals(
    confirmBlockMessage({ ok: false, action: "allow", error: { reason: "timeout", call: "confirm" } }),
    DEFAULT_CONFIRM_MESSAGE,
  );
});

Deno.test("the default onError warns about a failed confirmation report in one line, without the key or the email", async () => {
  const lines: string[] = [];
  const warn = console.warn;
  console.warn = (...args: unknown[]) => void lines.push(args.map(String).join(" "));
  const m = mockApi(() => json({ error: "invalid_api_key" }, 401));
  try {
    await confirmSignup({ apiKey: "sb_live_secret", baseUrl: "https://sb.test" }, {
      email: "private@example.com",
      userAgent: UA,
    });
  } finally {
    console.warn = warn;
    m.restore();
  }
  assertEquals(lines, [
    "[signupbouncer] confirmation report failed (http_status 401), confirmation allowed. Check the signupbouncer API " +
    "key in your config.",
  ]);
});
