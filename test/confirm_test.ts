// finaldynamics/signupbouncer#248: the second look at email confirmation (POST /v1/confirm). With `secondLook: true`
// the plugin reports each click on Better Auth's verification link, record only: it never refuses one, and every failure
// lets the confirmation through. signupBouncerConfirm, in beforeEmailVerification, may refuse a button press or a typed
// code. Runs a real Better Auth instance (memory adapter) with only the SignupBouncer API mocked.

import { assert, assertEquals } from "@std/assert";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
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

function makeAuth(
  opts: Partial<SignupBouncerOptions> = {},
  verification: { beforeEmailVerification?: (user: { email: string }, request?: Request) => Promise<void> } = {},
) {
  const db = { user: [], session: [], account: [], verification: [] } as Record<string, Record<string, unknown>[]>;
  const links: string[] = [];
  const auth = betterAuth({
    baseURL: BASE,
    secret: "test-secret-test-secret-test-secret-0123",
    database: memoryAdapter(db),
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

Deno.test("secondLook: no request headers (server code verifying) and an email change send nothing", async () => {
  const plugin = signupBouncer({ apiKey: "sb_live_test", baseUrl: "https://sb.test", secondLook: true });
  // deno-lint-ignore no-explicit-any
  const hooks = (await (plugin.init as any)({})).options.databaseHooks.user.update;
  const m = mockApi(() => json(confirmBody("allow")));
  try {
    const user = { email: "a@example.com", emailVerified: true };
    // An email change confirmed on /verify-email sets the new address with emailVerified.
    let ctx = { path: "/verify-email", headers: new Headers({ "user-agent": UA }) };
    await hooks.before({ email: "new@example.com", emailVerified: true }, ctx);
    await hooks.after({ ...user, email: "new@example.com" }, ctx);
    // Another route, or an update that does not verify.
    ctx = { path: "/update-user", headers: new Headers({ "user-agent": UA }) };
    await hooks.before({ emailVerified: true }, ctx);
    await hooks.after(user, ctx);
    ctx = { path: "/verify-email", headers: new Headers({ "user-agent": UA }) };
    await hooks.before({ name: "x" }, ctx);
    await hooks.after(user, ctx);
    // Neither an IP nor a User-Agent: the API would refuse the report.
    ctx = { path: "/verify-email", headers: new Headers() };
    await hooks.before({ emailVerified: true }, ctx);
    await hooks.after(user, ctx);
    // No endpoint context at all.
    await hooks.before({ emailVerified: true }, null);
    await hooks.after(user, null);
    assertEquals(m.confirms().length, 0);

    // The same hooks do report a real verification.
    ctx = { path: "/verify-email", headers: new Headers({ "user-agent": UA }) };
    await hooks.before({ emailVerified: true }, ctx);
    await hooks.after(user, ctx);
    assertEquals(m.confirms().map((c) => c.body), [{ via: "link", email: "a@example.com", user_agent: UA }]);
    // The plugin adds no update hooks without secondLook.
    const off = signupBouncer({ apiKey: "sb_live_test" });
    // deno-lint-ignore no-explicit-any
    assertEquals((await (off.init as any)({})).options.databaseHooks.user.update, undefined);
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
