// Unit tests for checkSignup, clientIp and shouldBlock, with fetch mocked.

import { assert, assertEquals } from "@std/assert";
import {
  type CheckError,
  type CheckResponse,
  checkSignup,
  DEFAULT_TIMEOUT_MS,
  MAX_TIMEOUT_MS,
  shouldBlock,
} from "../mod.ts";
import { clientIp, isCompleteAnswer, normalizeIp } from "../internal.ts";
import { answer, answerBody, hang, json, mockFetch } from "./mock_fetch.ts";
import { FULL_BLOCK, MALFORMED_BLOCKS, VALID_BLOCKS } from "./responses.ts";

const opts = { apiKey: "sb_live_test", baseUrl: "https://api.example/" };

Deno.test("allow: posts email, ip and user agent with the bearer key", async () => {
  const m = mockFetch(() => answer("allow"));
  try {
    const r = await checkSignup({ ...opts, app: "app_1" }, { email: "a@b.com", ip: "203.0.113.7", userAgent: "UA" });
    assertEquals(r.ok, true);
    assertEquals(r.action, "allow");
    assertEquals(m.calls.length, 1);
    assertEquals(m.calls[0].url, "https://api.example/v1/check");
    assertEquals(m.calls[0].headers.get("authorization"), "Bearer sb_live_test");
    assertEquals(m.calls[0].body, { email: "a@b.com", ip: "203.0.113.7", user_agent: "UA", app: "app_1" });
  } finally {
    m.restore();
  }
});

Deno.test("block and challenge pass through as the action", async () => {
  for (const action of ["block", "challenge"] as const) {
    const m = mockFetch(() => answer(action));
    try {
      const r = await checkSignup(opts, { email: "a@b.com" });
      assertEquals(r.action, action);
    } finally {
      m.restore();
    }
  }
});

Deno.test("shadow mode: a complete shadow answer (verdict block, action allow) is accepted and not blocked", async () => {
  const m = mockFetch(() => answer("allow", "block", "shadow"));
  try {
    const errors: CheckError[] = [];
    const r = await checkSignup({ ...opts, onError: (e) => errors.push(e) }, { email: "x@mailinator.com" });
    assertEquals(r.ok, true);
    assertEquals(r.action, "allow");
    if (r.ok) {
      assertEquals(r.response.mode, "shadow");
      assertEquals(r.response.verdict, "block");
    }
    assertEquals(errors, []);
    assertEquals(shouldBlock(r, "block"), false);
  } finally {
    m.restore();
  }
});

Deno.test("shouldBlock maps challenge by setting", () => {
  const response = answerBody("challenge") as CheckResponse;
  const ch = { ok: true as const, action: "challenge" as const, response };
  assertEquals(shouldBlock(ch), false);
  assertEquals(shouldBlock(ch, "allow"), false);
  assertEquals(shouldBlock(ch, "block"), true);
  assertEquals(shouldBlock({ ok: true, action: "block", response: answerBody("block") as CheckResponse }), true);
});

Deno.test("missing IP: the body carries no ip field", async () => {
  const m = mockFetch(() => answer("allow"));
  try {
    await checkSignup(opts, { email: "a@b.com" });
    assertEquals(m.calls[0].body, { email: "a@b.com" });
  } finally {
    m.restore();
  }
});

async function failsOpen(handler: Parameters<typeof mockFetch>[0], timeoutMs = 1500): Promise<CheckError> {
  const errors: CheckError[] = [];
  const m = mockFetch(handler);
  try {
    const r = await checkSignup({ ...opts, timeoutMs, onError: (e) => errors.push(e) }, { email: "a@b.com" });
    assertEquals(r.ok, false);
    assertEquals(r.action, "allow");
    assertEquals(errors.length, 1);
    return errors[0];
  } finally {
    m.restore();
  }
}

Deno.test("timeout: allows after timeoutMs", async () => {
  const started = performance.now();
  const e = await failsOpen(hang, 50);
  assertEquals(e.reason, "timeout");
  assert(performance.now() - started < 1000);
});

Deno.test("timeout while reading the body: allows", async () => {
  const e = await failsOpen((_c, signal) => {
    const body = new ReadableStream({
      start(ctl) {
        ctl.enqueue(new TextEncoder().encode('{"action":'));
        signal?.addEventListener("abort", () => ctl.error(new DOMException("aborted", "AbortError")));
      },
    });
    return new Response(body, { status: 200 });
  }, 50);
  assertEquals(e.reason, "timeout");
});

Deno.test("500: allows", async () => {
  const e = await failsOpen(() => json({ error: "boom" }, 500));
  assertEquals(e.reason, "http_status");
  assertEquals(e.status, 500);
});

Deno.test("non-2xx whose body stream errors (reset after headers): allows", async () => {
  const e = await failsOpen(() =>
    new Response(new ReadableStream({ start: (ctl) => ctl.error(new TypeError("connection reset")) }), { status: 502 })
  );
  assertEquals(e.reason, "http_status");
  assertEquals(e.status, 502);
});

Deno.test("2xx whose body stream errors: allows", async () => {
  const e = await failsOpen(() =>
    new Response(new ReadableStream({ start: (ctl) => ctl.error(new TypeError("connection reset")) }), { status: 200 })
  );
  assertEquals(e.reason, "bad_response");
});

Deno.test("401 (bad key): allows", async () => {
  const e = await failsOpen(() => json({ error: "invalid_api_key" }, 401));
  assertEquals(e.status, 401);
});

Deno.test("bad JSON: allows", async () => {
  const e = await failsOpen(() => new Response("<html>gateway</html>", { status: 200 }));
  assertEquals(e.reason, "bad_response");
});

Deno.test("JSON without a valid action: allows", async () => {
  for (const body of [{ verdict: "block" }, { action: "deny" }, null, [1]]) {
    const e = await failsOpen(() => json(body));
    assertEquals(e.reason, "bad_response");
  }
});

Deno.test("network error: allows", async () => {
  const e = await failsOpen(() => Promise.reject(new TypeError("connection refused")));
  assertEquals(e.reason, "network");
  assertEquals(Object.keys(e).sort(), ["reason"]); // no exception attached: it could quote the key
});

Deno.test("missing api key: allows without calling the API", async () => {
  const m = mockFetch(() => answer("block"));
  try {
    let seen: CheckError | undefined;
    const r = await checkSignup({ apiKey: "", onError: (e) => (seen = e) }, { email: "a@b.com" });
    assertEquals(r.action, "allow");
    assertEquals(seen?.reason, "missing_api_key");
    assertEquals(m.calls.length, 0);
  } finally {
    m.restore();
  }
});

Deno.test("an onError that throws does not escape", async () => {
  const m = mockFetch(() => json({}, 503));
  try {
    const r = await checkSignup({
      ...opts,
      onError: () => {
        throw new Error("logger down");
      },
    }, { email: "a@b.com" });
    assertEquals(r.action, "allow");
  } finally {
    m.restore();
  }
});

Deno.test("clientIp: no header trusted by default", () => {
  const h = new Headers({
    "cf-connecting-ip": "198.51.100.1",
    "x-forwarded-for": "203.0.113.7",
    "x-real-ip": "1.2.3.4",
  });
  assertEquals(clientIp(h, undefined), undefined);
  assertEquals(clientIp(h, ""), undefined);
  assertEquals(clientIp(undefined, "x-real-ip"), undefined);
});

Deno.test("clientIp: reads only the configured header", () => {
  const h = (o: Record<string, string>) => new Headers(o);
  // A caller-supplied cf-connecting-ip is ignored when the host's header is x-real-ip.
  assertEquals(
    clientIp(h({ "cf-connecting-ip": "198.51.100.66", "x-real-ip": "198.51.100.2" }), "x-real-ip"),
    "198.51.100.2",
  );
  assertEquals(clientIp(h({ "cf-connecting-ip": "198.51.100.66" }), "x-real-ip"), undefined);
  assertEquals(clientIp(h({ "fly-client-ip": "203.0.113.7:5678" }), "fly-client-ip"), "203.0.113.7");
  assertEquals(clientIp(h({ "x-real-ip": "[2001:db8::1]:443" }), "x-real-ip"), "2001:db8::1");
  assertEquals(clientIp(h({ "x-real-ip": "unknown" }), "x-real-ip"), undefined);
  assertEquals(clientIp(h({}), "x-real-ip"), undefined);
});

Deno.test("clientIp: X-Forwarded-For uses the entry trustedProxies places from the right", () => {
  const h = new Headers({ "x-forwarded-for": "198.51.100.99, 203.0.113.7, 10.0.0.1" });
  assertEquals(clientIp(h, "x-forwarded-for"), "10.0.0.1"); // one proxy: the right-most entry
  assertEquals(clientIp(h, "x-forwarded-for", 2), "203.0.113.7");
  assertEquals(clientIp(h, "x-forwarded-for", 3), "198.51.100.99");
  assertEquals(clientIp(h, "x-forwarded-for", 4), undefined); // shorter than the trusted chain: trust none of it
  assertEquals(clientIp(h, "X-Forwarded-For", 0), "10.0.0.1"); // nonsense counts fall back to 1
  // The client's own first entry is never chosen by the default.
  assertEquals(clientIp(new Headers({ "x-forwarded-for": "6.6.6.6, 203.0.113.7" }), "x-forwarded-for"), "203.0.113.7");
});

// ---- regressions from earlier security reviews (#1 to #5) ----------------------------------------------------------

Deno.test("#1 only a complete /v1/check answer can block; partial or mistyped answers allow", async () => {
  for (const body of VALID_BLOCKS) {
    const m = mockFetch(() => json(body));
    try {
      const r = await checkSignup(opts, { email: "a@b.com" });
      assertEquals(r.action, "block", JSON.stringify(body));
      assertEquals(isCompleteAnswer(body), true);
    } finally {
      m.restore();
    }
  }
  assert(MALFORMED_BLOCKS.length > 60);
  for (const body of MALFORMED_BLOCKS) {
    const errors: CheckError[] = [];
    const m = mockFetch(() => json(body));
    try {
      const r = await checkSignup({ ...opts, onError: (e) => errors.push(e) }, { email: "a@b.com" });
      assertEquals(r.action, "allow", JSON.stringify(body));
      assertEquals(shouldBlock(r, "block"), false, JSON.stringify(body));
      assertEquals(errors, [{ reason: "bad_response", status: 200 }], JSON.stringify(body));
    } finally {
      m.restore();
    }
  }
});

Deno.test("#1 a challenge needs a complete answer too", async () => {
  const challenge = { ...FULL_BLOCK, action: "challenge", verdict: "challenge" };
  for (const [body, expected] of [[challenge, "challenge"], [{ action: "challenge" }, "allow"]] as const) {
    const m = mockFetch(() => json(body));
    try {
      const r = await checkSignup({ ...opts, onError: () => {} }, { email: "a@b.com" });
      assertEquals(r.action, expected);
      assertEquals(shouldBlock(r, "block"), expected === "challenge");
    } finally {
      m.restore();
    }
  }
});

Deno.test("#2 onError never carries exception or response text, and a malformed key is never sent", async () => {
  const canary = "sb_live_REVIEW_CANARY";
  const cases: [string, () => Response | Promise<Response>, CheckError["reason"]][] = [
    ["network", () => Promise.reject(new TypeError(`Invalid header value: "Bearer ${canary}"`)), "network"],
    ["bad json", () => new Response(`${canary} is not JSON`, { status: 200 }), "bad_response"],
    ["500 body", () => new Response(canary, { status: 500 }), "http_status"],
  ];
  for (const [name, handler, reason] of cases) {
    const errors: CheckError[] = [];
    const m = mockFetch(handler);
    try {
      await checkSignup({ ...opts, apiKey: canary, onError: (e) => errors.push(e) }, { email: "a@b.com" });
      assertEquals(errors.length, 1, name);
      assertEquals(errors[0].reason, reason, name);
      assertEquals(JSON.stringify(errors[0]).includes("CANARY"), false, name);
      assertEquals(Object.keys(errors[0]).every((k) => k === "reason" || k === "status"), true, name);
    } finally {
      m.restore();
    }
  }
  // A key with a newline pasted in: refused before fetch, whose header error would quote it.
  const errors: CheckError[] = [];
  const m = mockFetch(() => answer("block"));
  try {
    const r = await checkSignup({ ...opts, apiKey: `${canary}\nx`, onError: (e) => errors.push(e) }, {
      email: "a@b.com",
    });
    assertEquals(r.action, "allow");
    assertEquals(errors, [{ reason: "malformed_api_key" }]);
    assertEquals(m.calls.length, 0);
    // Surrounding whitespace (a trailing newline from `echo`) is trimmed, not refused.
    assertEquals((await checkSignup({ ...opts, apiKey: ` ${canary}\n` }, { email: "a@b.com" })).action, "block");
    assertEquals(m.calls[0].headers.get("authorization"), `Bearer ${canary}`);
  } finally {
    m.restore();
  }
});

Deno.test("#3 an async onError that rejects or never settles neither escapes nor delays the check", async () => {
  const m = mockFetch(() => json({}, 503));
  try {
    const rejecting = await checkSignup({
      ...opts,
      onError: async () => {
        await Promise.resolve();
        throw new Error("logging service unavailable");
      },
    }, { email: "a@b.com" });
    assertEquals(rejecting.action, "allow");
    const started = performance.now();
    const hanging = await checkSignup({ ...opts, onError: () => new Promise(() => {}) }, { email: "a@b.com" });
    assertEquals(hanging.action, "allow");
    assert(performance.now() - started < 500);
    const thenable = await checkSignup({
      ...opts,
      onError: () => ({
        then() {
          throw new Error("broken thenable");
        },
      }),
    }, { email: "a@b.com" });
    assertEquals(thenable.action, "allow");
    // Let the rejections settle inside this test: an unhandled one would fail it.
    await new Promise((r) => setTimeout(r, 20));
  } finally {
    m.restore();
  }
});

Deno.test("#5 README: hop counts need a fixed ingress path; single-header recipes come first", async () => {
  const readme = (await Deno.readTextFile(new URL("../README.md", import.meta.url))).replace(/\s+/g, " ");
  const single = readme.indexOf("One header, written by the proxy that faces the internet");
  const count = readme.indexOf("A hop count on `X-Forwarded-For`, only on a fixed path");
  assert(single > 0 && count > single);
  assert(readme.includes("unreachable except through it"));
  // The behaviour the README warns about: one bypassed hop lets the client's own entry through.
  const bypassed = new Headers({ "x-forwarded-for": "198.51.100.77, 203.0.113.4" });
  assertEquals(clientIp(bypassed, "x-forwarded-for", 2), "198.51.100.77");
});

Deno.test("normalizeIp", () => {
  assertEquals(normalizeIp(" 203.0.113.7 "), "203.0.113.7");
  assertEquals(normalizeIp("203.0.113.7:80"), "203.0.113.7");
  assertEquals(normalizeIp("<script>"), undefined);
  assertEquals(normalizeIp(undefined), undefined);
});

// ---- default warning and timeout bounds (added for the public package) --------------------------------------------

/** Captures console.warn for one call. */
async function captureWarn(run: () => Promise<unknown>): Promise<string[]> {
  const original = console.warn;
  const lines: string[] = [];
  console.warn = (...args: unknown[]) => void lines.push(args.map(String).join(" "));
  try {
    await run();
  } finally {
    console.warn = original;
  }
  return lines;
}

Deno.test("401 without onError: allows and warns once, with no key, email or response text", async () => {
  const key = "sb_live_SECRET_CANARY";
  const m = mockFetch(() => json({ error: "invalid_api_key", echo: key }, 401));
  try {
    let r: Awaited<ReturnType<typeof checkSignup>> | undefined;
    const lines = await captureWarn(async () => {
      r = await checkSignup({ ...opts, apiKey: key }, { email: "victim@example.com", ip: "203.0.113.7" });
    });
    assertEquals(r?.action, "allow");
    assertEquals(r?.ok, false);
    assertEquals(lines.length, 1);
    assertEquals(
      lines[0],
      "[signupbouncer] check failed (http_status 401), sign-up allowed. Check the signupbouncer API key in your config.",
    );
    for (const secret of ["SECRET_CANARY", "victim", "example.com", "203.0.113", "invalid_api_key"]) {
      assertEquals(lines[0].includes(secret), false, secret);
    }
  } finally {
    m.restore();
  }
});

Deno.test("default warning for each failure kind holds only the reason and status", async () => {
  const cases: [Parameters<typeof mockFetch>[0], string][] = [
    [() => Promise.reject(new TypeError("dns error for sb_live_test")), "[signupbouncer] check failed (network)"],
    [() => json({}, 503), "[signupbouncer] check failed (http_status 503)"],
    [() => new Response("not json", { status: 200 }), "[signupbouncer] check failed (bad_response 200)"],
    [hang, "[signupbouncer] check failed (timeout)"],
  ];
  for (const [handler, prefix] of cases) {
    const m = mockFetch(handler);
    try {
      const lines = await captureWarn(() => checkSignup({ ...opts, timeoutMs: 30 }, { email: "a@b.com" }));
      assertEquals(lines.length, 1);
      assert(lines[0].startsWith(prefix), lines[0]);
      assertEquals(lines[0].includes("sb_live"), false);
      assertEquals(lines[0].includes("a@b.com"), false);
    } finally {
      m.restore();
    }
  }
});

Deno.test("an onError replaces the default warning", async () => {
  const m = mockFetch(() => json({}, 401));
  try {
    const seen: CheckError[] = [];
    const lines = await captureWarn(() => checkSignup({ ...opts, onError: (e) => seen.push(e) }, { email: "a@b.com" }));
    assertEquals(lines, []);
    assertEquals(seen, [{ reason: "http_status", status: 401 }]);
  } finally {
    m.restore();
  }
});

Deno.test("timeoutMs: nonsense values use the default; huge values are capped", async () => {
  const delays: number[] = [];
  const original = globalThis.setTimeout;
  globalThis.setTimeout = ((fn: () => void, ms?: number) => {
    delays.push(ms ?? 0);
    return original(fn, 0);
  }) as typeof setTimeout;
  const m = mockFetch(() => answer("allow"));
  try {
    for (const timeoutMs of [NaN, -5, 0, Infinity, 1e12, 250]) {
      await checkSignup({ ...opts, timeoutMs }, { email: "a@b.com" });
    }
  } finally {
    globalThis.setTimeout = original;
    m.restore();
  }
  assertEquals(delays, [
    DEFAULT_TIMEOUT_MS,
    DEFAULT_TIMEOUT_MS,
    DEFAULT_TIMEOUT_MS,
    MAX_TIMEOUT_MS,
    MAX_TIMEOUT_MS,
    250,
  ]);
});

// ---- Astra review fixes (P1-1, P1-4, P2-6) --------------------------------------------------------------------------

Deno.test("P1-1 an overlong or malformed email is blocked locally, never sent, never cut", async () => {
  const m = mockFetch(() => answer("allow"));
  try {
    const huge = "a".repeat(66_000) + "@mailinator.com";
    const at320 = "a".repeat(320 - "@example.com".length) + "@example.com";
    for (const email of [huge, "a" + at320, "no-at-sign", "@example.com", "a@", "a b@example.com", "a@b.com\n"]) {
      const errors: CheckError[] = [];
      const r = await checkSignup({ ...opts, onError: (e) => errors.push(e) }, { email });
      assertEquals(r, { ok: false, action: "block", error: { reason: "invalid_email" } }, email.slice(0, 40));
      assertEquals(shouldBlock(r), true);
      assertEquals(errors, []); // a refused address is not a failed check
    }
    assertEquals(m.calls.length, 0);
    assertEquals(at320.length, 320);
    assertEquals((await checkSignup(opts, { email: at320 })).action, "allow");
    assertEquals(m.calls.map((c) => c.body.email), [at320]);
  } finally {
    m.restore();
  }
});

Deno.test("no email and no IP: no request, onError gets no_input", async () => {
  const m = mockFetch(() => answer("block"));
  try {
    const errors: CheckError[] = [];
    const r = await checkSignup({ ...opts, onError: (e) => errors.push(e) }, { userAgent: "UA" });
    assertEquals(r.action, "allow");
    assertEquals(errors, [{ reason: "no_input" }]);
    assertEquals(m.calls.length, 0);
  } finally {
    m.restore();
  }
});

Deno.test("P1-4 redirects are never followed: one request, redirect manual, fails open", async () => {
  for (const status of [301, 302, 303, 307, 308]) {
    const m = mockFetch(() => new Response(null, { status, headers: { location: "https://evil.example/collect" } }));
    try {
      const errors: CheckError[] = [];
      const r = await checkSignup({ ...opts, onError: (e) => errors.push(e) }, { email: "a@b.com" });
      assertEquals(r.action, "allow");
      assertEquals(errors, [{ reason: "http_status", status }]);
      assertEquals(m.calls.length, 1);
      assertEquals(m.calls[0].redirect, "manual");
      assertEquals(m.calls[0].url, "https://api.example/v1/check");
    } finally {
      m.restore();
    }
  }
});

Deno.test("P2-6 a body over 64 KiB is cut off and fails open, even a valid block", async () => {
  const big = JSON.stringify({ ...FULL_BLOCK, padding: "x".repeat(70_000) });
  const cases: [string, () => Response][] = [
    ["streamed, no length", () => {
      const bytes = new TextEncoder().encode(big);
      return new Response(
        new ReadableStream({
          start(ctl) {
            for (let i = 0; i < bytes.length; i += 8192) ctl.enqueue(bytes.slice(i, i + 8192));
            ctl.close();
          },
        }),
        { status: 200 },
      );
    }],
    ["declared length", () => new Response(big, { status: 200, headers: { "content-length": String(big.length) } })],
  ];
  for (const [name, handler] of cases) {
    const errors: CheckError[] = [];
    const m = mockFetch(handler);
    try {
      const r = await checkSignup({ ...opts, onError: (e) => errors.push(e) }, { email: "a@b.com" });
      assertEquals(r.action, "allow", name);
      assertEquals(errors, [{ reason: "bad_response", status: 200 }], name);
    } finally {
      m.restore();
    }
  }
});

Deno.test("P2-6 a block that arrives after the deadline is a timeout, even if the body ignores the abort", async () => {
  const errors: CheckError[] = [];
  const m = mockFetch(() => {
    const bytes = new TextEncoder().encode(JSON.stringify(FULL_BLOCK));
    return new Response(
      new ReadableStream({
        start(ctl) {
          ctl.enqueue(bytes.slice(0, 10));
          setTimeout(() => {
            try {
              ctl.enqueue(bytes.slice(10));
              ctl.close();
            } catch {
              // the plugin cancelled the stream at the deadline, as it should
            }
          }, 150); // well after timeoutMs, and this stream never errors on abort
        },
      }),
      { status: 200 },
    );
  });
  try {
    const started = performance.now();
    const r = await checkSignup({ ...opts, timeoutMs: 30, onError: (e) => errors.push(e) }, { email: "a@b.com" });
    assertEquals(r.action, "allow");
    assertEquals(errors, [{ reason: "timeout" }]);
    assert(performance.now() - started < 140, "returned at the deadline, not when the body finished");
    await new Promise((r) => setTimeout(r, 160)); // let the mock's timer finish inside this test
  } finally {
    m.restore();
  }
});

Deno.test("P2-6 an answer read and parsed after the deadline, before the timer fires, is a timeout", async () => {
  const realNow = Date.now;
  const errors: CheckError[] = [];
  const m = mockFetch(() => {
    // Time jumps past the deadline while the answer is handled (a blocked event loop), so the timer has not fired.
    Date.now = () => realNow() + 60_000;
    return json(FULL_BLOCK);
  });
  try {
    const r = await checkSignup({ ...opts, timeoutMs: 1000, onError: (e) => errors.push(e) }, { email: "a@b.com" });
    assertEquals(r.action, "allow");
    assertEquals(errors, [{ reason: "timeout" }]);
  } finally {
    Date.now = realNow;
    m.restore();
  }
});
