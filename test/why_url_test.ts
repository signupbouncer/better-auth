// #210: the "Why was this refused?" link. When the customer turns it on (Rules tab of the dashboard), /v1/check sends
// why_url with block and challenge answers. The plugin passes it on as why_url in the 400 error body next to code and
// message, as SignupBouncer's copy-paste Better Auth hook does; without one, or with a malformed one, the key is absent.

import { assert, assertEquals } from "@std/assert";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { createAuthMiddleware } from "better-auth/api";
import {
  blockMessage,
  type CheckResult,
  checkSignup,
  signupBouncer,
  type SignupBouncerOptions,
  whyUrl,
} from "../mod.ts";
import { answer, answerBody, json, mockFetch } from "./mock_fetch.ts";

const BASE = "http://localhost:3000";
const WHY = "https://signupbouncer.com/why/mailinator.com";
const MESSAGE = "Use your work email.";

// The same lists as SignupBouncer's other helpers' tests (signupbouncer integrations/nextjs/test/why_urls.ts).
/** Well-formed links passed through exactly as sent. */
const GOOD_WHY_URLS = [
  "https://signupbouncer.com/why/mailinator.com",
  "HTTP://127.0.0.1:8080/why",
  "https://[::1]/why",
];
/** Values that must never become a link: malformed, hostless, not http(s), or too long. */
const BAD_WHY_URLS = [
  "",
  "javascript:alert(1)",
  "ftp://a.com/why",
  "https://#fragment",
  "https://[bad]",
  "https://",
  "https://?q",
  "https:///a.com",
  "https:example.com",
  "https://a.com:99999/why",
  "https://exa mple.com",
  "https://a.com\\why",
  `https://a.com/${"x".repeat(2048)}`,
];

const opts = { apiKey: "sb_live_test", baseUrl: "https://sb.test" };

/** checkSignup against one mocked answer. */
async function check(body: Record<string, unknown>): Promise<CheckResult> {
  const m = mockFetch(() => json(body));
  try {
    return await checkSignup({ ...opts, onError: () => {} }, { email: "a@mailinator.com" });
  } finally {
    m.restore();
  }
}

Deno.test("#210 whyUrl: the answer's why_url when well-formed, null when absent, malformed or not text", async () => {
  const block = { ...answerBody("block"), block_message: MESSAGE };
  const withLink = await check({ ...block, why_url: WHY });
  assertEquals([blockMessage(withLink), whyUrl(withLink)], [MESSAGE, WHY]);
  assert(withLink.ok);
  assertEquals(withLink.response.why_url, WHY);

  const without = await check(block);
  assertEquals([blockMessage(without), whyUrl(without)], [MESSAGE, null]);

  for (const u of GOOD_WHY_URLS) assertEquals(whyUrl(await check({ ...block, why_url: u })), u, u);
  for (const u of [...BAD_WHY_URLS, null, 42, { href: WHY }, [WHY]]) {
    const r = await check({ ...block, why_url: u });
    assertEquals(whyUrl(r), null, String(u));
    // A bad link is dropped from the answer and never fails the check: the sign-up is still refused.
    assert(r.ok && !("why_url" in r.response), String(u));
    assertEquals(r.action, "block");
  }
});

Deno.test("#210 whyUrl is null for a failed check and for an email refused without a request", async () => {
  assertEquals(whyUrl(await check({ ...answerBody("block"), why_url: WHY, score: "x" })), null); // incomplete answer
  assertEquals(whyUrl({ ok: false, action: "allow", error: { reason: "timeout" } }), null);
  const local = await checkSignup({ ...opts, onError: () => {} }, { email: "not an address" });
  assertEquals([local.action, whyUrl(local)], ["block", null]);
});

function makeAuth(o: Partial<SignupBouncerOptions> = {}, extra: Parameters<typeof betterAuth>[0] = {}) {
  const db = { user: [], session: [], account: [], verification: [] } as Record<string, Record<string, unknown>[]>;
  const auth = betterAuth({
    ...extra,
    baseURL: BASE,
    secret: "test-secret-test-secret-test-secret-0123",
    database: memoryAdapter(db),
    emailAndPassword: { enabled: true },
    rateLimit: { enabled: false },
    telemetry: { enabled: false },
    plugins: [signupBouncer({ ...opts, ...o })],
  });
  return { auth, db };
}

async function signUp(auth: ReturnType<typeof makeAuth>["auth"], email: string) {
  const res = await auth.handler(
    new Request(`${BASE}/api/auth/sign-up/email`, {
      method: "POST",
      headers: { "content-type": "application/json", origin: BASE },
      body: JSON.stringify({ email, password: "correct-horse-battery", name: "Test" }),
    }),
  );
  return { status: res.status, body: await res.json() };
}

Deno.test("#210 a refused email sign-up gets why_url next to code and message, only when the answer has a good one", async () => {
  const cases: [string, Record<string, unknown>, Partial<SignupBouncerOptions>, Record<string, unknown>][] = [
    [
      "block with link",
      { ...answerBody("block"), block_message: MESSAGE, why_url: WHY },
      {},
      { code: "SIGNUP_BLOCKED", message: MESSAGE, why_url: WHY },
    ],
    ["block without link", { ...answerBody("block"), block_message: MESSAGE }, {}, {
      code: "SIGNUP_BLOCKED",
      message: MESSAGE,
    }],
    ["block with a malformed link", { ...answerBody("block"), block_message: MESSAGE, why_url: "javascript:x" }, {}, {
      code: "SIGNUP_BLOCKED",
      message: MESSAGE,
    }],
    // The link follows the dashboard setting, so a message set in code keeps it.
    [
      "blockMessage in code",
      { ...answerBody("block"), block_message: MESSAGE, why_url: WHY },
      { blockMessage: "No burners, please." },
      { code: "SIGNUP_BLOCKED", message: "No burners, please.", why_url: WHY },
    ],
    [
      "challenge refused with challenge: 'block'",
      { ...answerBody("challenge"), block_message: MESSAGE, why_url: WHY },
      { challenge: "block" },
      { code: "SIGNUP_BLOCKED", message: MESSAGE, why_url: WHY },
    ],
  ];
  for (const [label, sent, o, expected] of cases) {
    const m = mockFetch(() => json(sent));
    try {
      const { auth, db } = makeAuth(o);
      const r = await signUp(auth, "a@mailinator.com");
      assertEquals(r.status, 400, label);
      assertEquals(r.body, expected, label);
      assertEquals(db.user.length, 0, label);
    } finally {
      m.restore();
    }
  }
});

Deno.test("#210 an answer that lets the sign-up through never produces a link", async () => {
  const sent: Record<string, unknown>[] = [
    { ...answerBody("challenge"), block_message: MESSAGE, why_url: WHY }, // challenge allowed by default
    { ...answerBody("allow", "block", "shadow"), why_url: WHY }, // shadow mode
  ];
  for (const body of sent) {
    const m = mockFetch(() => json(body));
    try {
      const { auth, db } = makeAuth();
      const r = await signUp(auth, `a${db.user.length}@example.com`);
      assertEquals(r.status, 200);
      assertEquals(db.user.length, 1);
      assert(!JSON.stringify(r.body).includes(WHY));
    } finally {
      m.restore();
    }
  }
});

Deno.test("#210 the database hook passes why_url too (an app hook rewrote the address after the first check)", async () => {
  const m = mockFetch((call) =>
    String(call.body.email).endsWith("@mailinator.com")
      ? json({ ...answerBody("block"), block_message: MESSAGE, why_url: WHY })
      : answer("allow")
  );
  try {
    const { auth, db } = makeAuth({}, {
      hooks: {
        // deno-lint-ignore require-await
        before: createAuthMiddleware(async (ctx) => {
          if (ctx.path !== "/sign-up/email") return;
          return { context: { body: { ...(ctx.body as object), email: "rewritten@mailinator.com" } } };
        }),
      },
    });
    const r = await signUp(auth, "innocent@example.com");
    assertEquals(r.status, 400);
    assertEquals(r.body, { code: "SIGNUP_BLOCKED", message: MESSAGE, why_url: WHY });
    assertEquals(m.calls.map((c) => c.body.email), ["innocent@example.com", "rewritten@mailinator.com"]);
    assertEquals(db.user.length, 0);
  } finally {
    m.restore();
  }
});

Deno.test("#210 README says what a refused user sees, link included", async () => {
  const readme = (await Deno.readTextFile(new URL("../README.md", import.meta.url))).replace(/\s+/g, " ");
  assert(readme.includes("## What a refused user sees"));
  assert(readme.includes("why_url"));
  assert(readme.includes("Why was this refused?"));
});
