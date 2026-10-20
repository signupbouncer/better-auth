// #210: OAuth sign-ups through a real Better Auth instance (memory adapter) with its built-in Google provider. The
// redirect flow is /sign-in/social then /callback/google; ID-token sign-in is one POST to /sign-in/social. The
// plugin's database hook sees Better Auth's own context (path "/callback/:id", params.id, or the body's provider).
// Mocked: the SignupBouncer API, Google's token endpoint, the profile (the provider's getUserInfo option) and ID-token
// verification (its verifyIdToken option), so no network is used. Better Auth itself runs unmodified.

import { assert, assertEquals } from "@std/assert";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { genericOAuth } from "better-auth/plugins";
import { signupBouncer } from "../mod.ts";
import { answer, answerBody, json } from "./mock_fetch.ts";

const BASE = "http://localhost:3000";
const BURNER = "verified@mailinator.com";

type Plugin = Parameters<typeof betterAuth>[0]["plugins"] extends (infer P)[] | undefined ? P : never;

const googleConfig = (email: string, emailVerified: boolean) => ({
  clientId: "google-client",
  clientSecret: "google-secret",
  verifyIdToken: () => Promise.resolve(true),
  getUserInfo: () =>
    Promise.resolve({
      user: { id: "g-123", email, emailVerified, name: "Gee" },
      data: { sub: "g-123", email, email_verified: emailVerified },
    }),
});

/** A generic-OAuth provider that reuses the id "google" (Better Auth 1.7 allows it, with a warning). */
const shadowingGeneric = () =>
  genericOAuth({
    config: [{
      providerId: "google",
      clientId: "generic-client",
      clientSecret: "generic-secret",
      authorizationUrl: "https://idp.example.test/authorize",
      tokenUrl: "https://idp.example.test/token",
      getToken: () => Promise.resolve({ accessToken: "generic-at", tokenType: "Bearer" }),
      getUserInfo: () => Promise.resolve({ id: "x-1", email: BURNER, emailVerified: true, name: "X" }),
    }],
  });

/**
 * Records SignupBouncer checks and answers them the way the real API treats an email rule: a mailinator.com address
 * is blocked unless the request says a known provider verified it (auth_provider "google" with email_verified true),
 * which skips the email checks. Also answers Google's token endpoint. Any other request fails the test.
 */
function mockNetwork(extra: Record<string, unknown> = {}) {
  const original = globalThis.fetch;
  const checks: Record<string, unknown>[] = [];
  globalThis.fetch = ((input: string | URL | Request, init?: RequestInit) => {
    const url = input instanceof Request ? input.url : String(input);
    if (url === "https://sb.test/v1/check") {
      const body = JSON.parse(String(init?.body));
      checks.push(body);
      const skipped = body.auth_provider === "google" && body.email_verified === true;
      const burner = String(body.email).endsWith("@mailinator.com");
      if (skipped || !burner) return Promise.resolve(answer("allow"));
      return Promise.resolve(json({ ...answerBody("block"), ...extra }));
    }
    if (url === "https://oauth2.googleapis.com/token") {
      return Promise.resolve(json({ access_token: "google-at", token_type: "Bearer", expires_in: 3600 }));
    }
    return Promise.reject(new Error(`unexpected fetch: ${url}`));
  }) as typeof fetch;
  return { checks, restore: () => (globalThis.fetch = original) };
}

function makeAuth(socialProviders: Record<string, unknown>, plugins: Plugin[]) {
  const db = { user: [], session: [], account: [], verification: [] } as Record<string, Record<string, unknown>[]>;
  const auth = betterAuth({
    baseURL: BASE,
    secret: "test-secret-test-secret-test-secret-0123",
    database: memoryAdapter(db),
    rateLimit: { enabled: false },
    telemetry: { enabled: false },
    logger: { disabled: true },
    // deno-lint-ignore no-explicit-any
    socialProviders: socialProviders as any,
    plugins,
  });
  return { auth, db };
}

/** The redirect flow: start at /sign-in/social, finish at /callback/google. Returns the redirect and saved users. */
async function redirectSignup(socialProviders: Record<string, unknown>, plugins: Plugin[]) {
  const { auth, db } = makeAuth(socialProviders, plugins);
  const start = await auth.handler(
    new Request(`${BASE}/api/auth/sign-in/social`, {
      method: "POST",
      headers: { "content-type": "application/json", origin: BASE },
      body: JSON.stringify({ provider: "google", callbackURL: "/done", errorCallbackURL: "/error" }),
    }),
  );
  const { url } = await start.json() as { url: string };
  const state = new URL(url).searchParams.get("state")!;
  const cookie = start.headers.getSetCookie().map((c) => c.split(";")[0]).join("; ");
  const done = await auth.handler(
    new Request(`${BASE}/api/auth/callback/google?code=the-code&state=${encodeURIComponent(state)}`, {
      headers: { cookie },
    }),
  );
  await done.body?.cancel();
  return { status: done.status, location: done.headers.get("location") ?? "", users: db.user };
}

/** ID-token sign-in: one POST to /sign-in/social with the token. Returns the JSON answer and saved users. */
async function idTokenSignup(socialProviders: Record<string, unknown>, plugins: Plugin[]) {
  const { auth, db } = makeAuth(socialProviders, plugins);
  const res = await auth.handler(
    new Request(`${BASE}/api/auth/sign-in/social`, {
      method: "POST",
      headers: { "content-type": "application/json", origin: BASE },
      body: JSON.stringify({ provider: "google", idToken: { token: "header.payload.signature" } }),
    }),
  );
  return { status: res.status, body: await res.json(), users: db.user };
}

const bouncer = (checkOtherSignups = true) =>
  signupBouncer({ apiKey: "sb_live_test", baseUrl: "https://sb.test", checkOtherSignups });

Deno.test("#210 a verified Google sign-up sends auth_provider and email_verified, so an email rule cannot refuse it", async () => {
  const net = mockNetwork();
  try {
    const r = await redirectSignup({ google: googleConfig(BURNER, true) }, [bouncer()]);
    assertEquals(net.checks, [{ email: BURNER, auth_provider: "google", email_verified: true }]);
    assertEquals(r.status, 302);
    assert(r.location.startsWith("/done"), r.location);
    assertEquals(r.users.length, 1);
  } finally {
    net.restore();
  }
});

Deno.test("#210 a Google sign-up the provider did not verify sends email_verified false and its email is checked", async () => {
  const net = mockNetwork();
  try {
    const r = await redirectSignup({ google: googleConfig(BURNER, false) }, [bouncer()]);
    assertEquals(net.checks, [{ email: BURNER, auth_provider: "google", email_verified: false }]);
    assert(r.location.startsWith("/error"), r.location);
    assertEquals(new URL(r.location, BASE).searchParams.get("error"), "SIGNUP_BLOCKED");
    assertEquals(r.users.length, 0);
  } finally {
    net.restore();
  }
});

Deno.test("#210 ID-token sign-in with Google sends the provider and the flag too", async () => {
  for (const emailVerified of [true, false]) {
    const net = mockNetwork();
    try {
      const r = await idTokenSignup({ google: googleConfig(BURNER, emailVerified) }, [bouncer()]);
      assertEquals(net.checks, [{ email: BURNER, auth_provider: "google", email_verified: emailVerified }]);
      assertEquals([r.status, r.users.length], emailVerified ? [200, 1] : [400, 0], String(emailVerified));
      if (!emailVerified) assertEquals(r.body.code, "SIGNUP_BLOCKED");
    } finally {
      net.restore();
    }
  }
});

Deno.test("#210 a function-valued socialProviders entry is trusted like an object", async () => {
  const net = mockNetwork();
  try {
    const r = await redirectSignup({ google: () => Promise.resolve(googleConfig(BURNER, true)) }, [bouncer()]);
    assertEquals(r.users.length, 1);
    assertEquals(net.checks, [{ email: BURNER, auth_provider: "google", email_verified: true }]);
  } finally {
    net.restore();
  }
});

Deno.test("#210 a generic-OAuth provider named google is never sent as google, before or after the plugin", async () => {
  for (const order of ["generic first", "generic last"]) {
    const net = mockNetwork();
    try {
      const plugins = order === "generic first" ? [shadowingGeneric(), bouncer()] : [bouncer(), shadowingGeneric()];
      const r = await redirectSignup({ google: googleConfig(BURNER, true) }, plugins);
      // The generic provider handled the sign-in, so the email goes without a provider and the email rule applies.
      assertEquals(net.checks, [{ email: BURNER }], order);
      assertEquals(r.users.length, 0, order);
    } finally {
      net.restore();
    }
  }
});

Deno.test("#210 without checkOtherSignups, OAuth sign-ups are not checked at all", async () => {
  const net = mockNetwork();
  try {
    const r = await redirectSignup({ google: googleConfig(BURNER, false) }, [bouncer(false)]);
    assertEquals(net.checks, []);
    assertEquals(r.users.length, 1);
  } finally {
    net.restore();
  }
});

Deno.test("#210 why_url: the OAuth redirect carries code and message only; ID-token sign-in returns the link", async () => {
  const why = "https://signupbouncer.com/why/mailinator.com";
  const net = mockNetwork({ block_message: "Use your work email.", why_url: why });
  try {
    // Better Auth turns a refusal in the OAuth callback into a redirect to your error page with error and
    // error_description, and drops every other field of the error.
    const redirect = await redirectSignup({ google: googleConfig(BURNER, false) }, [bouncer()]);
    const params = new URL(redirect.location, BASE).searchParams;
    assertEquals([...params.keys()].sort(), ["error", "error_description"]);
    assertEquals([params.get("error"), params.get("error_description")], ["SIGNUP_BLOCKED", "Use your work email."]);

    const idToken = await idTokenSignup({ google: googleConfig(BURNER, false) }, [bouncer()]);
    assertEquals(idToken.status, 400);
    assertEquals(idToken.body.why_url, why);
    assertEquals([idToken.body.code, idToken.body.message], ["SIGNUP_BLOCKED", "Use your work email."]);
  } finally {
    net.restore();
  }
});
