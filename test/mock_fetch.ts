// Replaces globalThis.fetch for one test. Every call is recorded; the handler decides the answer.

export interface Call {
  url: string;
  headers: Headers;
  body: Record<string, unknown>;
  /** The fetch `redirect` option the caller passed. */
  redirect: RequestRedirect | undefined;
}

export type Handler = (call: Call, signal: AbortSignal | undefined) => Response | Promise<Response>;

export function mockFetch(handler: Handler): { calls: Call[]; restore: () => void } {
  const original = globalThis.fetch;
  const calls: Call[] = [];
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const call: Call = {
      url: String(input),
      headers: new Headers(init?.headers),
      body: JSON.parse(String(init?.body ?? "{}")),
      redirect: init?.redirect,
    };
    calls.push(call);
    return await handler(call, init?.signal ?? undefined);
  }) as typeof fetch;
  return { calls, restore: () => (globalThis.fetch = original) };
}

export function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

/** A body shaped like the real /v1/check response. */
export function answerBody(
  action: "allow" | "challenge" | "block",
  verdict: "allow" | "challenge" | "block" = action,
  mode: "enforce" | "shadow" = "enforce",
): Record<string, unknown> {
  return {
    verdict,
    action,
    mode,
    score: action === "allow" ? 0 : 90,
    check_id: "chk_test",
    reasons: action === "allow" ? [] : [{ code: "disposable_domain", detail: "x", points: 100, tier: "free" }],
    normalized: { provider: null, repeat_signups_7d: 0 },
    network: null,
    shadow: [],
    latency_ms: 1,
    quota_exceeded: false,
  };
}

/** An answer shaped like the real /v1/check response. */
export function answer(
  action: "allow" | "challenge" | "block",
  verdict: "allow" | "challenge" | "block" = action,
  mode: "enforce" | "shadow" = "enforce",
): Response {
  return json(answerBody(action, verdict, mode));
}

/** Never answers until the request is aborted, then rejects like fetch does. */
export function hang(_call: Call, signal: AbortSignal | undefined): Promise<Response> {
  return new Promise((_, reject) => {
    signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")));
  });
}
