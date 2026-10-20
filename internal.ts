// Helpers behind mod.ts. Not part of the package's public API: JSR and npm expose mod.ts only, so these can change in
// any release. Tests import them from here.

/** The longest email the `/v1/check` API accepts. It cuts longer input to this length. */
export const MAX_EMAIL_LENGTH = 320;
/** The most response body the plugin reads. A real answer is a few hundred bytes. */
export const MAX_RESPONSE_BYTES = 64 * 1024;

const ACTIONS = new Set<string>(["allow", "challenge", "block"]);

/**
 * True for an address the API checks as sent: at most 320 characters, an `@` with text on both sides, and no
 * whitespace or control characters. Anything else is refused locally, because the API would cut or reject it and the
 * plugin would then check an address other than the one Better Auth saves.
 */
export function isCheckableEmail(email: string): boolean {
  if (email.length < 3 || email.length > MAX_EMAIL_LENGTH) return false;
  // deno-lint-ignore no-control-regex
  if (/[\s\x00-\x1f\x7f]/.test(email)) return false;
  const at = email.lastIndexOf("@");
  return at > 0 && at < email.length - 1;
}

/** Returns `raw` as a bare IP address (ports and IPv6 brackets removed), or `undefined` if it does not look like one. */
export function normalizeIp(raw: string | undefined | null): string | undefined {
  let ip = raw?.trim() ?? "";
  if (ip.startsWith("[")) ip = ip.slice(1, ip.indexOf("]") > 0 ? ip.indexOf("]") : undefined); // "[::1]:443"
  else if (/^\d{1,3}(\.\d{1,3}){3}:\d+$/.test(ip)) ip = ip.slice(0, ip.lastIndexOf(":")); // "1.2.3.4:5678"
  return ip.length > 0 && ip.length <= 64 && /^[0-9a-fA-F:.]+$/.test(ip) ? ip : undefined;
}

/**
 * Reads the client IP from `ipHeader`, the one header your host or proxy overwrites. Without `ipHeader` it returns
 * `undefined`: no header is trusted by default. For a comma-separated list the entry `trustedProxies` places from the
 * right is used (default 1, the right-most), because entries further left were sent by the client.
 */
export function clientIp(
  headers: Headers | undefined,
  ipHeader: string | undefined,
  trustedProxies = 1,
): string | undefined {
  if (!headers || !ipHeader) return undefined;
  const raw = headers.get(ipHeader);
  if (!raw) return undefined;
  const entries = raw.split(",");
  const n = Number.isInteger(trustedProxies) && trustedProxies >= 1 ? trustedProxies : 1;
  // Fewer entries than trusted proxies: the chain did not come through all of them, so none of it can be trusted.
  if (entries.length < n) return undefined;
  return normalizeIp(entries[entries.length - n]);
}

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const isNum = (v: unknown): v is number => typeof v === "number" && Number.isFinite(v);
const isStr = (v: unknown): v is string => typeof v === "string";
const isStrOrNull = (v: unknown): boolean => v === null || typeof v === "string";

/**
 * True only for a complete `/v1/check` answer: every field the API always sends, with the right type. Only such an
 * answer can refuse a sign-up; a partial or malformed one counts as a failed check (allow, `onError` "bad_response").
 * A refusing answer must also be consistent: enforce mode, under quota, and `action` equal to `verdict`.
 */
export function isCompleteAnswer(v: unknown): boolean {
  if (!isObj(v)) return false;
  const { action, verdict, mode, reasons, shadow, normalized: n, network: net } = v;
  if (!isStr(action) || !ACTIONS.has(action) || !isStr(verdict) || !ACTIONS.has(verdict)) return false;
  if (mode !== "shadow" && mode !== "enforce") return false;
  if (!isNum(v.score) || !isStr(v.check_id) || !isNum(v.latency_ms) || typeof v.quota_exceeded !== "boolean") {
    return false;
  }
  const reasonOk = (r: unknown) => isObj(r) && isStr(r.code) && isStr(r.detail) && isNum(r.points) && isStr(r.tier);
  if (!Array.isArray(reasons) || !reasons.every(reasonOk)) return false;
  const shadowOk = (r: unknown) => isObj(r) && isStr(r.code) && isStr(r.detail) && isStr(r.tier);
  if (!Array.isArray(shadow) || !shadow.every(shadowOk)) return false;
  if (!isObj(n) || !isStrOrNull(n.provider) || !isNum(n.repeat_signups_7d)) return false;
  if (
    net !== null &&
    !(isObj(net) && (net.asn === null || isNum(net.asn)) && isStrOrNull(net.asn_org) && Array.isArray(net.kinds) &&
      net.kinds.every(isStr) && isStrOrNull(net.label) && isStr(net.prefix))
  ) return false;
  return action === "allow" || (mode === "enforce" && v.quota_exceeded === false && action === verdict);
}

/** Why {@link readCapped} gave up. */
export type ReadFailure = "too_large" | "aborted";

/**
 * Reads a response body as text, at most `maxBytes`. Stops as soon as `signal` aborts, even when the body stream itself
 * ignores the abort. Returns the text, or why it stopped. Throws only if the stream errors.
 */
export async function readCapped(
  res: Response,
  signal: AbortSignal,
  maxBytes = MAX_RESPONSE_BYTES,
): Promise<string | { failed: ReadFailure }> {
  const free = () => {
    try {
      res.body?.cancel().catch(() => {});
    } catch {
      // a locked or broken body: nothing to free
    }
  };
  const declared = Number(res.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > maxBytes) {
    free();
    return { failed: "too_large" };
  }
  if (!res.body) return "";
  const reader = res.body.getReader();
  let onAbort = () => {};
  const aborted = new Promise<"aborted">((resolve) => {
    onAbort = () => resolve("aborted");
    if (signal.aborted) resolve("aborted");
    else signal.addEventListener("abort", onAbort, { once: true });
  });
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    for (;;) {
      const next = await Promise.race([reader.read(), aborted]);
      if (next === "aborted") {
        reader.cancel().catch(() => {});
        return { failed: "aborted" };
      }
      if (next.done) break;
      size += next.value.byteLength;
      if (size > maxBytes) {
        reader.cancel().catch(() => {});
        return { failed: "too_large" };
      }
      chunks.push(next.value);
    }
  } finally {
    signal.removeEventListener("abort", onAbort);
  }
  const all = new Uint8Array(size);
  let offset = 0;
  for (const c of chunks) {
    all.set(c, offset);
    offset += c.byteLength;
  }
  return new TextDecoder().decode(all);
}

// A subset of what the API accepts (letters, digits, . _ : -; 40 at most) that must start with a letter or digit, so a
// route pattern such as ":id" is never sent as a provider.
const PROVIDER_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,39}$/;

/** The parts of a Better Auth endpoint context this plugin reads. */
export type HookCtx =
  | {
    path?: string;
    params?: Record<string, unknown>;
    headers?: Headers;
    request?: Request;
    body?: unknown;
  }
  | null
  | undefined;

/** The provider ids the generic-OAuth plugin registers, from the `plugins` in the app's Better Auth options. */
function genericOAuthIds(options: unknown): Set<string> {
  const ids = new Set<string>();
  const plugins = (options as { plugins?: unknown } | null | undefined)?.plugins;
  if (!Array.isArray(plugins)) return ids;
  for (const plugin of plugins) {
    const p = plugin as { id?: unknown; options?: { config?: unknown } } | null;
    if (!p || p.id !== "generic-oauth" || !Array.isArray(p.options?.config)) continue;
    for (const c of p.options.config) {
      const id = (c as { providerId?: unknown } | null)?.providerId;
      if (typeof id === "string") ids.add(id);
    }
  }
  return ids;
}

/**
 * The social provider ids whose sign-ups may be sent with `auth_provider` and `email_verified`: the app's own
 * `socialProviders` (Better Auth's built-in OAuth providers, which take `emailVerified` from the provider's own flag)
 * that Better Auth enabled at start-up, minus every generic-OAuth provider id.
 *
 * Read from the context Better Auth passes to the plugin's `init`. By then Better Auth has called each function-valued
 * `socialProviders` entry and left out the ones with `enabled: false` or no config, and `ctx.socialProviders` holds the
 * resulting providers. The plugin reads their ids and never calls a config function itself, so a factory that fails or
 * hangs on a second call cannot change which providers are trusted or stall start-up.
 *
 * An id counts only when it is also a key of `options.socialProviders`, so a provider another plugin adds is not
 * trusted. A generic-OAuth provider may reuse a built-in id ("google") and then handles that id's sign-ins in place of
 * the built-in one, whatever the plugin order, so a generic id, or an id that appears twice, is never trusted.
 */
export function configuredSocialProviders(authCtx: unknown): Set<string> {
  const ctx = authCtx as { socialProviders?: unknown; options?: unknown } | null | undefined;
  const ids = new Set<string>();
  const resolved = ctx?.socialProviders;
  const configured = (ctx?.options as { socialProviders?: unknown } | null | undefined)?.socialProviders;
  if (!Array.isArray(resolved) || !configured || typeof configured !== "object") return ids;
  const generic = genericOAuthIds(ctx?.options);
  const seen = new Set<string>();
  const repeated = new Set<string>();
  for (const provider of resolved) {
    // An entry that is not a provider object (Better Auth's own lookups allow a function here) is never called.
    const id = provider && typeof provider === "object" ? (provider as { id?: unknown }).id : undefined;
    if (typeof id !== "string") continue;
    if (seen.has(id)) repeated.add(id);
    seen.add(id);
  }
  for (const id of seen) {
    if (Object.hasOwn(configured, id) && !generic.has(id) && !repeated.has(id)) ids.add(id);
  }
  return ids;
}

/**
 * The provider id to send as `auth_provider` for a user created by this request, or `undefined`. Only Better Auth's
 * core social sign-in routes, and only for a provider in `trusted` (see {@link configuredSocialProviders}): the OAuth
 * callback `/callback/:id` (the id is in `ctx.params`), ID-token sign-in on `/sign-in/social` (the id is the body's
 * `provider`) and `/one-tap/callback` (Google). Never an id from an SSO route (`/sso/...`) or a generic-OAuth provider:
 * those ids are named by the app or, with self-service SSO, by its users, who could pick a name SignupBouncer trusts
 * and hand it any address. Without a provider, the email is checked like an email sign-up.
 */
export function socialProviderFor(ctx: HookCtx, trusted: ReadonlySet<string>): string | undefined {
  const path = ctx?.path;
  let id: unknown;
  if (path === "/callback/:id") id = ctx?.params?.id;
  else if (path === "/one-tap/callback") id = "google";
  else if (path === "/sign-in/social") id = (ctx?.body as { provider?: unknown } | undefined)?.provider;
  return typeof id === "string" && PROVIDER_ID.test(id) && trusted.has(id) ? id : undefined;
}

/**
 * `u` when it is a well-formed http(s) URL with a host, at most 2,048 characters, unchanged; otherwise `undefined`.
 * The same check as SignupBouncer's other helpers, so a bad `why_url` never becomes a link.
 */
export function validWhyUrl(u: unknown): string | undefined {
  if (typeof u !== "string" || u.length > 2048 || !/^https?:\/\/[^\s/\\?#][^\s\\]*$/i.test(u)) return undefined;
  try {
    const url = new URL(u);
    return (url.protocol === "https:" || url.protocol === "http:") && url.hostname !== "" ? u : undefined;
  } catch {
    return undefined;
  }
}
