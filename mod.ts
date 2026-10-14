/**
 * signupbouncer plugin for Better Auth. It checks each new email sign-up with signupbouncer's `/v1/check` API and
 * refuses the ones signupbouncer says to block. If signupbouncer is slow, down or sends anything unexpected (including
 * an answer missing a field the API always sends), the sign-up goes through (fail open).
 *
 * ```ts
 * import { betterAuth } from "better-auth";
 * import { signupBouncer } from "@signupbouncer/better-auth";
 *
 * export const auth = betterAuth({
 *   emailAndPassword: { enabled: true },
 *   plugins: [signupBouncer({ apiKey: process.env.SIGNUPBOUNCER_API_KEY! })],
 * });
 * ```
 *
 * Better Auth APIs used (checked 2026-10-14 against the docs and better-auth 1.7.7 on npm):
 * - plugin `hooks.before` with `matcher` + `createAuthMiddleware`: https://better-auth.com/docs/concepts/plugins#hooks
 * - throwing `APIError` from a hook: https://better-auth.com/docs/concepts/hooks#errors
 * - `databaseHooks.user.create.before` (returned from the plugin's `init`, as the built-in admin plugin does):
 *   https://better-auth.com/docs/concepts/database#database-hooks
 *
 * @module
 */

import type { BetterAuthPlugin } from "better-auth";
import { APIError, createAuthMiddleware } from "better-auth/api";

/** What signupbouncer says to do with a sign-up. In shadow mode this is always `"allow"`. */
export type SignupAction = "allow" | "challenge" | "block";

/** Why a check could not be completed. The sign-up is allowed in every case. */
export type CheckErrorReason =
  | "missing_api_key"
  | "malformed_api_key"
  | "timeout"
  | "network"
  | "http_status"
  | "bad_response";

/**
 * Passed to `onError`. The sign-up has already been allowed when you receive it. Safe to log: a fixed reason and a
 * status code, never an exception message or response text (a fetch error can quote your API key).
 */
export interface CheckError {
  /** Why the check failed. */
  reason: CheckErrorReason;
  /** HTTP status, for `http_status` and `bad_response`. */
  status?: number;
}

/** The parts of the `/v1/check` answer this plugin relies on. Other fields are passed through untouched. */
export interface CheckResponse {
  /** The verdict before the app's mode is applied. Never act on it: in shadow mode it can say block. */
  verdict?: SignupAction;
  /** What to do: the verdict in enforce mode, always `"allow"` in shadow mode. */
  action: SignupAction;
  /** The app's mode in your signupbouncer dashboard. */
  mode?: "shadow" | "enforce";
  /** Risk score; 70 and up blocks with the default thresholds. */
  score?: number;
  /** Id of this check in your dashboard log (`chk_...`). */
  check_id?: string;
  /** Why the score is what it is. */
  reasons?: { code: string; detail?: string; points?: number; tier?: string }[];
  /** What a higher plan would also have flagged. */
  shadow?: { code: string; tier?: string; detail?: string }[];
  /** True when the check was skipped because the account is over its monthly limit. The action is then allow. */
  quota_exceeded?: boolean;
  /** Fields this plugin does not read (`normalized`, `network`, `latency_ms` and any added later). */
  [key: string]: unknown;
}

/** Result of one check. `action` is always set: `"allow"` whenever the check failed. */
export type CheckResult =
  | { ok: true; action: SignupAction; response: CheckResponse }
  | { ok: false; action: "allow"; error: CheckError };

/** Options for {@linkcode signupBouncer}. Only `apiKey` is required. */
export interface SignupBouncerOptions {
  /** Your signupbouncer API key (`sb_live_...`). Without one, every sign-up is allowed and `onError` is called. */
  apiKey: string;
  /** API origin. Default `https://signupbouncer.com`. */
  baseUrl?: string;
  /** Which of your signupbouncer apps to log the checks under (`app_...`). Default: your first app. */
  app?: string;
  /**
   * How long to wait for signupbouncer before allowing the sign-up, in milliseconds. Default 1,500. A value that is
   * not a positive number uses the default, and anything above 10,000 is cut to 10,000.
   */
  timeoutMs?: number;
  /** Message returned to the client when a sign-up is blocked. */
  blockMessage?: string;
  /** What to do when the answer is `"challenge"`. Better Auth has no captcha step to send it to. Default `"allow"`. */
  challenge?: "allow" | "block";
  /**
   * The one request header your host or proxy sets to the client IP, overwriting anything the client sent, for example
   * `"cf-connecting-ip"` (Cloudflare), `"x-real-ip"` (Vercel), `"fly-client-ip"` (Fly.io). Default: none, so no IP is
   * sent and only the email is checked. A header nothing in front of your app overwrites is whatever the client says.
   */
  ipHeader?: string;
  /**
   * For a comma-separated `ipHeader` such as X-Forwarded-For: how many proxies you run that each append the address
   * they received from. The entry that many places from the right is used; anything further left came from the client.
   * Default 1 (one proxy, such as nginx with `proxy_add_x_forwarded_for`). Only safe when every request passes through
   * all of them: if your app or an inner proxy can be reached directly, a client can supply the missing entries and
   * pick its own IP. Prefer a single header your outermost proxy overwrites (see the README).
   */
  trustedProxies?: number;
  /**
   * Your own way to find the client IP, used instead of `ipHeader`. Called with the request (when Better Auth has one)
   * and its headers. Return `undefined` for no IP. If it throws, the check runs without an IP.
   */
  getIp?: (request: Request | undefined, headers: Headers | undefined) => string | undefined;
  /**
   * Called when a check fails (timeout, network error, non-2xx, unreadable or incomplete answer). The sign-up is still
   * allowed. Not awaited, so a slow logger never delays the sign-up; anything it throws or rejects with is ignored.
   * Without `onError`, each failure is written with `console.warn` as one line holding the reason and status code
   * only. Pass `onError: () => {}` to turn that off.
   */
  onError?: (error: CheckError) => unknown;
  /**
   * Also check users created outside `/sign-up/email` (OAuth callbacks, magic link, email OTP and other plugins),
   * through a `user.create.before` database hook. OAuth sign-ups send the email with `auth_provider` (the provider id,
   * such as `"google"`): signupbouncer scores them on IP and signup bursts only, because the provider has verified the
   * email, and counts the email's domain in your dashboard. Default `false`.
   */
  checkOtherSignups?: boolean;
}

/** The API origin used when `baseUrl` is not set. */
export const DEFAULT_BASE_URL = "https://signupbouncer.com";
/** How long a check waits by default before the sign-up is allowed anyway, in milliseconds. */
export const DEFAULT_TIMEOUT_MS = 1500;
/** The longest `timeoutMs` accepted, in milliseconds. Longer values are cut to this. */
export const MAX_TIMEOUT_MS = 10_000;
/** The message a blocked sign-up gets when `blockMessage` is not set. */
export const DEFAULT_BLOCK_MESSAGE = "Please sign up with a permanent email address.";

const ACTIONS = new Set<string>(["allow", "challenge", "block"]);

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

/**
 * The `onError` used when you pass none: one `console.warn` line. It holds the fixed reason and the status code only,
 * never the API key, the email, the IP, an exception message or response text.
 */
export function warnCheckError(error: CheckError): void {
  const status = typeof error.status === "number" ? ` ${error.status}` : "";
  const hint = error.reason === "missing_api_key" || error.reason === "malformed_api_key" || error.status === 401
    ? " Check the signupbouncer API key in your config."
    : "";
  console.warn(`[signupbouncer] check failed (${error.reason}${status}), sign-up allowed.${hint}`);
}

function timeoutOf(ms: number | undefined): number {
  return typeof ms === "number" && ms > 0 ? Math.min(ms, MAX_TIMEOUT_MS) : DEFAULT_TIMEOUT_MS; // NaN > 0 is false
}

function report(onError: SignupBouncerOptions["onError"], error: CheckError): CheckResult {
  // A broken or slow onError must not fail or delay the sign-up: not awaited, sync throws and rejections ignored.
  try {
    const pending: unknown = (onError ?? warnCheckError)(error);
    if (pending && typeof (pending as PromiseLike<unknown>).then === "function") {
      Promise.resolve(pending).catch(() => {});
    }
  } catch {
    // ignored
  }
  return { ok: false, action: "allow", error };
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
export function isCheckResponse(v: unknown): v is CheckResponse {
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

/**
 * Calls `POST {baseUrl}/v1/check`. Never throws: on any failure it returns `action: "allow"` and calls `onError`
 * (or {@linkcode warnCheckError} when there is none). Exported so you can run the same check from your own routes.
 *
 * @param options The API key and connection settings, as for {@linkcode signupBouncer}.
 * @param input What to check. Send at least an email or an IP; with neither, the result is allow and no request is made.
 * @returns The action to take, with the API's answer or the reason the check failed.
 */
export async function checkSignup(
  options: Pick<SignupBouncerOptions, "apiKey" | "baseUrl" | "app" | "timeoutMs" | "onError">,
  input: {
    /** The address the person signed up with. */
    email?: string;
    /** The client IP, if you know it from a header your host overwrites. */
    ip?: string;
    /** The request's User-Agent header. Cut to 512 characters. */
    userAgent?: string;
    /**
     * The OAuth/SSO provider that verified `email` (`"google"`, `"github"`, ...). signupbouncer then scores only the IP
     * and signup bursts and keeps the email's domain for your stats. Leave it out for email/password sign-ups.
     */
    authProvider?: string;
  },
): Promise<CheckResult> {
  const apiKey = options.apiKey?.trim() ?? "";
  if (!apiKey) return report(options.onError, { reason: "missing_api_key" });
  // A key with a newline or other junk pasted in: fetch would reject the header and quote the key in its error.
  if (!/^[\x21-\x7e]+$/.test(apiKey)) return report(options.onError, { reason: "malformed_api_key" });
  const url = (options.baseUrl ?? DEFAULT_BASE_URL).replace(/\/+$/, "") + "/v1/check";
  const body: Record<string, string> = {};
  if (input.email) body.email = input.email;
  if (input.ip) body.ip = input.ip;
  if (input.userAgent) body.user_agent = input.userAgent.slice(0, 512);
  if (input.authProvider) body.auth_provider = input.authProvider;
  if (options.app) body.app = options.app;
  // The API needs an email or an IP; with neither there is nothing to check.
  if (!body.email && !body.ip) return { ok: true, action: "allow", response: { action: "allow" } };

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutOf(options.timeoutMs));
  let res: Response;
  try {
    res = await fetch(url, {
      method: "POST",
      headers: { "authorization": `Bearer ${apiKey}`, "content-type": "application/json" },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
  } catch {
    clearTimeout(timer);
    return report(options.onError, { reason: controller.signal.aborted ? "timeout" : "network" });
  }
  try {
    if (!res.ok) {
      // Free the connection without waiting: cancel() rejects on a stream that already errored (a reset after the
      // headers), and cleanup must never turn into a failed sign-up.
      try {
        res.body?.cancel().catch(() => {});
      } catch {
        // a locked or broken body: nothing to free
      }
      return report(options.onError, { reason: "http_status", status: res.status });
    }
    let parsed: unknown;
    try {
      parsed = await res.json();
    } catch {
      if (controller.signal.aborted) return report(options.onError, { reason: "timeout" });
      return report(options.onError, { reason: "bad_response", status: res.status });
    }
    if (!isCheckResponse(parsed)) return report(options.onError, { reason: "bad_response", status: res.status });
    return { ok: true, action: parsed.action, response: parsed };
  } catch {
    // Anything else that goes wrong while handling the answer still allows the sign-up.
    if (controller.signal.aborted) return report(options.onError, { reason: "timeout" });
    return report(options.onError, { reason: "bad_response", status: res.status });
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Whether a check result should stop the sign-up, given the `challenge` setting.
 *
 * @param result A result from {@linkcode checkSignup}.
 * @param challenge What to do with a `"challenge"` answer. Default `"allow"`.
 */
export function shouldBlock(result: CheckResult, challenge: "allow" | "block" = "allow"): boolean {
  return result.action === "block" || (result.action === "challenge" && challenge === "block");
}

function blockError(message: string): APIError {
  return new APIError("BAD_REQUEST", { message, code: "SIGNUP_BLOCKED" });
}

// Paths where a user is created by a provider that has verified the email (OAuth, OIDC, One Tap, SSO).
const PROVIDER_VERIFIED_PATH = /(^|\/)callback(\/|$)|^\/sign-in\/social$|^\/one-tap\//;
// Paths the database hook leaves alone: the email sign-up (the before hook checked it), admin-created users and
// anonymous users (no real email).
const SKIP_PATH = /^\/sign-up\/email$|^\/admin\/|^\/sign-in\/anonymous$/;

type HookCtx = { path?: string; headers?: Headers; request?: Request; body?: unknown } | null | undefined;

function headersOf(ctx: HookCtx): Headers | undefined {
  return ctx?.headers ?? ctx?.request?.headers ?? undefined;
}

const PROVIDER_ID = /^[A-Za-z0-9._:-]{1,40}$/;

/**
 * The provider id for a provider-verified sign-up, sent as `auth_provider`: from `/callback/:id` (social, generic
 * OAuth, SSO), `"google"` for One Tap, the body's `provider` for `/sign-in/social` (ID-token sign-in), else
 * `"oauth"`.
 */
export function providerFromPath(path: string, body?: unknown): string {
  let id: unknown = /\/callback\/([^/?#]+)/.exec(path)?.[1];
  if (id === undefined && /^\/one-tap\//.test(path)) id = "google";
  if (id === undefined && path === "/sign-in/social") id = (body as { provider?: unknown } | undefined)?.provider;
  return typeof id === "string" && PROVIDER_ID.test(id) ? id : "oauth";
}

/**
 * The Better Auth plugin. Add it to `plugins` in your `betterAuth()` config.
 *
 * @param options Your API key and settings. See {@linkcode SignupBouncerOptions}.
 * @returns A Better Auth plugin with the id `"signupbouncer"`.
 */
export function signupBouncer(options: SignupBouncerOptions): BetterAuthPlugin {
  const blockMessage = options.blockMessage ?? DEFAULT_BLOCK_MESSAGE;
  const challenge = options.challenge ?? "allow";
  const ipOf = (ctx: HookCtx): string | undefined => {
    const headers = headersOf(ctx);
    if (options.getIp) {
      try {
        return normalizeIp(options.getIp(ctx?.request ?? undefined, headers));
      } catch {
        return undefined; // a broken getIp must not fail the sign-up
      }
    }
    return clientIp(headers, options.ipHeader, options.trustedProxies);
  };

  const plugin = {
    id: "signupbouncer",
    hooks: {
      before: [
        {
          matcher: (context) => context.path === "/sign-up/email",
          handler: createAuthMiddleware(async (ctx) => {
            const email = (ctx.body as { email?: unknown } | undefined)?.email;
            const headers = headersOf(ctx);
            const ip = ipOf(ctx);
            if (typeof email !== "string" && !ip) return;
            const result = await checkSignup(options, {
              email: typeof email === "string" ? email : undefined,
              ip,
              userAgent: headers?.get("user-agent") ?? undefined,
            });
            if (shouldBlock(result, challenge)) throw blockError(blockMessage);
          }),
        },
      ],
    },
    init: options.checkOtherSignups
      ? () => ({
        options: {
          databaseHooks: {
            user: {
              create: {
                before: async (user: { email?: string | null }, ctx?: HookCtx) => {
                  // No endpoint context means your own server code created the user: not a sign-up to check.
                  const path = ctx?.path;
                  if (!path || SKIP_PATH.test(path)) return;
                  const headers = headersOf(ctx);
                  const ip = ipOf(ctx);
                  // OAuth/SSO: the provider verified the email. Send it with the provider id, so signupbouncer
                  // scores only the IP and signup bursts but still counts the email's domain.
                  const authProvider = PROVIDER_VERIFIED_PATH.test(path)
                    ? providerFromPath(path, ctx?.body)
                    : undefined;
                  const email = user.email ?? undefined;
                  if (!email && !ip) return;
                  const result = await checkSignup(options, {
                    email,
                    ip,
                    userAgent: headers?.get("user-agent") ?? undefined,
                    authProvider,
                  });
                  if (shouldBlock(result, challenge)) throw blockError(blockMessage);
                },
              },
            },
          },
        },
      })
      : undefined,
  } satisfies BetterAuthPlugin;
  return plugin;
}
