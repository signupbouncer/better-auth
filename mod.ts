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
 * Better Auth APIs used (checked 2026-10-14 against the docs and better-auth 1.7.0 and 1.7.7 from npm):
 * - plugin `hooks.before` with `matcher` + `createAuthMiddleware`: https://better-auth.com/docs/concepts/plugins#hooks
 * - throwing `APIError` from a hook: https://better-auth.com/docs/concepts/hooks#errors
 * - `databaseHooks.user.create.before` (returned from the plugin's `init`, as the built-in admin plugin does):
 *   https://better-auth.com/docs/concepts/database#database-hooks. Better Auth passes the endpoint context as the
 *   second argument, with the route pattern in `path` (`/callback/:id`) and the values in `params`.
 *
 * @module
 */

import type { BetterAuthPlugin } from "better-auth";
import { APIError, createAuthMiddleware } from "better-auth/api";
import {
  clientIp,
  type HookCtx,
  isCheckableEmail,
  isCompleteAnswer,
  normalizeIp,
  providerFor,
  readCapped,
} from "./internal.ts";

/** What signupbouncer says to do with a sign-up. In shadow mode this is always `"allow"`. */
export type SignupAction = "allow" | "challenge" | "block";

/** Why a check could not be completed. The sign-up is allowed in every case. */
export type CheckErrorReason =
  | "missing_api_key"
  | "malformed_api_key"
  | "no_input"
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

/** A complete `/v1/check` answer. The plugin acts on one only when every field below is present and well-typed. */
export interface CheckResponse {
  /** The verdict before the app's mode is applied. Never act on it: in shadow mode it can say block. */
  verdict: SignupAction;
  /** What to do: the verdict in enforce mode, always `"allow"` in shadow mode. */
  action: SignupAction;
  /** The app's mode in your signupbouncer dashboard. */
  mode: "shadow" | "enforce";
  /** Risk score; 70 and up blocks with the default thresholds. */
  score: number;
  /** Id of this check in your dashboard log (`chk_...`). */
  check_id: string;
  /** Why the score is what it is. */
  reasons: { code: string; detail: string; points: number; tier: string }[];
  /** What a higher plan would also have flagged. */
  shadow: { code: string; detail: string; tier: string }[];
  /** The mailbox provider, if known, and how often the same inbox signed up in the last 7 days. */
  normalized: { provider: string | null; repeat_signups_7d: number };
  /** The IP's network, or `null` when no usable IP was sent. */
  network: { asn: number | null; asn_org: string | null; kinds: string[]; label: string | null; prefix: string } | null;
  /** Time the check took on signupbouncer's side, in milliseconds. */
  latency_ms: number;
  /** True when the check was skipped because the account is over its monthly limit. The action is then allow. */
  quota_exceeded: boolean;
  /** Fields added to the API later. */
  [key: string]: unknown;
}

/**
 * Result of one check. `action` is always set:
 * - `ok: true`: signupbouncer answered, and `action` is its answer.
 * - `ok: false` with `action: "allow"`: the check failed and the sign-up is allowed (fail open).
 * - `ok: false` with `action: "block"`: the email is longer than 320 characters or is not an address. The API would cut
 *   or reject it, so the plugin refuses it without a request.
 */
export type CheckResult =
  | { ok: true; action: SignupAction; response: CheckResponse }
  | { ok: false; action: "allow"; error: CheckError }
  | { ok: false; action: "block"; error: { reason: "invalid_email" } };

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
   * through a `user.create.before` database hook. An OAuth sign-up whose provider marked the email verified is sent
   * with `auth_provider` (the provider id, such as `"google"`): signupbouncer scores it on IP and signup bursts only and
   * counts the email's domain in your dashboard. One with an unverified email is checked like an email sign-up.
   * Default `false`.
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

/**
 * The `onError` used when you pass none: one `console.warn` line. It holds the fixed reason and the status code only,
 * never the API key, the email, the IP, an exception message or response text.
 */
function warnCheckError(error: CheckError): void {
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

/**
 * Calls `POST {baseUrl}/v1/check`. Never throws. On any failure it returns `action: "allow"` and calls `onError` (or
 * writes one `console.warn` line when there is none). An email longer than 320 characters, or one that is not an
 * address, returns `action: "block"` without a request. Exported so you can run the same check from your own routes.
 *
 * The request does not follow redirects: a 3xx answer counts as a failed check. Only the first 64 KiB of an answer
 * are read, and an answer that completes after `timeoutMs` counts as a timeout.
 *
 * @param options The API key and connection settings, as for {@linkcode signupBouncer}.
 * @param input What to check. Send at least an email or an IP.
 * @returns The action to take, with the API's answer or the reason the check failed.
 */
export async function checkSignup(
  options: Pick<SignupBouncerOptions, "apiKey" | "baseUrl" | "app" | "timeoutMs" | "onError">,
  input: {
    /** The address the person signed up with, exactly as your app saves it. */
    email?: string;
    /** The client IP, if you know it from a header your host overwrites. */
    ip?: string;
    /** The request's User-Agent header. Cut to 512 characters. */
    userAgent?: string;
    /**
     * The OAuth/SSO provider that verified `email` (`"google"`, `"github"`, ...). signupbouncer then scores only the IP
     * and signup bursts and keeps the email's domain for your stats. Send it only when the provider marked the email
     * verified, and leave it out for email/password sign-ups.
     */
    authProvider?: string;
  },
): Promise<CheckResult> {
  if (typeof input.email === "string" && input.email !== "" && !isCheckableEmail(input.email)) {
    return { ok: false, action: "block", error: { reason: "invalid_email" } };
  }
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
  if (!body.email && !body.ip) return report(options.onError, { reason: "no_input" });

  const timeoutMs = timeoutOf(options.timeoutMs);
  const deadline = Date.now() + timeoutMs;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const late = () => controller.signal.aborted || Date.now() > deadline;
  let res: Response;
  try {
    res = await fetch(url, {
      method: "POST",
      headers: { "authorization": `Bearer ${apiKey}`, "content-type": "application/json" },
      body: JSON.stringify(body),
      signal: controller.signal,
      // Never follow a redirect: it could carry the key and the email to another host (Cloudflare Workers forwards
      // Authorization on cross-origin redirects). A 3xx is a failed check below.
      redirect: "manual",
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
    let text: string | { failed: string };
    try {
      text = await readCapped(res, controller.signal);
    } catch {
      return report(options.onError, late() ? { reason: "timeout" } : { reason: "bad_response", status: res.status });
    }
    if (typeof text !== "string") {
      return report(
        options.onError,
        text.failed === "aborted" ? { reason: "timeout" } : { reason: "bad_response", status: res.status },
      );
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      return report(options.onError, { reason: "bad_response", status: res.status });
    }
    if (!isCompleteAnswer(parsed)) return report(options.onError, { reason: "bad_response", status: res.status });
    // An answer that arrived after the deadline is a timeout, even if the timer has not fired yet.
    if (late()) return report(options.onError, { reason: "timeout" });
    const response = parsed as CheckResponse;
    return { ok: true, action: response.action, response };
  } catch {
    // Anything else that goes wrong while handling the answer still allows the sign-up.
    return report(options.onError, late() ? { reason: "timeout" } : { reason: "bad_response", status: res.status });
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

// Paths where a user is created by a provider that may have verified the email (OAuth, OIDC, One Tap, SSO). Better
// Auth gives route patterns here, such as "/callback/:id".
const PROVIDER_PATH = /(^|\/)callback(\/|$)|^\/sign-in\/social$|^\/one-tap\//;
// Paths the database hook leaves alone: admin-created users and anonymous users (no real email).
const SKIP_PATH = /^\/admin\/|^\/sign-in\/anonymous$/;
const EMAIL_SIGNUP = "/sign-up/email";

function headersOf(ctx: HookCtx): Headers | undefined {
  return ctx?.headers ?? ctx?.request?.headers ?? undefined;
}

/**
 * The Better Auth plugin. Add it to `plugins` in your `betterAuth()` config.
 *
 * Email/password sign-ups are checked in two places: a before hook checks the address in the request, and a
 * `user.create.before` database hook checks the user Better Auth is about to save. The second check makes a request
 * only when the saved address differs from the one already checked, for example when another hook rewrote it.
 *
 * @param options Your API key and settings. See {@linkcode SignupBouncerOptions}.
 * @returns A Better Auth plugin with the id `"signupbouncer"`.
 */
export function signupBouncer(options: SignupBouncerOptions): BetterAuthPlugin {
  const blockMessage = options.blockMessage ?? DEFAULT_BLOCK_MESSAGE;
  const challenge = options.challenge ?? "allow";
  // The email the before hook checked and allowed, per request. The database hook skips its own request for the same
  // address. Keyed by the Request (or the Headers when Better Auth is called without one); entries go with the request.
  const allowedEmail = new WeakMap<object, string>();
  const requestKey = (ctx: HookCtx): object | undefined => ctx?.request ?? ctx?.headers ?? undefined;

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

  const enforce = async (ctx: HookCtx, email: string | undefined, authProvider?: string): Promise<void> => {
    const ip = ipOf(ctx);
    if (email === undefined && !ip) return;
    const result = await checkSignup(options, {
      email,
      ip,
      userAgent: headersOf(ctx)?.get("user-agent") ?? undefined,
      authProvider,
    });
    if (shouldBlock(result, challenge)) throw blockError(blockMessage);
  };

  const plugin = {
    id: "signupbouncer",
    hooks: {
      before: [
        {
          matcher: (context) => context.path === EMAIL_SIGNUP,
          handler: createAuthMiddleware(async (ctx) => {
            const email = (ctx.body as { email?: unknown } | undefined)?.email;
            // Better Auth refuses a missing or non-string email itself; the database hook covers the rest.
            if (typeof email !== "string") return;
            await enforce(ctx, email);
            const key = requestKey(ctx);
            if (key) allowedEmail.set(key, email.toLowerCase());
          }),
        },
      ],
    },
    init: () => ({
      options: {
        databaseHooks: {
          user: {
            create: {
              before: async (user: { email?: string | null; emailVerified?: boolean | null }, ctx?: HookCtx) => {
                // No endpoint context means your own server code created the user: not a sign-up to check.
                const path = ctx?.path;
                if (!path || SKIP_PATH.test(path)) return;
                const email = typeof user.email === "string" && user.email !== "" ? user.email : undefined;
                if (path === EMAIL_SIGNUP) {
                  const key = requestKey(ctx);
                  if (email !== undefined && key && allowedEmail.get(key) === email.toLowerCase()) return;
                  return await enforce(ctx, email);
                }
                if (!options.checkOtherSignups) return;
                // A provider that verified the email: send its id, so signupbouncer scores only the IP and signup
                // bursts but still counts the email's domain. An unverified email is checked like any other.
                const authProvider = PROVIDER_PATH.test(path) && user.emailVerified === true
                  ? providerFor(ctx)
                  : undefined;
                return await enforce(ctx, email, authProvider);
              },
            },
          },
        },
      },
    }),
  } satisfies BetterAuthPlugin;
  return plugin;
}
