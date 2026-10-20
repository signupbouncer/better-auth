/**
 * signupbouncer plugin for Better Auth. It checks each new email sign-up with signupbouncer's `/v1/check` API and
 * refuses the ones signupbouncer says to block. If signupbouncer is slow, down or sends anything unexpected (including
 * an answer missing a field the API always sends), the sign-up goes through (fail open). A refused sign-up gets HTTP
 * 400 with `{ code: "SIGNUP_BLOCKED", message }`, plus `why_url` when you turn on the "Why was this refused?" link on
 * the Rules tab of your dashboard.
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
  configuredSocialProviders,
  type HookCtx,
  isCheckableEmail,
  isCompleteAnswer,
  normalizeIp,
  readCapped,
  socialProviderFor,
  validWhyUrl,
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
  /** The result before the app's mode is applied. Never act on it: in shadow mode it can say block. */
  verdict: SignupAction;
  /** What to do: the same as `verdict` in enforce mode, always `"allow"` in shadow mode. */
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
  /**
   * Sent only with a block or challenge answer: the message from the Rules tab of your dashboard, or, while you keep
   * the default there, one worded for the reason (such as "Did you mean ...?" for a typo domain).
   */
  block_message?: string;
  /**
   * Sent with `block_message` only when you turn on "Add a 'Why was this refused?' link" on the Rules tab of your
   * dashboard: SignupBouncer's page about the email's domain (`/why/<domain>`). Show it after the message. The plugin
   * drops a value that is not a well-formed http(s) URL, so when present it is always one.
   */
  why_url?: string;
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
  /**
   * Leave it out: an API key belongs to one app, and its checks are logged under that app. If set, it must be the key's
   * own app id (`app_...`). Another app's id gets HTTP 403 `app_mismatch`, a failed check, so every sign-up is allowed.
   * Only older keys, labelled "all apps (older key)" in the dashboard, use it to pick the app (default: your first
   * app).
   */
  app?: string;
  /**
   * How long to wait for signupbouncer before allowing the sign-up, in milliseconds. Default 1,500. A value that is
   * not a positive number uses the default, and anything above 10,000 is cut to 10,000.
   */
  timeoutMs?: number;
  /**
   * Message returned to the client when a sign-up is blocked. Set here, it wins over the dashboard. Leave it out to use
   * the one signupbouncer sends, which you set on the Rules tab of your dashboard, or {@linkcode DEFAULT_BLOCK_MESSAGE}
   * when there is none, such as for an email the plugin refuses without a request (see {@linkcode blockMessage}).
   */
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
   * through a `user.create.before` database hook. A sign-up through one of your `socialProviders` (Google, GitHub and
   * the other providers built into Better Auth) is sent with `auth_provider` (the provider id, such as `"google"`) and
   * `email_verified`, Better Auth's own flag that the provider verified the address. When that is `true`, signupbouncer
   * scores the sign-up on IP and signup bursts only and counts the email's domain in your dashboard; when it is
   * `false`, the email is checked too. Every other sign-up, SSO and generic OAuth included, has its email checked like
   * an email sign-up. Default `false`.
   */
  checkOtherSignups?: boolean;
}

/** The API origin used when `baseUrl` is not set. */
export const DEFAULT_BASE_URL = "https://signupbouncer.com";
/** How long a check waits by default before the sign-up is allowed anyway, in milliseconds. */
export const DEFAULT_TIMEOUT_MS = 1500;
/** The longest `timeoutMs` accepted, in milliseconds. Longer values are cut to this. */
export const MAX_TIMEOUT_MS = 10_000;
/** The message a blocked sign-up gets when neither `blockMessage` nor the answer has one. */
export const DEFAULT_BLOCK_MESSAGE = "Please sign up with a permanent email address.";

/**
 * The `onError` used when you pass none: one `console.warn` line. It holds the fixed reason and the status code only,
 * never the API key, the email, the IP, an exception message or response text.
 */
function warnCheckError(error: CheckError): void {
  const status = typeof error.status === "number" ? ` ${error.status}` : "";
  const hint = error.reason === "missing_api_key" || error.reason === "malformed_api_key" || error.status === 401
    ? " Check the signupbouncer API key in your config."
    // 403 app_mismatch and 404 unknown_app are the only 403 and 404 /v1/check sends, both about the `app` option.
    : error.status === 403
    ? " Check the app option: leave it out, or set it to the API key's own app id."
    : error.status === 404
    // Only an older all-apps key gets 404; leaving `app` out would move its checks to the account's first app.
    ? " Check the app option: set it to an app id from this API key's account."
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
     * For OAuth/SSO sign-ups: the provider id (`"google"`, `"github"`, ...). Send it with `emailVerified`, and leave
     * it out for email/password sign-ups.
     */
    authProvider?: string;
    /**
     * With `authProvider`: your auth library's own flag that the provider verified `email` (Better Auth's
     * `user.emailVerified` from the OAuth profile), never something the user typed. Only when it is `true` and
     * signupbouncer knows the provider does it score just the IP and signup bursts, keeping the email's domain for your
     * stats; missing or `false`, the email is checked too.
     */
    emailVerified?: boolean;
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
  const body: Record<string, string | boolean> = {};
  if (input.email) body.email = input.email;
  if (input.ip) body.ip = input.ip;
  if (input.userAgent) body.user_agent = input.userAgent.slice(0, 512);
  if (input.authProvider) body.auth_provider = input.authProvider;
  if (input.emailVerified === true || input.emailVerified === false) body.email_verified = input.emailVerified;
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
    // block_message is optional and only ever shown: drop one that is not a message worth showing, rather than fail
    // the check, so `response.block_message` is always a usable string or absent.
    if (messageOrUndefined(response.block_message) === undefined) delete response.block_message;
    // The same for why_url: a value that is not a well-formed http(s) link is dropped, never shown.
    if (validWhyUrl(response.why_url) === undefined) delete response.why_url;
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

/**
 * The message to show a refused sign-up: the `block_message` signupbouncer sent with the answer (set on the Rules tab
 * of your dashboard), or {@linkcode DEFAULT_BLOCK_MESSAGE} when there is none, such as for an email refused locally.
 *
 * @param result A result from {@linkcode checkSignup}.
 */
export function blockMessage(result: CheckResult): string {
  return messageOrUndefined(result.ok ? result.response.block_message : undefined) ?? DEFAULT_BLOCK_MESSAGE;
}

/**
 * The "Why was this refused?" link to show after {@linkcode blockMessage}: SignupBouncer's page about the email's
 * domain. signupbouncer sends it with a block or challenge answer only when you turn the link on in the Rules tab of
 * your dashboard. Otherwise, for a failed check and for an email refused locally, it is `null`. Only a well-formed
 * http(s) URL with a host counts, returned unchanged.
 *
 * @param result A result from {@linkcode checkSignup}.
 */
export function whyUrl(result: CheckResult): string | null {
  return validWhyUrl(result.ok ? result.response.why_url : undefined) ?? null;
}

// A message worth showing: a non-blank string of at most 500 characters (the dashboard allows 200).
function messageOrUndefined(m: unknown): string | undefined {
  return typeof m === "string" && m.trim() !== "" && m.length <= 500 ? m : undefined;
}

// The error a refused sign-up gets: HTTP 400 with { code, message } and, when the answer carries the "Why was this
// refused?" link, why_url next to them (the same field name as SignupBouncer's copy-paste Better Auth hook).
function blockError(message: string, why: string | null): APIError {
  return new APIError("BAD_REQUEST", { message, code: "SIGNUP_BLOCKED", ...(why ? { why_url: why } : {}) });
}
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

  const enforce = async (
    ctx: HookCtx,
    email: string | undefined,
    provider?: { authProvider: string; emailVerified: boolean },
  ): Promise<void> => {
    const ip = ipOf(ctx);
    if (email === undefined && !ip) return;
    const result = await checkSignup(options, {
      email,
      ip,
      userAgent: headersOf(ctx)?.get("user-agent") ?? undefined,
      authProvider: provider?.authProvider,
      emailVerified: provider?.emailVerified,
    });
    // The link follows the dashboard setting, so it is passed on with a blockMessage set in code too.
    if (shouldBlock(result, challenge)) throw blockError(options.blockMessage ?? blockMessage(result), whyUrl(result));
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
    init: async (authCtx?: { options?: unknown }) => {
      // Read once: the app's socialProviders and plugins are fixed when Better Auth starts.
      const social = options.checkOtherSignups ? await configuredSocialProviders(authCtx?.options) : new Set<string>();
      return {
        options: {
          databaseHooks: {
            user: {
              create: {
                before: async (user: { email?: string | null; emailVerified?: unknown }, ctx?: HookCtx) => {
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
                  // One of the app's own social providers: send its id with Better Auth's emailVerified from the
                  // provider, so signupbouncer can score only the IP and signup bursts when the provider verified the
                  // address, and still count the email's domain. Anything else, SSO and generic OAuth included, has its
                  // email checked.
                  const authProvider = socialProviderFor(ctx, social);
                  return await enforce(
                    ctx,
                    email,
                    authProvider ? { authProvider, emailVerified: user.emailVerified === true } : undefined,
                  );
                },
              },
            },
          },
        },
      };
    },
  } satisfies BetterAuthPlugin;
  return plugin;
}
