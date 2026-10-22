/**
 * SignupBouncer plugin for Better Auth. It checks each new email sign-up with SignupBouncer's `/v1/check` API and
 * refuses the ones SignupBouncer says to block. If SignupBouncer is slow, down or sends anything unexpected (including
 * an answer missing a field the API always sends), the sign-up goes through (fail open). A refused sign-up gets HTTP
 * 400 with `{ code: "SIGNUP_BLOCKED", message }`, plus `why_url` when you turn on the "Why was this refused?" link on
 * the Rules tab of your dashboard.
 *
 * Setup guide: https://signupbouncer.com/better-auth. API docs: https://signupbouncer.com/docs.
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
 * The second look at email confirmation (`secondLook`, {@linkcode signupBouncerConfirm}; checked 2026-10-22 against
 * better-auth 1.7.0, 1.7.7 and 1.7.11 from npm, `dist/api/routes/email-verification.mjs`,
 * `dist/plugins/email-otp/routes.mjs`, `dist/db/with-hooks.mjs`, `dist/db/revoke-unproven-account-access.mjs`,
 * `dist/api/dispatch.mjs` and `dist/context/helpers.mjs`):
 * - `GET /verify-email` checks the token (an HS256 JWT signed with `ctx.context.secret`), then marks the address
 *   verified with `internalAdapter.updateUserByEmail(email, { emailVerified: true })`. On an address already verified
 *   it answers without updating anything. Plugin `hooks.after` run after the endpoint, a thrown redirect included.
 * - `emailVerification.beforeEmailVerification(user, request)` runs just before that update, on `/verify-email` and
 *   on the email-OTP plugin's `/email-otp/verify-email` and `/email-otp/change-email` (typed in `@better-auth/core`
 *   `dist/types/init-options.d.mts`). Throwing from it leaves the address unverified. Plugin `init` receives the app's
 *   options, so the plugin can see which function the app passed.
 * - `/sign-in/email-otp` and `/email-otp/reset-password` mark an existing user's address verified with
 *   `internalAdapter.updateUser(id, { emailVerified: true })` without calling `beforeEmailVerification`. That runs
 *   `databaseHooks.user.update.before` with the endpoint context (route pattern in `path`, the request body in `body`).
 *
 * @module
 */

import type { BetterAuthPlugin } from "better-auth";
import { APIError, createAuthMiddleware } from "better-auth/api";
import {
  clientIp,
  configuredSocialProviders,
  firstStandsCode,
  type HookCtx,
  isCheckableEmail,
  isCompleteAnswer,
  isCompleteConfirmAnswer,
  isConfirmBlock,
  normalizeIp,
  readCapped,
  socialProviderFor,
  validWhyUrl,
  verifiedTokenPayload,
} from "./internal.ts";

/** What SignupBouncer says to do with a sign-up. In shadow mode this is always `"allow"`. */
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
  /**
   * `"confirm"` when the call that failed reported an email confirmation (`POST /v1/confirm`, see
   * {@linkcode confirmSignup}); the confirmation has already gone through. Absent for a sign-up check.
   */
  call?: "confirm";
}

/** A complete `/v1/check` answer. The plugin acts on one only when every field below is present and well-typed. */
export interface CheckResponse {
  /** The result before the app's mode is applied. Never act on it: in shadow mode it can say block. */
  verdict: SignupAction;
  /** What to do: the same as `verdict` in enforce mode, always `"allow"` in shadow mode. */
  action: SignupAction;
  /** The app's mode in your SignupBouncer dashboard. */
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
  /** Time the check took on SignupBouncer's side, in milliseconds. */
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
 * - `ok: true`: SignupBouncer answered, and `action` is its answer.
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
  /** Your SignupBouncer API key (`sb_live_...`). Without one, every sign-up is allowed and `onError` is called. */
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
   * How long to wait for SignupBouncer before allowing the sign-up, in milliseconds. Default 1,500. A value that is
   * not a positive number uses the default, and anything above 10,000 is cut to 10,000.
   */
  timeoutMs?: number;
  /**
   * Message returned to the client when a sign-up is blocked. Set here, it wins over the dashboard. Leave it out to use
   * the one SignupBouncer sends, which you set on the Rules tab of your dashboard, or {@linkcode DEFAULT_BLOCK_MESSAGE}
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
   * `email_verified`, Better Auth's own flag that the provider verified the address. When that is `true`, SignupBouncer
   * scores the sign-up on IP and signup bursts only and counts the email's domain in your dashboard; when it is
   * `false`, the email is checked too. Every other sign-up, SSO and generic OAuth included, has its email checked like
   * an email sign-up. Default `false`.
   */
  checkOtherSignups?: boolean;
  /**
   * Report each email confirmation to SignupBouncer for the second look at challenged sign-ups (`POST /v1/confirm`):
   * after each successful click on the link in Better Auth's verification email (`/verify-email`), the plugin sends the
   * address, the User-Agent and, with an IP source, the IP, with `via: "link"`. A click on an address already verified
   * is reported too, so the person's own click counts when a mail scanner opened the link first. Record only: it never
   * refuses a confirmation, whatever the answer, because mail scanners open links too. It runs after Better Auth has
   * answered, and waits at most 1 second (less with a lower `timeoutMs`). To refuse a confirmation on a page of your
   * own with a button, use {@linkcode signupBouncerConfirm}. Default `false`.
   */
  secondLook?: boolean;
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
 * The longest a confirmation report waits for SignupBouncer, in milliseconds. SignupBouncer answers `/v1/confirm`
 * within 500 ms and asks clients to give the call 0.8 to 1 second. A lower `timeoutMs` lowers it.
 */
export const CONFIRM_TIMEOUT_MS = 1000;
/** The message a refused confirmation gets when neither `blockMessage` nor the answer has one. */
export const DEFAULT_CONFIRM_MESSAGE = "We couldn't confirm your email address. Please contact us if you need help.";

/**
 * The `onError` used when you pass none: one `console.warn` line. It holds the fixed reason and the status code only,
 * never the API key, the email, the IP, an exception message or response text.
 */
function warnCheckError(error: CheckError): void {
  const status = typeof error.status === "number" ? ` ${error.status}` : "";
  const confirm = error.call === "confirm";
  const hint = error.reason === "missing_api_key" || error.reason === "malformed_api_key" || error.status === 401
    ? " Check the signupbouncer API key in your config."
    // 403 app_mismatch and 404 unknown_app are the only 403 and 404 /v1/check sends, both about the `app` option.
    // /v1/confirm sends 403 app_mismatch too; its own 404 (unknown_check) is never reported.
    : error.status === 403
    ? " Check the app option: leave it out, or set it to the API key's own app id."
    : error.status === 404 && !confirm
    // Only an older all-apps key gets 404; leaving `app` out would move its checks to the account's first app.
    ? " Check the app option: set it to an app id from this API key's account."
    : "";
  console.warn(
    confirm
      ? `[signupbouncer] confirmation report failed (${error.reason}${status}), confirmation allowed.${hint}`
      : `[signupbouncer] check failed (${error.reason}${status}), sign-up allowed.${hint}`,
  );
}

function timeoutOf(ms: number | undefined): number {
  return typeof ms === "number" && ms > 0 ? Math.min(ms, MAX_TIMEOUT_MS) : DEFAULT_TIMEOUT_MS; // NaN > 0 is false
}

function notify(onError: SignupBouncerOptions["onError"], error: CheckError): void {
  // A broken or slow onError must not fail or delay the sign-up: not awaited, sync throws and rejections ignored.
  try {
    const pending: unknown = (onError ?? warnCheckError)(error);
    if (pending && typeof (pending as PromiseLike<unknown>).then === "function") {
      Promise.resolve(pending).catch(() => {});
    }
  } catch {
    // ignored
  }
}

function report(onError: SignupBouncerOptions["onError"], error: CheckError): CheckResult {
  notify(onError, error);
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
     * SignupBouncer knows the provider does it score just the IP and signup bursts, keeping the email's domain for your
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
 * The message to show a refused sign-up: the `block_message` SignupBouncer sent with the answer (set on the Rules tab
 * of your dashboard), or {@linkcode DEFAULT_BLOCK_MESSAGE} when there is none, such as for an email refused locally.
 *
 * @param result A result from {@linkcode checkSignup}.
 */
export function blockMessage(result: CheckResult): string {
  return messageOrUndefined(result.ok ? result.response.block_message : undefined) ?? DEFAULT_BLOCK_MESSAGE;
}

/**
 * The "Why was this refused?" link to show after {@linkcode blockMessage}: SignupBouncer's page about the email's
 * domain. SignupBouncer sends it with a block or challenge answer only when you turn the link on in the Rules tab of
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

// ---- Second look at email confirmation (POST /v1/confirm) ----------------------------------------------------------

/**
 * How the person confirmed their address:
 * - `"link"`: the click on the emailed link confirmed it by itself. Mail scanners open links too, so SignupBouncer
 *   never scores that request's IP or browser, and the plugin never refuses a link confirmation.
 * - `"button"`: the person pressed a button on a page of your own (the emailed link opens the page; the button calls
 *   `authClient.verifyEmail`).
 * - `"code"`: the person typed a code, such as with Better Auth's email OTP plugin.
 */
export type ConfirmVia = "link" | "button" | "code";

/** A complete `/v1/confirm` answer. The plugin acts on one only when every field below is present and well-typed. */
export interface ConfirmResponse {
  /** The result before the app's mode is applied. Never act on it: in shadow mode it can say block. */
  verdict: "allow" | "block";
  /** What to do: the same as `verdict` in enforce mode, always `"allow"` in shadow mode. */
  action: "allow" | "block";
  /** The app's mode in your SignupBouncer dashboard. */
  mode: "shadow" | "enforce";
  /** Risk score after the second look (or the first check's, when there was none). */
  score: number;
  /** Id of the sign-up's check in your dashboard log (`chk_...`). `null` in an error answer that found none. */
  check_id: string | null;
  /** The first check's result and score. `null` in an error answer. */
  first: { verdict: SignupAction; score: number } | null;
  /** The first check's reasons and the new ones. */
  reasons: { code: string; detail: string; points: number; tier: string }[];
  /** What a higher plan would also have flagged. */
  shadow: { code: string; detail: string; tier: string }[];
  /** True when this check got a second look. Only a challenged sign-up that was let through gets one. */
  second_look: boolean;
  /** True when an earlier report of the same check already had the second look, and this is its answer again. */
  replayed: boolean;
  /** Time the report took on SignupBouncer's side, in milliseconds. */
  latency_ms: number;
  /** Sent with a block: the message from the Rules tab of your dashboard, or a neutral default. */
  block_message?: string;
  /** `"internal_error"` when something failed on SignupBouncer's side. The answer is then an allow. */
  error?: string;
  /** Fields added to the API later. */
  [key: string]: unknown;
}

/**
 * Result of one confirmation report. `action` is the plugin's decision:
 * - `ok: true`: SignupBouncer answered. `action` is `"block"` only for a `"button"` or `"code"` confirmation whose
 *   answer is a complete enforce-mode block from a second look; otherwise `"allow"`, including every `"link"` one.
 * - `ok: false`: the report failed, or SignupBouncer has no second look for it (404 `unknown_check`, 410
 *   `check_expired`, which do not call `onError`). The confirmation goes through.
 */
export type ConfirmResult =
  | { ok: true; action: "allow" | "block"; response: ConfirmResponse }
  | { ok: false; action: "allow"; error: CheckError };

function confirmFailed(onError: SignupBouncerOptions["onError"], error: CheckError, quiet = false): ConfirmResult {
  const e: CheckError = { ...error, call: "confirm" };
  if (!quiet) notify(onError, e);
  return { ok: false, action: "allow", error: e };
}

/**
 * Calls `POST {baseUrl}/v1/confirm` to report an email confirmation, for the second look at challenged sign-ups.
 * Never throws. SignupBouncer looks at a challenged sign-up again with the confirming request and answers allow or
 * block; any other sign-up keeps its first answer. Exported so you can report confirmations from your own routes.
 *
 * Fails open like {@linkcode checkSignup}: a timeout, a network error, a non-2xx answer or an unreadable or incomplete
 * answer returns `action: "allow"` and calls `onError` (with `call: "confirm"`). A 404 `unknown_check` (no sign-up of
 * this address or check id in the last 72 hours on this key's app) and a 410 `check_expired` return `action: "allow"`
 * without calling `onError`. It waits at most {@linkcode CONFIRM_TIMEOUT_MS} (1 second), or `timeoutMs` when lower.
 * The request does not follow redirects, and only the first 64 KiB of an answer are read.
 *
 * @param options The API key and connection settings, as for {@linkcode signupBouncer}.
 * @param input The confirmed address (or the `check_id` from `/v1/check`), the confirming request's IP and/or
 *   User-Agent, and how the person confirmed. With neither an address nor a check id, or neither an IP nor a
 *   User-Agent, nothing is sent (`onError` "no_input").
 * @returns The action to take, with the API's answer or the reason the report failed.
 */
export async function confirmSignup(
  options: Pick<SignupBouncerOptions, "apiKey" | "baseUrl" | "app" | "timeoutMs" | "onError">,
  input: {
    /** The address that was confirmed, as your app saves it. */
    email?: string;
    /** The `check_id` `/v1/check` answered for this sign-up, if you kept it. It wins over `email`. */
    checkId?: string;
    /** The IP of the request that confirmed, from a header your host overwrites. */
    ip?: string;
    /** The User-Agent header of the request that confirmed. Cut to 512 characters. */
    userAgent?: string;
    /** How the person confirmed. Default (and for any other value) `"link"`, which never refuses. */
    via?: ConfirmVia;
  },
): Promise<ConfirmResult> {
  const onError = options.onError;
  const apiKey = options.apiKey?.trim() ?? "";
  if (!apiKey) return confirmFailed(onError, { reason: "missing_api_key" });
  // A key with a newline or other junk pasted in: fetch would reject the header and quote the key in its error.
  if (!/^[\x21-\x7e]+$/.test(apiKey)) return confirmFailed(onError, { reason: "malformed_api_key" });
  const via: ConfirmVia = input.via === "button" || input.via === "code" ? input.via : "link";
  const body: Record<string, string> = { via };
  if (typeof input.checkId === "string" && input.checkId) body.check_id = input.checkId;
  if (typeof input.email === "string" && input.email) body.email = input.email;
  if (typeof input.ip === "string" && input.ip) body.ip = input.ip;
  if (typeof input.userAgent === "string" && input.userAgent) body.user_agent = input.userAgent.slice(0, 512);
  if (options.app) body.app = options.app;
  // The API needs a check id or an address, and the confirming request's IP or User-Agent (400 invalid_body).
  if ((!body.check_id && !body.email) || (!body.ip && !body.user_agent)) {
    return confirmFailed(onError, { reason: "no_input" });
  }

  const timeoutMs = Math.min(timeoutOf(options.timeoutMs), CONFIRM_TIMEOUT_MS);
  const deadline = Date.now() + timeoutMs;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const late = () => controller.signal.aborted || Date.now() > deadline;
  const url = (options.baseUrl ?? DEFAULT_BASE_URL).replace(/\/+$/, "") + "/v1/confirm";
  let res: Response;
  try {
    res = await fetch(url, {
      method: "POST",
      headers: { "authorization": `Bearer ${apiKey}`, "content-type": "application/json" },
      body: JSON.stringify(body),
      signal: controller.signal,
      redirect: "manual", // as in checkSignup: a redirect is a failed report, and the key goes nowhere else
    });
  } catch {
    clearTimeout(timer);
    return confirmFailed(onError, { reason: controller.signal.aborted ? "timeout" : "network" });
  }
  try {
    let text: string | { failed: string };
    if (!res.ok) {
      // 404 unknown_check and 410 check_expired mean "no second look, the first answer stands": not a failure.
      if (res.status === 404 || res.status === 410) {
        try {
          text = await readCapped(res, controller.signal);
        } catch {
          text = "";
        }
        const code = typeof text === "string" ? firstStandsCode(text) : undefined;
        const quiet = (res.status === 404 && code === "unknown_check") ||
          (res.status === 410 && code === "check_expired");
        return confirmFailed(onError, { reason: "http_status", status: res.status }, quiet);
      }
      try {
        res.body?.cancel().catch(() => {});
      } catch {
        // a locked or broken body: nothing to free
      }
      return confirmFailed(onError, { reason: "http_status", status: res.status });
    }
    try {
      text = await readCapped(res, controller.signal);
    } catch {
      return confirmFailed(onError, late() ? { reason: "timeout" } : { reason: "bad_response", status: res.status });
    }
    if (typeof text !== "string") {
      return confirmFailed(
        onError,
        text.failed === "aborted" ? { reason: "timeout" } : { reason: "bad_response", status: res.status },
      );
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      return confirmFailed(onError, { reason: "bad_response", status: res.status });
    }
    if (!isCompleteConfirmAnswer(parsed)) return confirmFailed(onError, { reason: "bad_response", status: res.status });
    // An answer that arrived after the deadline is a timeout: the person has been let through already.
    if (late()) return confirmFailed(onError, { reason: "timeout" });
    const response = parsed as ConfirmResponse;
    if (messageOrUndefined(response.block_message) === undefined) delete response.block_message;
    // A link confirmation is record only: mail scanners open links, so its answer never refuses anyone.
    const block = via !== "link" && isConfirmBlock(response);
    return { ok: true, action: block ? "block" : "allow", response };
  } catch {
    return confirmFailed(onError, late() ? { reason: "timeout" } : { reason: "bad_response", status: res.status });
  } finally {
    clearTimeout(timer);
  }
}

/**
 * The message to show a refused confirmation: the `block_message` SignupBouncer sent with the answer (set on the Rules
 * tab of your dashboard), or {@linkcode DEFAULT_CONFIRM_MESSAGE} when there is none.
 *
 * @param result A result from {@linkcode confirmSignup}.
 */
export function confirmBlockMessage(result: ConfirmResult): string {
  return messageOrUndefined(result.ok ? result.response.block_message : undefined) ?? DEFAULT_CONFIRM_MESSAGE;
}

/**
 * Addresses {@linkcode signupBouncerConfirm} reported in the last few seconds (lower-cased, with when the entry
 * expires), so the plugin's own `secondLook` report of the same `/verify-email` request skips them. Keyed by address
 * rather than by request because a server-side `auth.api.verifyEmail` call has headers but no Request.
 */
const recentConfirms = new Map<string, number>();
const RECENT_CONFIRM_MS = 10_000;

function rememberConfirm(email: string): void {
  const now = Date.now();
  // Oldest first: drop expired entries so the map stays small.
  for (const [key, expires] of recentConfirms) {
    if (expires > now) break;
    recentConfirms.delete(key);
  }
  const key = email.toLowerCase();
  recentConfirms.delete(key);
  recentConfirms.set(key, now + RECENT_CONFIRM_MS);
}

/** True, once, when {@linkcode signupBouncerConfirm} reported `email` in the last few seconds. */
function takeConfirm(email: string): boolean {
  const key = email.toLowerCase();
  const expires = recentConfirms.get(key);
  if (expires === undefined) return false;
  recentConfirms.delete(key);
  return expires > Date.now();
}

// The email-OTP plugin's email change also runs beforeEmailVerification: a change of address, not a sign-up. Better
// Auth's router (better-call) refuses double slashes and accepts one trailing slash with
// `advanced.skipTrailingSlashes`, so both spellings of the route end this way.
const EMAIL_CHANGE = /\/email-otp\/change-email\/?$/;

type ConfirmHookOptions = SignupBouncerOptions & { via: "button" | "code" };
/** The options of each function {@linkcode signupBouncerConfirm} returned, so the plugin can recognise one. */
const confirmHooks = new WeakMap<object, ConfirmHookOptions>();

/** Reports a confirmation the person made themselves, and throws the refusal when a second look says block. */
async function refuseIfBlocked(
  options: ConfirmHookOptions,
  input: { email: string; ip?: string; userAgent?: string; via: ConfirmVia },
): Promise<void> {
  const result = await confirmSignup(options, input);
  if (result.action === "block") {
    throw new APIError("FORBIDDEN", {
      message: options.blockMessage ?? confirmBlockMessage(result),
      code: "SIGNUP_BLOCKED",
    });
  }
}

function requestPath(request: Request | undefined): string {
  try {
    return request ? new URL(request.url).pathname : "";
  } catch {
    return "";
  }
}

/**
 * A second look that can refuse the confirmation, for Better Auth's `emailVerification.beforeEmailVerification`. Use
 * it only when the person's own action confirms the address: your verification email links to a page of your own
 * whose button calls `authClient.verifyEmail` (`via: "button"`), or the person types a code from the email OTP plugin
 * (`via: "code"`). Better Auth runs it just before it marks the address verified; on a refusal it throws `APIError`
 * 403 `{ code: "SIGNUP_BLOCKED", message }` and the address stays unverified. Every failure lets the confirmation
 * through, and in shadow mode nothing is refused.
 *
 * Do not use it when the emailed link goes straight to Better Auth's `/verify-email`: that click is not a button press,
 * and mail scanners open links too. Use the plugin's `secondLook: true` there, which only records.
 *
 * ```ts
 * const sb = { apiKey: process.env.SIGNUPBOUNCER_API_KEY!, ipHeader: "cf-connecting-ip" };
 * export const auth = betterAuth({
 *   emailVerification: {
 *     sendVerificationEmail, // your own: its link opens your page with the button
 *     beforeEmailVerification: signupBouncerConfirm({ ...sb, via: "button" }),
 *   },
 *   plugins: [signupBouncer(sb)],
 * });
 * ```
 *
 * Better Auth's email OTP plugin also marks an address verified on `/sign-in/email-otp` and
 * `/email-otp/reset-password` without calling `beforeEmailVerification`. When you pass the function this returns as
 * `beforeEmailVerification` itself (not wrapped in a function of your own), the plugin recognises it and checks those
 * two routes too, as typed codes, so a refused person cannot verify the address there instead.
 *
 * @param options Your API key and settings, as for {@linkcode signupBouncer}, and `via`: how the person confirms.
 *   A `via` other than `"button"` or `"code"` reports `"link"` and never refuses.
 * @returns The function to pass as `beforeEmailVerification`.
 */
export function signupBouncerConfirm(
  options: SignupBouncerOptions & { via: "button" | "code" },
): (user: { email: string }, request?: Request) => Promise<void> {
  const hook = async (user: { email: string }, request?: Request): Promise<void> => {
    if (EMAIL_CHANGE.test(requestPath(request))) return;
    const email = typeof user?.email === "string" && user.email !== "" ? user.email : undefined;
    const headers = request?.headers;
    const ip = ipFrom(options, request, headers);
    const userAgent = headers?.get("user-agent") ?? undefined;
    if (email === undefined || (!ip && !userAgent)) return;
    rememberConfirm(email);
    await refuseIfBlocked(options, { email, ip, userAgent, via: options.via });
  };
  confirmHooks.set(hook, options);
  return hook;
}

// The error a refused sign-up gets: HTTP 400 with { code, message } and, when the answer carries the "Why was this
// refused?" link, why_url next to them (the same field name as SignupBouncer's copy-paste Better Auth hook).
function blockError(message: string, why: string | null): APIError {
  return new APIError("BAD_REQUEST", { message, code: "SIGNUP_BLOCKED", ...(why ? { why_url: why } : {}) });
}
// Paths the database hook leaves alone: admin-created users and anonymous users (no real email).
const SKIP_PATH = /^\/admin\/|^\/sign-in\/anonymous$/;
const EMAIL_SIGNUP = "/sign-up/email";

// Where Better Auth's GET /verify-email marks the address verified (the link in its verification email).
const VERIFY_EMAIL = "/verify-email";
// Email OTP routes that mark an existing user's address verified without calling beforeEmailVerification
// (better-auth dist/plugins/email-otp/routes.mjs: signInEmailOTP through revokeUnprovenAccountAccess, and
// resetPasswordEmailOTP), both after checking a code the person typed.
const OTP_VERIFYING_PATHS = new Set(["/sign-in/email-otp", "/email-otp/reset-password"]);

/** The parts of the `/verify-email` endpoint context the `secondLook` report reads. */
type VerifyCtx = HookCtx & {
  query?: { token?: unknown };
  context?: {
    secret?: unknown;
    internalAdapter?: {
      findUserByEmail?: (email: string) => Promise<{ user?: { email?: unknown; emailVerified?: unknown } } | null>;
    };
  };
};

function headersOf(ctx: HookCtx): Headers | undefined {
  return ctx?.headers ?? ctx?.request?.headers ?? undefined;
}

/** The client IP from `getIp`, or else from `ipHeader`; `undefined` when there is none or `getIp` throws. */
function ipFrom(
  options: Pick<SignupBouncerOptions, "getIp" | "ipHeader" | "trustedProxies">,
  request: Request | undefined,
  headers: Headers | undefined,
): string | undefined {
  if (options.getIp) {
    try {
      return normalizeIp(options.getIp(request, headers));
    } catch {
      return undefined; // a broken getIp must not fail the sign-up
    }
  }
  return clientIp(headers, options.ipHeader, options.trustedProxies);
}

/**
 * The Better Auth plugin. Add it to `plugins` in your `betterAuth()` config.
 *
 * Email/password sign-ups are checked in two places: a before hook checks the address in the request, and a
 * `user.create.before` database hook checks the user Better Auth is about to save. The second check makes a request
 * only when the saved address differs from the one already checked, for example when another hook rewrote it.
 *
 * With `secondLook: true`, an after hook on `/verify-email` reports each successful click on Better Auth's
 * verification link, including a later click on an address already verified (when a mail scanner opened the link
 * first). It never refuses anything. When the app's `beforeEmailVerification` is a function from
 * {@linkcode signupBouncerConfirm}, a `user.update.before` database hook also checks the email OTP routes that verify
 * an address without calling it.
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

  const ipOf = (ctx: HookCtx): string | undefined => ipFrom(options, ctx?.request ?? undefined, headersOf(ctx));

  // secondLook: record only, after the endpoint has run. Each click on a valid link whose address is now verified is
  // reported, also when the address was verified already: a mail scanner's GET may have verified it first, and then
  // Better Auth answers the person's own click without updating the user, and SignupBouncer keeps nothing from a
  // scanner's report. The answer is never acted on, and nothing here may throw.
  const reportLinkClick = async (ctx: VerifyCtx): Promise<void> => {
    try {
      // Only a token Better Auth itself accepted names the address; an email change (updateTo) is not a sign-up.
      const payload = await verifiedTokenPayload(ctx?.query?.token, ctx?.context?.secret);
      if (!payload || typeof payload.email !== "string" || payload.email === "" || payload.updateTo !== undefined) {
        return;
      }
      // signupBouncerConfirm already reported this confirmation in beforeEmailVerification.
      if (takeConfirm(payload.email)) return;
      const ip = ipOf(ctx);
      const userAgent = headersOf(ctx)?.get("user-agent") ?? undefined;
      // The API needs the IP or the User-Agent; server code verifying without a request has neither.
      if (!ip && !userAgent) return;
      const found = await ctx?.context?.internalAdapter?.findUserByEmail?.(payload.email);
      const user = found?.user;
      // Not verified: the link failed, or signupBouncerConfirm refused it.
      if (user?.emailVerified !== true || typeof user.email !== "string" || user.email === "") return;
      await confirmSignup(options, { email: user.email, ip, userAgent, via: "link" });
    } catch {
      // a confirmation never fails because of the report
    }
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
      ...(options.secondLook
        ? {
          after: [
            {
              matcher: (context: { path?: string }) => context.path === VERIFY_EMAIL,
              handler: createAuthMiddleware(async (ctx) => {
                await reportLinkClick(ctx as unknown as VerifyCtx);
              }),
            },
          ],
        }
        : {}),
    },
    init: (authCtx?: unknown) => {
      // Read once, from the providers Better Auth resolved at start-up: they are fixed while it runs.
      const social = options.checkOtherSignups ? configuredSocialProviders(authCtx) : new Set<string>();
      // The app's beforeEmailVerification, when it is a function from signupBouncerConfirm (passed directly).
      const appHook = (authCtx as { options?: { emailVerification?: { beforeEmailVerification?: unknown } } } | null)
        ?.options?.emailVerification?.beforeEmailVerification;
      const guard = typeof appHook === "function" ? confirmHooks.get(appHook) : undefined;
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
                  // provider, so SignupBouncer can score only the IP and signup bursts when the provider verified the
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
              ...(guard
                ? {
                  update: {
                    // Email OTP sign-in and password reset verify an existing user's address without calling
                    // beforeEmailVerification, so a person signupBouncerConfirm refused could verify there instead.
                    // Each is a typed code: the same report and refusal, before the address is marked verified.
                    before: async (data: Record<string, unknown>, ctx?: HookCtx) => {
                      if (typeof data !== "object" || data === null || data.emailVerified !== true) return;
                      if (!ctx?.path || !OTP_VERIFYING_PATHS.has(ctx.path)) return;
                      const raw = (ctx.body as { email?: unknown } | undefined)?.email;
                      if (typeof raw !== "string" || raw === "") return;
                      const ip = ipFrom(guard, ctx.request ?? undefined, headersOf(ctx));
                      const userAgent = headersOf(ctx)?.get("user-agent") ?? undefined;
                      if (!ip && !userAgent) return;
                      await refuseIfBlocked(guard, { email: raw.toLowerCase(), ip, userAgent, via: "code" });
                    },
                  },
                }
                : {}),
            },
          },
        },
      };
    },
  } satisfies BetterAuthPlugin;
  return plugin;
}
