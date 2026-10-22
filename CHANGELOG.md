# Changelog

## 0.3.0 (unreleased)

The plugin can now tell SignupBouncer when a user clicks the link in Better Auth's verification email, so a challenged
sign-up gets SignupBouncer's second look at email confirmation. It only records: it never refuses a confirmation, and it
is off until you set `secondLook: true`. Apps whose verification email opens a page of their own with a button, or that
use email OTP codes, can let the second look refuse a confirmation with `signupBouncerConfirm`.

- **`secondLook: true`** (default `false`, so upgrading sends nothing new). After each successful click on Better Auth's
  verification link (`GET /verify-email`), the plugin sends `POST /v1/confirm` with the address, the User-Agent, the
  client IP when you configure a source for it, and `via: "link"`. A click on an address already verified counts too, so
  the person's own click is reported when a mail scanner opened the link first. It never acts on the answer, because
  mail scanners open links too. The click waits at most 1 second (`CONFIRM_TIMEOUT_MS`, or `timeoutMs` when lower), and
  any failure lets it through. An email change, or a token Better Auth would refuse, sends nothing.
- **`signupBouncerConfirm({ ...options, via: "button" | "code" })`**, for Better Auth's
  `emailVerification.beforeEmailVerification`. When a complete enforce-mode answer from a second look says block, it
  throws HTTP 403 `{ code: "SIGNUP_BLOCKED", message }` and the address stays unverified. Shadow mode, a check with no
  second look, a timeout and any error let the confirmation through. It skips the email OTP plugin's email change (with
  or without a trailing slash). Passed directly as `beforeEmailVerification`, the plugin recognises it and also checks
  email OTP sign-in and password reset, which verify an address without calling `beforeEmailVerification`. With
  `secondLook: true` as well, each confirmation is reported once, server-side `auth.api` calls included.
- **`confirmSignup(options, input)`** and **`confirmBlockMessage(result)`**: the same report from your own routes. It
  never throws; with `via: "link"` (the default) its `action` is always `"allow"`.
- **`onError` for reports.** A failed report calls `onError` with `call: "confirm"`, and the default warning says
  "confirmation report failed ..., confirmation allowed." A 404 `unknown_check` or 410 `check_expired` (no sign-up of
  that address in the last 72 hours) is the first answer standing and calls no `onError`.
- New exports: `ConfirmVia`, `ConfirmResponse`, `ConfirmResult`, `CONFIRM_TIMEOUT_MS`, `DEFAULT_CONFIRM_MESSAGE`, and
  `call` on `CheckError`.

## 0.2.1

A user whose address has a quoted part with a space, such as `"first last"@company.co.uk`, is no longer refused before
SignupBouncer is asked. Releases now reach npm without a stored npm token. The npm listing names SignupBouncer and links
to https://signupbouncer.com.

- **Quoted addresses are checked.** 0.2.0 refused any address with a space without a request, so an OAuth user with a
  quoted address (with `checkOtherSignups: true`) got `SIGNUP_BLOCKED`. The plugin now refuses only what SignupBouncer
  would trim, cut or read differently: more than 320 characters, whitespace at either end, control characters, no text
  on one side of the last `@`, or whitespace in the domain or in an unquoted local part. Everything else is sent and
  checked. On `/sign-up/email`, Better Auth still refuses a quoted address as an invalid email, after the check.
- **Setup guide links.** The README and the module doc JSR shows link https://signupbouncer.com/better-auth.
- **SignupBouncer** with both capitals in the doc comments JSR shows.
- npm `author` is now `SignupBouncer` (was `Final Dynamics LLC`; the licence still names the company that holds the
  copyright) and `homepage` is the home page (was `/docs`).
- **Release workflow** (signupbouncer/better-auth#3): the npm job stages each version with npm trusted publishing
  (GitHub OIDC) and holds no npm token; a version goes live on npm once approved on npmjs.com. The job receives one
  packed tarball from the build job, checks it, writes a clean copy from what it checked, and runs npm in a folder
  holding only that copy, so nothing the build writes can become npm configuration.

## 0.2.0

A Google, GitHub or other built-in OAuth sign-up whose address the provider verified is no longer refused by an email
rule: the plugin now tells SignupBouncer the provider verified it. A refused sign-up can also carry the "Why was this
refused?" link you turn on in your dashboard.

- **OAuth sign-ups send `email_verified`** (with `checkOtherSignups: true`). A sign-up through one of your
  `socialProviders` sends `auth_provider` and `email_verified`, Better Auth's own `emailVerified` flag from the
  provider. With `true`, SignupBouncer scores only the IP and signup bursts. 0.1.0 sent `auth_provider` alone, which the
  API treats as unverified, so a verified user with an address an email rule matches was refused.
- **Only your own built-in social providers count.** Generic OAuth and SSO sign-ups no longer send `auth_provider`, and
  their email is always checked. Their ids are names the app or its SSO users pick. A generic provider that reuses a
  built-in id such as `"google"` is not trusted either. In 0.1.0 these sent `auth_provider` when the provider said the
  address was verified, which the API ignored for scoring.
- **An unverified social sign-up sends `auth_provider` with `email_verified: false`.** 0.1.0 sent the email alone. The
  check is the same: the email is checked.
- **`why_url` in the refusal body.** When you turn on "Add a 'Why was this refused?' link" on the Rules tab, a refused
  sign-up gets `{ code: "SIGNUP_BLOCKED", message, why_url }`. Without the setting, or with a malformed link, the key is
  absent. A `blockMessage` set in code keeps the link. OAuth and magic-link redirects carry only the error code and the
  message, because Better Auth drops other fields.
- **New exports:** `whyUrl(result)`, and `emailVerified` in `checkSignup`'s input. `CheckResponse` documents `why_url`;
  `checkSignup` drops a malformed one from the response, as it already did for `block_message`.
- **Tests and README for the per-reason message** (finaldynamics/signupbouncer#185, signupbouncer/better-auth#1): both
  checks show the `block_message` SignupBouncer sends for each reason, and `blockMessage` in code wins for every one.
  The README lists the three default messages and has a new section, "What a refused user sees".
- The plugin reads which providers you enabled once, when Better Auth starts, from the providers Better Auth has already
  set up. It never calls a function-valued `socialProviders` entry itself.
- The changelog now ships with the package on JSR and npm.

## 0.1.0

First release on JSR and npm.
