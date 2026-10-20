# Changelog

## 0.2.0 (unreleased)

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
