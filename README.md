# @signupbouncer/better-auth

A [Better Auth](https://better-auth.com) plugin that checks each new sign-up with
[SignupBouncer](https://signupbouncer.com) and refuses the ones SignupBouncer says to block, such as sign-ups from
throwaway email addresses. If SignupBouncer is slow or down, the sign-up goes through. By default your users wait at
most 1.5 seconds on the check.

You need a SignupBouncer API key. Create an account at https://signupbouncer.com/signup, then choose "Create API key" on
your app's Integration tab in the dashboard and copy the key (`sb_live_...`). Each key belongs to one app, and the
checks it makes are logged under that app. The full API docs are at https://signupbouncer.com/docs.

## Install

Deno:

```sh
deno add jsr:@signupbouncer/better-auth
```

Node, Bun and other npm-based setups, from npm:

```sh
npm install @signupbouncer/better-auth
```

or from JSR:

```sh
npx jsr add @signupbouncer/better-auth
```

The plugin has no dependencies of its own. It needs `better-auth` 1.7 or later, which your app already has, as a peer
dependency. On Node it needs Node 22 or later, as `better-auth` 1.7's own dependencies do.

## Use

```ts
import { betterAuth } from "better-auth";
import { signupBouncer } from "@signupbouncer/better-auth";

export const auth = betterAuth({
  emailAndPassword: { enabled: true },
  plugins: [
    signupBouncer({
      apiKey: process.env.SIGNUPBOUNCER_API_KEY!, // sb_live_..., from your SignupBouncer dashboard
      // ipHeader: "cf-connecting-ip", // the header your host sets to the client IP. See "The client IP".
    }),
  ],
});
```

New SignupBouncer apps start in **shadow mode**. Every sign-up is checked and logged in your dashboard, and none is
blocked. When the log looks right, switch the app to enforce in the dashboard. The plugin needs no change for that,
because it acts on the `action` field of the answer. In shadow mode `action` is always `"allow"`.

## What a refused user sees

A refused sign-up gets HTTP 400 with this body:

```json
{
  "code": "SIGNUP_BLOCKED",
  "message": "Please sign up with a permanent email address.",
  "why_url": "https://signupbouncer.com/why/mailinator.com"
}
```

On the client, `authClient.signUp.email()` returns that body as `error`. Show `error.message`, and the link when there
is one:

```tsx
const { error } = await authClient.signUp.email({ email, password, name });
// why_url is not in Better Auth's error type, but the client returns every field of the body.
const whyUrl = (error as { why_url?: string } | null)?.why_url;

// Where your form shows the error (JSX):
<p role="alert">
  {error?.message} {whyUrl && <a href={whyUrl}>Why was this refused?</a>}
</p>;
```

### The message

The message is the one SignupBouncer sends with the answer (`block_message`), the same for an email sign-up and for one
the database hook refuses. It is the message you set on the Rules tab of your SignupBouncer dashboard. While you keep
the default there, the words fit the reason:

- A burner domain: "Please sign up with a permanent email address."
- A domain that looks like a typo of a big mail provider: "Did you mean ann@gmail.com? Please check your email address
  and try again."
- Any other reason, such as a repeat inbox: "We couldn't create your account. Please contact us if you need help."

When the answer has no message, the plugin uses "Please sign up with a permanent email address." That covers an older
server, a message that is blank, not text or over 500 characters, and an email the plugin refuses without asking (over
320 characters, or not an address). Set `blockMessage` to use your own message in code. It then wins for every reason.

### The "Why was this refused?" link

`why_url` is there only when you turn the link on. Open Advanced on the Rules tab of your SignupBouncer dashboard and
switch on "Add a 'Why was this refused?' link". The link goes to our page about the email's domain, such as
https://signupbouncer.com/why/mailinator.com. That page says what we know about the domain and how to sign up another
way. It never shows your settings or your checks, and the link carries the domain only, never the full address.

- With the setting off, the body has no `why_url` key. Your form shows the message alone.
- The plugin passes the link on exactly as SignupBouncer sent it, and only when it is a well-formed `http` or `https`
  URL. Anything else is dropped, and the sign-up is still refused.
- The link follows the dashboard setting, so it is there with a `blockMessage` set in code too.
- An email the plugin refuses without asking (over 320 characters, or not an address) gets no link.
- OAuth and magic-link sign-ups refused by the database hook end in a redirect, not this body. See "Sign-ups other than
  email and password".

## What it does

- Checks every `POST /sign-up/email` before Better Auth creates the user. It sends SignupBouncer the email, the
  User-Agent and, when you configure a source for it, the client IP.
- Checks the user Better Auth is about to save as well, through a `user.create.before` database hook. When the saved
  address is the one already checked, it makes no second request. When another hook in your app changed the address, it
  checks the new one.
- Refuses an email longer than 320 characters, or one with spaces or without text on both sides of an `@`, without
  asking SignupBouncer. The API takes at most 320 characters, so a longer address would be cut before the check.
- Refuses the sign-up when the answer's `action` is `"block"`. A `"challenge"` answer is allowed unless you set
  `challenge: "block"`, because Better Auth has no captcha step to send it to.
- With `checkOtherSignups: true`, also checks users created by OAuth, magic link, email OTP and other plugins (see
  below).

It leaves alone sign-ins, password resets, sessions and anything else that does not create a user. It stores nothing
between requests.

Your own `databaseHooks.user.create.before` runs after the plugin's. If it changes the email, the plugin has already
checked the earlier address.

## When a check fails, the sign-up goes through

Any failure allows the sign-up. That covers a timeout, a network error, a non-2xx answer (such as 401 for a wrong key)
and an answer that is not a complete `/v1/check` response. Only a complete answer can refuse a sign-up.

The plugin never follows a redirect, so your API key and the email cannot be sent on to another host. A 3xx answer
counts as a failed check. It reads at most 64 KiB of an answer, and an answer that completes after `timeoutMs` counts as
a timeout.

Each failure calls `onError` with one of these reasons:

- `timeout`: no full answer within `timeoutMs`.
- `network`: a DNS, TLS or connection failure.
- `http_status`: any non-2xx answer (3xx redirect, 401 bad key, 403 `app_mismatch`, 404 unknown app, 5xx). `status`
  holds the code.
- `bad_response`: the body was not JSON, was larger than 64 KiB, was missing a field the API always sends or had one of
  the wrong type, or the connection broke while it was being read.
- `missing_api_key`: `apiKey` was empty. No request was made.
- `malformed_api_key`: `apiKey` holds a space, newline or other character a key never has. No request was made.
- `no_input`: `checkSignup` got neither an email nor an IP. No request was made.

Without `onError`, the plugin writes one `console.warn` line per failure, for example:

```
[signupbouncer] check failed (http_status 401), sign-up allowed. Check the signupbouncer API key in your config.
```

The line and the `onError` argument hold only the reason and the status code. They never hold the API key, the email,
the IP, an exception message or response text, so you can log them whole. Pass your own `onError` to send failures to
your logger, or `onError: () => {}` to turn the warning off. A 403 or 404 warning adds a hint about the `app` option:
403 means it names another app than the key's own, and 404 (older all-apps keys only) an app id not on the key's
account. The plugin does not wait for `onError`, so a slow logger never delays a sign-up, and anything it throws is
ignored.

## Options

| Option              | Default                                 | Meaning                                                                                     |
| ------------------- | --------------------------------------- | ------------------------------------------------------------------------------------------- |
| `apiKey`            | required                                | Your `sb_live_...` key. If it is empty, every sign-up is allowed and `onError` is called.   |
| `baseUrl`           | `https://signupbouncer.com`             | API origin.                                                                                 |
| `app`               | the API key's app                       | Leave it out. See "Which app the checks go to".                                             |
| `timeoutMs`         | `1500`                                  | How long to wait before allowing the sign-up anyway. At most 10,000.                        |
| `blockMessage`      | the one from your dashboard's Rules tab | Message returned to the client on a block. Set here, it wins over the dashboard.            |
| `challenge`         | `"allow"`                               | What to do when the answer is `"challenge"`: `"allow"` or `"block"`.                        |
| `ipHeader`          | none (email-only checks)                | The one header your host overwrites with the client IP. See "The client IP".                |
| `trustedProxies`    | `1`                                     | For X-Forwarded-For on a fixed proxy chain only: the entry this many places from the right. |
| `getIp`             | none                                    | `(request, headers) => ip`: your own IP lookup, used instead of `ipHeader`.                 |
| `onError`           | one `console.warn` line                 | Called with `{ reason, status? }` when a check fails. The sign-up is still allowed.         |
| `checkOtherSignups` | `false`                                 | Also check users created by OAuth, magic link, email OTP and other plugins (see below).     |

### Which app the checks go to

Each API key belongs to one SignupBouncer app, and its checks are logged under that app, so leave `app` out. If you set
it, it must be the key's own app id (`app_...`). Any other app's id gets HTTP 403 `app_mismatch`, which counts as a
failed check: every sign-up is allowed and `onError` gets `http_status` 403. To check sign-ups for a second app, create
a key on that app's Integration tab and use it in that app's config.

Keys made before keys belonged to an app are labelled "all apps (older key)" in the dashboard. Only those keys use `app`
to pick the app, and without it they log the checks under your first app.

### The client IP

By default the plugin reads no request header and sends no IP, so SignupBouncer checks the email alone. A client can
send `CF-Connecting-IP`, `X-Real-IP` or `X-Forwarded-For` itself. Unless something in front of your app overwrites that
header, a bot can pick any IP it likes, get past the IP checks, or get a stranger's address blocked.

Set `ipHeader` to the one header your host writes itself:

| Where your app runs             | Setting                                                                      |
| ------------------------------- | ---------------------------------------------------------------------------- |
| Behind Cloudflare (proxied DNS) | `ipHeader: "cf-connecting-ip"`, and only accept traffic from Cloudflare      |
| Vercel                          | `ipHeader: "x-real-ip"`, or `"x-vercel-forwarded-for"` with a proxy in front |
| Fly.io                          | `ipHeader: "fly-client-ip"`                                                  |
| Node behind your own proxies    | Best: `ipHeader: "x-real-ip"`, written by your edge proxy (see below)        |
| Anything else                   | `getIp: (request, headers) => ...` with your platform's own lookup           |

- **Cloudflare** sends `CF-Connecting-IP`, the address of the client connecting to Cloudflare, on traffic from its edge
  to your origin (https://developers.cloudflare.com/fundamentals/reference/http-headers/#cf-connecting-ip). That holds
  only while every request comes through Cloudflare. If your origin is reachable directly, a client can send the header
  itself.
- **Vercel** overwrites `X-Forwarded-For` and does not forward external IPs, to prevent spoofing. `X-Real-IP` and
  `X-Vercel-Forwarded-For` carry the same value, and `X-Vercel-Forwarded-For` keeps the client IP even when you put your
  own proxy in front of Vercel (https://vercel.com/docs/headers/request-headers#x-forwarded-for,
  https://vercel.com/docs/headers/request-headers#x-vercel-forwarded-for).
- **Fly.io**'s proxy sets `Fly-Client-IP` to "the IP address of the client from the perspective of Fly Proxy"
  (https://docs.fly.io/networking/request-headers). Fly's page does not say whether it replaces a value the client sent.
  With another proxy in front of Fly, the header holds that proxy's address.

Your own proxies (self-hosted nginx, Caddy, HAProxy, a cloud load balancer), safest first:

1. **One header, written by the proxy that faces the internet.** Have that proxy overwrite a header of its own with the
   address it received the connection from, and have any proxies behind it pass that header through unchanged. For nginx
   at the edge: `proxy_set_header X-Real-IP $remote_addr;`, then `ipHeader: "x-real-ip"`. This holds even if a client
   sends `X-Real-IP` itself, because the edge proxy replaces it. It works only when the app cannot be reached without
   passing through that proxy.
2. **A resolver that knows your proxies' addresses.** If requests can reach you along different paths, let the proxy in
   front of the app work out the client address from its list of trusted proxy addresses (nginx `ngx_http_realip_module`
   with `set_real_ip_from <your proxy CIDRs>` and `real_ip_recursive on`, then pass `$remote_addr` on as `X-Real-IP`).
   It looks at the address that actually connected, which a count of hops cannot do.
3. **A hop count on `X-Forwarded-For`, only on a fixed path.** A proxy that appends to `X-Forwarded-For` (nginx
   `proxy_add_x_forwarded_for`, most load balancers) keeps whatever the client sent and adds the address it saw at the
   right. Set `ipHeader: "x-forwarded-for"` and `trustedProxies` to the number of proxies in the chain. The plugin takes
   the entry that many places from the right (default 1, the right-most). This is safe only when **every** request
   passes through the same chain of exactly that many proxies, and the inner proxies and the app are unreachable except
   through it (a private network, or firewall rules that accept only the previous hop). If an inner proxy can be reached
   directly, a client sends `X-Forwarded-For: <any IP>`, the proxy appends the real address, and the list has the length
   you configured, so the plugin uses the client's made-up entry. A list shorter than the count gives no IP, but that
   does not prove the request came through the whole chain.

Better Auth's own rate limiter reads the client IP too and has its own setting for it
(https://better-auth.com/docs/concepts/rate-limit#connecting-ip-address). This plugin does not read that setting.

### Sign-ups other than email and password

By default the plugin checks email and password sign-ups only. With `checkOtherSignups: true` its database hook checks
every user created through a request: OAuth callbacks, ID-token sign-in, One Tap, magic link, email OTP and so on.

- A sign-up through one of your `socialProviders` (Google, GitHub, Apple and the other providers built into Better Auth)
  sends the email with `auth_provider`, the provider id such as `"google"`, and `email_verified`. That is Better Auth's
  own `emailVerified` flag from the provider, never something the user typed. The plugin covers the OAuth callback
  (`/callback/:id`), ID-token sign-in (`/sign-in/social`) and Google One Tap.
- When `email_verified` is `true`, SignupBouncer scores the sign-up on the IP and signup bursts only. An email rule,
  such as one for a burner domain, cannot refuse it. We still count the email's domain in your dashboard.
- When the provider did not verify the address, `email_verified` is `false` and the email is checked like an email
  sign-up.
- Generic OAuth providers (the `genericOAuth` plugin) and SSO providers send the email without `auth_provider`, so the
  email is always checked. Their ids are names your app or, with self-service SSO, your users pick, so a sign-up through
  one never skips the email checks. The same goes for a generic provider that reuses a built-in id such as `"google"`.
- Magic link, email OTP and the rest send the email and the IP.
- The hook skips `/admin/*` (users your admins create), `/sign-in/anonymous`, and users your own server code creates
  without a request.

A block in a database hook throws the same `APIError`. ID-token sign-in answers with the JSON body above, `why_url`
included. The OAuth callback and magic link are redirects instead: Better Auth sends the user to your error callback URL
with `?error=SIGNUP_BLOCKED&error_description=<the message>`. It drops every other field of the error, so a redirect
never carries the "Why was this refused?" link. Show `error_description` on that page. We have tested the redirect with
Google, a generic OAuth provider and magic link. On other redirect flows the error the user sees depends on the flow and
your Better Auth version.

### Using the check directly

`checkSignup(options, { email, ip, userAgent, authProvider, emailVerified })` is exported too. It returns
`{ ok, action, response | error }` and never throws, so you can run the same fail-open check from any route. Pass the
email exactly as your app saves it. For an OAuth or SSO sign-up, pass the provider id as `authProvider` and your auth
library's own verified flag as `emailVerified`. `shouldBlock(result, challenge)` turns the result into a yes or no.
`blockMessage(result)` gives the message to show and `whyUrl(result)` the link, or `null` without one.

## Better Auth APIs this plugin uses

Checked on 14 Oct 2026 against the live docs and `better-auth` 1.7.0 and 1.7.7 from npm:

- Plugin `hooks.before` entries with `matcher` and `createAuthMiddleware` from `better-auth/api`:
  https://better-auth.com/docs/concepts/plugins#hooks
- Throwing `APIError` from a hook to stop the request: https://better-auth.com/docs/concepts/hooks#errors
- `databaseHooks.user.create.before`, and throwing `APIError` from it:
  https://better-auth.com/docs/concepts/database#database-hooks. A plugin supplies database hooks by returning
  `{ options: { databaseHooks } }` from its `init` function. The `BetterAuthPlugin` type includes that, and the built-in
  admin plugin uses it, but the plugin docs page does not describe it. Better Auth passes the endpoint context as the
  hook's second argument, with the route pattern in `path` (`/callback/:id`) and the provider in `params`.

## Development

```sh
deno task test           # unit tests, plus a real in-memory Better Auth instance with the SignupBouncer API mocked
deno task check          # fmt, lint, type check
deno task publish:check  # deno publish --dry-run
deno task build:npm      # npm package into npm/: npm:deps (deno install, no scripts), then npm:build (dnt)
```

## Licence

MIT. Copyright (c) 2026 Final Dynamics LLC, which does business as SignupBouncer. See [LICENSE](LICENSE).
