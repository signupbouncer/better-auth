# Publishing

How a release gets to JSR and npm, and the one-time setup it needs. Nothing is published from a laptop: pushing a tag
such as `v0.1.0` runs `.github/workflows/publish.yml`, which publishes to JSR (GitHub OIDC, no secret) and to npm (the
`NPM_TOKEN` secret, with provenance).

## One-time setup

1. **GitHub repo.** Create the public repo `signupbouncer/better-auth` (empty: no README, licence or .gitignore), then
   push this one:

   ```
   git remote add origin git@github.com:signupbouncer/better-auth.git
   git push -u origin master
   ```

   Wait for the `ci` workflow to go green on `master` before going further.

2. **JSR scope and package.** Sign in at https://jsr.io with the GitHub account that owns the `signupbouncer` org.
   - Create the scope `@signupbouncer` and, in it, the package `better-auth` (https://jsr.io/new).
   - In the package's Settings tab, link it to the GitHub repository `signupbouncer/better-auth`. This is what lets the
     workflow publish with GitHub's OIDC token (https://jsr.io/docs/publishing-packages#publishing-from-github-actions).

3. **npm org and token.**
   - Create the free npm organization `signupbouncer` (https://www.npmjs.com/org/create). This reserves the
     `@signupbouncer` scope.
   - Create a granular access token (https://www.npmjs.com/settings/~/tokens/granular-access-tokens/new):
     - Packages and scopes: Read and write, limited to the `@signupbouncer` scope.
     - Tick "Bypass two-factor authentication", or the workflow cannot publish.
     - Pick an expiry and put a reminder in your calendar to rotate it.

     npm's older "Automation" classic tokens are what many guides name. Use a granular token instead
     (https://docs.npmjs.com/creating-and-viewing-access-tokens).
   - In GitHub, add it as a repository secret named `NPM_TOKEN`
     (https://github.com/signupbouncer/better-auth/settings/secrets/actions).

## Each release

1. Bump `"version"` in `deno.json`, commit, push, and wait for `ci` to go green.
2. Tag the commit with the same version and push the tag:

   ```
   git tag v0.1.0
   git push origin v0.1.0
   ```

3. Watch https://github.com/signupbouncer/better-auth/actions. The `verify` job refuses a tag that does not match
   `deno.json` or a published file that still holds a `[FILL ...]` placeholder. Then `jsr` publishes while `build-npm`
   builds the npm package in a job with no publishing rights. `npm` publishes that build after both have succeeded.
4. Check https://jsr.io/@signupbouncer/better-auth and https://www.npmjs.com/package/@signupbouncer/better-auth.

A version number can be published once on each registry. If one registry fails and the other succeeds, fix the cause and
re-run only the failed job from the Actions page. Never re-tag.

## Checking a release locally (publishes nothing)

```
deno task check
deno task test
deno task publish:check
deno task build:npm
```

`build:npm` writes the npm package to `npm/` in two steps. `npm:deps` fills `npm/node_modules` with `deno install`,
which runs no npm install scripts. `npm:build` then runs dnt with no permission to start other processes. The npm CLI
runs only inside GitHub Actions.

## Later: drop the npm token

npm supports trusted publishing from GitHub Actions with OIDC, the way JSR works here
(https://docs.npmjs.com/trusted-publishers). It needs npm 11.5.1 or later and Node 22.14.0 or later, and gives
provenance without `--provenance`. After the first release, add `signupbouncer/better-auth` and `publish.yml` as the
package's trusted publisher on npmjs.com, remove `NODE_AUTH_TOKEN` from `publish.yml`, and delete the `NPM_TOKEN` secret
and the token.
