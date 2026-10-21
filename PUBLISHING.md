# Publishing

How a release gets to JSR and npm, and the one-time setup it needs. Nothing is published from a laptop: pushing a tag
such as `v0.1.0` runs `.github/workflows/publish.yml`. It publishes to JSR and stages the version on npm, both
authenticated with GitHub's OIDC token, so the repository holds no publishing secret. A staged npm version goes live
only when you approve it on npmjs.com with your 2FA.

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

3. **npm org and trusted publisher.**
   - Create the free npm organization `signupbouncer` (https://www.npmjs.com/org/create). This reserves the
     `@signupbouncer` scope.
   - The package must exist on npm before a trusted publisher can be added. `@signupbouncer/better-auth` has existed
     since 0.1.0.
   - On https://www.npmjs.com/package/@signupbouncer/better-auth, open Settings, find "Trusted Publisher" and choose
     GitHub Actions (https://docs.npmjs.com/trusted-publishers). Enter:
     - Organization or user: `signupbouncer`
     - Repository: `better-auth`
     - Workflow filename: `publish.yml`
     - Environment name: leave empty. The workflow's npm job has no GitHub environment, and the fields must match the
       workflow exactly or npm refuses the run.
     - Allowed actions: leave "Allow npm publish" and "Allow npm dist-tag" unticked. `npm stage publish` is always
       allowed, and it is the only command the workflow runs, so every version waits for your approval.
   - Under Settings, "Publishing access", choose "Require two-factor authentication and disallow tokens". Trusted
     publishing does not use a token, so the workflow keeps working, and no leaked token can publish this package.
   - Then delete the old `NPM_TOKEN` repository secret
     (https://github.com/signupbouncer/better-auth/settings/secrets/actions). Nothing in this repository reads it any
     more. Revoke the token itself on npmjs.com (https://www.npmjs.com/settings/~/tokens) once no other repository uses
     it: it can publish every `@signupbouncer` package.

## Each release

1. Bump `"version"` in `deno.json`, commit, push, and wait for `ci` to go green.
2. Tag the commit with the same version and push the tag:

   ```
   git tag v0.1.0
   git push origin v0.1.0
   ```

3. Watch https://github.com/signupbouncer/better-auth/actions. The `verify` job refuses a tag that does not match
   `deno.json` or a published file that still holds a `[FILL ...]` placeholder. Then `jsr` publishes while `build-npm`
   builds and packs the npm package in a job with no publishing rights. After both have succeeded, `npm` checks that
   tarball with `scripts/release_tarball.py` (no links, odd paths, `.npmrc` or unexpected `publishConfig`), writes a
   clean copy from what it checked, and stages that copy.
4. Approve the staged version at npmjs.com (package > staged versions; needs your 2FA). Until then it is not live on
   npm; JSR publishes on its own. npm's docs call the page the "Staged Packages" tab of the package
   (https://docs.npmjs.com/staged-publishing): open https://www.npmjs.com/package/@signupbouncer/better-auth, go to that
   tab, check the version and click Approve. From a terminal, `npm stage list @signupbouncer/better-auth` shows the
   stage id and `npm stage approve <stage-id>` approves it, also with 2FA.
5. Check https://jsr.io/@signupbouncer/better-auth and https://www.npmjs.com/package/@signupbouncer/better-auth. The npm
   version page should show a provenance badge.

A version number can be published once on each registry, and a staged npm version holds its number too. If one registry
fails and the other succeeds, fix the cause and re-run only the failed job from the Actions page. Never re-tag. To throw
away a staged npm version, reject it on the Staged Packages tab (or `npm stage reject <stage-id>`); the same version can
then be staged again by re-running the `npm` job. A prerelease version such as `0.3.0-rc.1` cannot be staged as it is:
npm requires a `--tag` for prereleases, which the workflow does not pass.

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
