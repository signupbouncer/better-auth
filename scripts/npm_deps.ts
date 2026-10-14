// Step 1 of the npm build: empties npm/ and writes npm/package.json with better-auth as its one dependency, so
// `deno install` (run next by the `npm:deps` task, in npm/) can fill npm/node_modules for dnt's type check.
// Deno runs no npm lifecycle scripts unless --allow-scripts is passed, and the npm CLI never runs.
// Step 2, scripts/build_npm.ts, then runs dnt with no permission to start processes.

import { betterAuthRange, readConfig } from "./npm_config.ts";

const config = await readConfig();
await Deno.remove("npm", { recursive: true }).catch((e) => {
  if (!(e instanceof Deno.errors.NotFound)) throw e;
});
await Deno.mkdir("npm");
const pkg = { private: true, devDependencies: { "better-auth": betterAuthRange(config) } };
await Deno.writeTextFile("npm/package.json", JSON.stringify(pkg, null, 2) + "\n");
