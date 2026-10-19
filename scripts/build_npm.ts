// Step 2 of the npm build: turns mod.ts into the npm package in npm/ with dnt (https://jsr.io/@deno/dnt): ESM plus
// .d.ts, Better Auth as a peer dependency.
//
//   deno task build:npm            # runs step 1 (npm:deps), then this, with the version from deno.json
//   deno task npm:build 0.1.1      # this step only; the version must match deno.json
//
// dnt needs better-auth's types to type-check and emit declarations. Step 1 (scripts/npm_deps.ts and `deno install`)
// already put them in npm/node_modules, so dnt runs with skipNpmInstall and the task grants it no --allow-run: no
// code dnt loads can start another process.

import { build } from "@deno/dnt";
import { betterAuthRange, readConfig } from "./npm_config.ts";

const config = await readConfig();
const version = Deno.args[0] ?? config.version;
if (!/^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/.test(version)) throw new Error(`Not a semver version: ${version}`);
if (version !== config.version) {
  throw new Error(`Version ${version} does not match deno.json (${config.version}). Bump deno.json first.`);
}
const range = betterAuthRange(config);

try {
  await Deno.stat("npm/node_modules/better-auth/package.json");
} catch {
  throw new Error("npm/node_modules has no better-auth. Run `deno task npm:deps` first.");
}
// Clear the previous build output but keep step 1's install.
for await (const entry of Deno.readDir("npm")) {
  if (entry.name !== "node_modules" && entry.name !== "deno.lock") {
    await Deno.remove(`npm/${entry.name}`, { recursive: true });
  }
}

// dnt reads a plain import map, not deno.json: given deno.json it searches every parent directory up to / for a
// workspace config, which would need read access to the whole path. The map lives in .dnt/ (gitignored).
await Deno.remove(".dnt", { recursive: true }).catch(() => {});
await Deno.mkdir(".dnt");
await Deno.writeTextFile(".dnt/import_map.json", JSON.stringify({ imports: config.imports }, null, 2));

await build({
  entryPoints: ["./mod.ts"],
  outDir: "./npm",
  importMap: ".dnt/import_map.json",
  shims: {},
  test: false,
  skipNpmInstall: true,
  scriptModule: false, // ESM only, like better-auth itself
  declaration: "separate",
  compilerOptions: { lib: ["ES2022", "DOM"], target: "ES2022" },
  mappings: {
    "better-auth": { name: "better-auth", version: range, peerDependency: true },
    "better-auth/api": { name: "better-auth", version: range, subPath: "api", peerDependency: true },
  },
  package: {
    name: "@signupbouncer/better-auth",
    version,
    description:
      "Better Auth plugin that blocks disposable email, burner account and fake signups with SignupBouncer. Fails open.",
    license: "MIT",
    author: "Final Dynamics LLC",
    homepage: "https://signupbouncer.com/docs",
    repository: { type: "git", url: "git+https://github.com/signupbouncer/better-auth.git" },
    bugs: { url: "https://github.com/signupbouncer/better-auth/issues" },
    keywords: [
      "better-auth",
      "better-auth-plugin",
      "disposable-email",
      "burner-email",
      "temporary-email",
      "email-validation",
      "signup",
      "signup-protection",
      "fake-accounts",
      "fraud",
      "fraud-prevention",
      "bot-protection",
      "auth",
      "signupbouncer",
    ],
    // better-auth 1.7's dependencies need Node 22 (kysely 0.29 declares >=22.0.0). CI imports the build on 22.0.0.
    engines: { node: ">=22.0.0" },
    sideEffects: false,
    publishConfig: { access: "public", provenance: true },
  },
  postBuild() {
    Deno.copyFileSync("LICENSE", "npm/LICENSE");
    Deno.copyFileSync("README.md", "npm/README.md");
    Deno.writeTextFileSync("npm/.npmignore", Deno.readTextFileSync("npm/.npmignore") + "deno.lock\n");
  },
});
