// Builds the npm package into npm/ with dnt (https://jsr.io/@deno/dnt): ESM plus .d.ts, Better Auth as a peer.
//
//   deno task build:npm            # version from deno.json
//   deno task build:npm 0.1.1      # or an explicit version (CI passes the tag's version)
//
// dnt has to resolve better-auth's types to type-check and emit declarations, so it needs a node_modules in npm/.
// It installs one with the command named in `packageManager`. We name `deno`, so `deno install` reads the generated
// package.json and fills npm/node_modules from the npm registry. Deno runs no npm lifecycle scripts unless
// --allow-scripts is passed, and the npm CLI never runs. The tests run under Deno (`deno task test`), not here.

import { build, emptyDir } from "@deno/dnt";

const config = JSON.parse(await Deno.readTextFile("deno.json")) as { version: string; imports: Record<string, string> };
const version = Deno.args[0] ?? config.version;
if (!/^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/.test(version)) throw new Error(`Not a semver version: ${version}`);
if (version !== config.version) {
  throw new Error(`Version ${version} does not match deno.json (${config.version}). Bump deno.json first.`);
}

// The peer range comes from deno.json, so JSR and npm ask for the same Better Auth versions.
const betterAuthRange = /^npm:better-auth@(.+)$/.exec(config.imports["better-auth"] ?? "")?.[1];
if (!betterAuthRange) throw new Error('deno.json imports["better-auth"] must be "npm:better-auth@<range>"');
if (config.imports["better-auth/api"] !== `npm:better-auth@${betterAuthRange}/api`) {
  throw new Error('deno.json imports["better-auth/api"] must use the same range as imports["better-auth"]');
}

// dnt reads a plain import map, not deno.json: given deno.json it searches every parent directory up to / for a
// workspace config, which would need read access to the whole path. The map lives in .dnt/ (gitignored).
await emptyDir("./.dnt");
await Deno.writeTextFile(".dnt/import_map.json", JSON.stringify({ imports: config.imports }, null, 2));
await emptyDir("./npm");

await build({
  entryPoints: ["./mod.ts"],
  outDir: "./npm",
  importMap: ".dnt/import_map.json",
  shims: {},
  test: false,
  scriptModule: false, // ESM only, like better-auth itself
  declaration: "separate",
  packageManager: "deno",
  compilerOptions: { lib: ["ES2022", "DOM"], target: "ES2022" },
  mappings: {
    "better-auth": { name: "better-auth", version: betterAuthRange, peerDependency: true },
    "better-auth/api": { name: "better-auth", version: betterAuthRange, subPath: "api", peerDependency: true },
  },
  package: {
    name: "@signupbouncer/better-auth",
    version,
    description: "Better Auth plugin that checks each new sign-up with signupbouncer and blocks throwaway accounts.",
    license: "MIT",
    homepage: "https://signupbouncer.com/docs",
    repository: { type: "git", url: "git+https://github.com/signupbouncer/better-auth.git" },
    bugs: { url: "https://github.com/signupbouncer/better-auth/issues" },
    keywords: ["better-auth", "better-auth-plugin", "signup", "disposable-email", "fraud", "signupbouncer"],
    engines: { node: ">=18" },
    sideEffects: false,
    // Only for type-checking during this build. Consumers get better-auth through peerDependencies.
    devDependencies: { "better-auth": betterAuthRange },
    publishConfig: { access: "public", provenance: true },
  },
  postBuild() {
    Deno.copyFileSync("LICENSE", "npm/LICENSE");
    Deno.copyFileSync("README.md", "npm/README.md");
    // The build-only better-auth install stays out of the published manifest and tarball.
    const pkg = JSON.parse(Deno.readTextFileSync("npm/package.json"));
    delete pkg.devDependencies;
    Deno.writeTextFileSync("npm/package.json", JSON.stringify(pkg, null, 2) + "\n");
    Deno.writeTextFileSync("npm/.npmignore", Deno.readTextFileSync("npm/.npmignore") + "deno.lock\n");
  },
});
