// Reads what the npm build needs from deno.json, so JSR and npm publish the same version and Better Auth range.

/** The parts of deno.json the npm build reads. */
export interface Config {
  version: string;
  imports: Record<string, string>;
}

/** Reads deno.json. */
export async function readConfig(): Promise<Config> {
  return JSON.parse(await Deno.readTextFile("deno.json")) as Config;
}

/** The Better Auth version range from deno.json's import map, checked to be the same for `better-auth/api`. */
export function betterAuthRange(config: Config): string {
  const range = /^npm:better-auth@(.+)$/.exec(config.imports["better-auth"] ?? "")?.[1];
  if (!range) throw new Error('deno.json imports["better-auth"] must be "npm:better-auth@<range>"');
  if (config.imports["better-auth/api"] !== `npm:better-auth@${range}/api`) {
    throw new Error('deno.json imports["better-auth/api"] must use the same range as imports["better-auth"]');
  }
  return range;
}
