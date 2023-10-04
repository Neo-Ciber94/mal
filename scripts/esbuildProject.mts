import * as esbuild from "esbuild";
import path from "path";
import * as glob from "glob";

const DEFINE: Record<string, string> = {
  // this prevent esbuild to overwrite the NODE_ENV
  "process.env.NODE_ENV": "process.env.NODE_ENV",
};

type BuildFormat = "cjs" | "esm";

interface BuildConfig {
  inputs: [string, ...string[]];
  exclude?: string[];
  packageDir: string;
  formats?: [BuildFormat, ...BuildFormat[]];
  outExtensions?: Record<string, string>;
}

export async function esbuildProject({
  packageDir,
  exclude,
  inputs,
  ...rest
}: BuildConfig) {
  const outdir = path.resolve(packageDir, "dist");
  const entryPoints: string[] = [];
  const formats = rest.formats || ["cjs", "esm"];

  for (const input of inputs) {
    if (input.includes("*")) {
      const files = glob.sync(input, { ignore: exclude });
      entryPoints.push(...files);
    } else {
      entryPoints.push(input);
    }
  }

  if (formats.includes("cjs")) {
    // Build CommonJS
    await esbuild.build({
      entryPoints,
      logLevel: "debug",
      outdir,
      sourcemap: true,
      format: "cjs",
      define: DEFINE,
      outExtension: rest.outExtensions,
    });
  }

  if (formats.includes("esm")) {
    // Build ESM
    await esbuild.build({
      entryPoints,
      logLevel: "debug",
      outdir,
      sourcemap: true,
      format: "esm",
      define: DEFINE,
      outExtension: rest.outExtensions ?? {
        ".js": ".mjs",
      },
    });
  }
}
