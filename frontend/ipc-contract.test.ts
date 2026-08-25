import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "..");
const tauriLib = readFileSync(
  join(repoRoot, "crates/tauri-app/src/lib.rs"),
  "utf8"
);

function walkTsFiles(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) {
      out.push(...walkTsFiles(full));
    } else if (
      /\.(ts|tsx)$/.test(name) &&
      !name.endsWith(".test.ts") &&
      !name.endsWith(".test.tsx")
    ) {
      out.push(full);
    }
  }
  return out;
}

function commandSignature(src: string, name: string): string {
  const after = src.split(`fn ${name}`).at(1);
  expect(after, `${name} must be defined`).toBeDefined();
  return after!.split("{")[0];
}

function tauriCommandSignatures(src: string): string[] {
  const out: string[] = [];
  let rest = src;
  const marker = "#[tauri::command]";
  while (rest.includes(marker)) {
    rest = rest.slice(rest.indexOf(marker) + marker.length);
    const fnIdx = rest.search(/\bfn\s+/);
    if (fnIdx < 0) break;
    const fromFn = rest.slice(fnIdx);
    const end = fromFn.indexOf("{");
    if (end < 0) break;
    out.push(fromFn.slice(0, end));
    rest = fromFn.slice(end + 1);
  }
  return out;
}

describe("desktop IPC contract", () => {
  it("does not define or register get_secret", () => {
    expect(tauriLib).not.toMatch(/\bfn get_secret\b/);
    expect(tauriLib).not.toMatch(/\bget_secret,/);
  });

  it("does not return expose_secret() as an IPC Ok payload", () => {
    expect(tauriLib).not.toContain("Ok(secret.expose_secret().to_string())");
  });

  it("no tauri command returns a String Ok payload", () => {
    const leaked = tauriCommandSignatures(tauriLib).filter((sig) =>
      /Result\s*<\s*String\b/.test(sig)
    );
    expect(leaked).toEqual([]);
  });

  it("keeps reveal_secret as a unit-returning native command", () => {
    expect(commandSignature(tauriLib, "reveal_secret")).toContain(
      "Result<(), String>"
    );
    expect(tauriLib).toMatch(/\breveal_secret,/);
  });

  it("keeps copy_secret as a unit-returning native command", () => {
    expect(commandSignature(tauriLib, "copy_secret")).toContain(
      "Result<(), String>"
    );
    expect(tauriLib).toMatch(/\bcopy_secret,/);
  });

  it("frontend source never invokes get_secret", () => {
    const files = walkTsFiles(join(here, "src"));
    const hits = files.filter((file) =>
      readFileSync(file, "utf8").includes("get_secret")
    );
    expect(hits).toEqual([]);
  });
});
