import { readdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
const skip = new Set([
  "node_modules",
  ".git",
  ".secrets",
  ".next",
  "dist",
  "target",
  "artifacts",
  "icons",
]);
async function walk(dir) {
  let result = [];
  for (const e of await readdir(dir, { withFileTypes: true })) {
    if (
      skip.has(e.name) ||
      (e.name.startsWith(".env") && e.name !== ".env.example") ||
      ["SOURCE_BUNDLE.md", "package-lock.json", "Cargo.lock"].includes(e.name)
    )
      continue;
    const p = path.join(dir, e.name);
    if (e.isDirectory()) result.push(...(await walk(p)));
    else if (
      /\.(ts|tsx|rs|toml|json|css|mjs|yml|sql|ps1)$/.test(p) ||
      e.name === "Dockerfile" ||
      e.name === ".env.example" ||
      e.name.startsWith("Caddyfile")
    )
      result.push(p);
  }
  return result;
}
let text =
  "# Полные исходные файлы OnlineKeyGen\n\nСекреты, зависимости и сгенерированные бинарные файлы исключены.\n";
for (const p of (await walk(".")).sort()) {
  text +=
    "\n## " +
    p.replaceAll("\\", "/") +
    "\n\n```" +
    path.extname(p).slice(1) +
    "\n" +
    (await readFile(p, "utf8")) +
    "\n```\n";
}
await writeFile("docs/SOURCE_BUNDLE.md", text);
