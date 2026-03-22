/**
 * JSONL read/write utilities
 */

import fs from "node:fs";

export function readJsonl<T = Record<string, unknown>>(
  filepath: string,
): T[] {
  const content = fs.readFileSync(filepath, "utf-8");
  const lines = content.split("\n").filter((line) => line.trim().length > 0);
  return lines.map((line) => JSON.parse(line) as T);
}

export function writeJsonl(
  filepath: string,
  records: Record<string, unknown>[],
): void {
  const content = records.map((r) => JSON.stringify(r)).join("\n") + "\n";
  fs.writeFileSync(filepath, content, "utf-8");
}

export function appendJsonl(
  filepath: string,
  record: Record<string, unknown>,
): void {
  fs.appendFileSync(filepath, JSON.stringify(record) + "\n", "utf-8");
}
