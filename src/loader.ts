/**
 * Fixture loading. Same shapes as mcp-tool-lint so fixtures are portable
 * between the two tools: `{server, source, tools}` or a bare tools array.
 */

import { readFileSync, readdirSync, statSync } from "node:fs";
import { basename, extname, join, resolve } from "node:path";
import type { McpTool, ServerTools } from "./types.ts";

export class FixtureError extends Error {
  readonly file?: string;
  constructor(message: string, file?: string) {
    super(message);
    this.name = "FixtureError";
    this.file = file;
  }
}

function normalizeTool(raw: unknown, index: number): McpTool {
  if (!raw || typeof raw !== "object") throw new FixtureError(`tool #${index} is not an object`);
  const t = raw as Record<string, unknown>;
  const tool: McpTool = { name: typeof t.name === "string" ? t.name : `tool_${index}` };
  if (typeof t.description === "string") tool.description = t.description;
  if (t.inputSchema && typeof t.inputSchema === "object") tool.inputSchema = t.inputSchema as McpTool["inputSchema"];
  if (t.annotations && typeof t.annotations === "object") tool.annotations = t.annotations as McpTool["annotations"];
  return tool;
}

export function parseFixture(raw: unknown, filename: string): ServerTools {
  const fallbackName = basename(filename, extname(filename));
  if (Array.isArray(raw)) {
    return { server: fallbackName, source: "fixture", tools: raw.map(normalizeTool) };
  }
  if (raw && typeof raw === "object") {
    const o = raw as Record<string, unknown>;
    if (!Array.isArray(o.tools)) throw new FixtureError("fixture must contain a `tools` array", filename);
    return {
      server: typeof o.server === "string" ? o.server : fallbackName,
      source: typeof o.source === "string" ? o.source : "fixture",
      tools: o.tools.map(normalizeTool),
    };
  }
  throw new FixtureError("fixture must be an object or array", filename);
}

export function loadFixture(path: string): ServerTools {
  const abs = resolve(path);
  let text: string;
  try {
    text = readFileSync(abs, "utf8");
  } catch (e) {
    throw new FixtureError(`cannot read: ${(e as Error).message}`, abs);
  }
  try {
    return parseFixture(JSON.parse(text), abs);
  } catch (e) {
    if (e instanceof FixtureError) throw e;
    throw new FixtureError(`invalid JSON: ${(e as Error).message}`, abs);
  }
}

export function collectPaths(inputs: string[]): string[] {
  const out: string[] = [];
  for (const input of inputs) {
    const abs = resolve(input);
    let st;
    try {
      st = statSync(abs);
    } catch {
      throw new FixtureError(`path does not exist: ${input}`, abs);
    }
    if (st.isDirectory()) walk(abs, out);
    else out.push(abs);
  }
  return out.sort();
}

function walk(dir: string, out: string[]): void {
  for (const e of readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
    if (e.name.startsWith(".")) continue;
    const p = join(dir, e.name);
    if (e.isDirectory()) walk(p, out);
    else if (e.name.endsWith(".json")) out.push(p);
  }
}

export function loadAll(inputs: string[]): ServerTools[] {
  return collectPaths(inputs).map(loadFixture);
}
