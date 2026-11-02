import { strict as assert } from "node:assert";
import { test } from "node:test";
import {
  extractCapabilities,
  isMutating,
  isNetworked,
  toolRisk,
  words,
} from "../src/capabilities.ts";
import type { McpTool } from "../src/types.ts";

const tool = (over: Partial<McpTool> & { name: string }): McpTool => ({
  inputSchema: { type: "object", properties: {} },
  ...over,
});

const caps = (t: McpTool): string[] => extractCapabilities(t).map((h) => h.capability);

// ───────────────────────────── word splitting ─────────────────────────────

test("words splits every naming convention", () => {
  assert.deepEqual(words("read_file"), ["read", "file"]);
  assert.deepEqual(words("readFile"), ["read", "file"]);
  assert.deepEqual(words("ReadFile"), ["read", "file"]);
  assert.deepEqual(words("read-file"), ["read", "file"]);
  assert.deepEqual(words("HTTPGet"), ["http", "get"]);
});

// ───────────────────────────── extraction ─────────────────────────────

test("a plain file reader gets fs:read and nothing scary", () => {
  const t = tool({
    name: "read_text_file",
    description: "Read a UTF-8 text file from disk and return its contents as a string.",
    inputSchema: { type: "object", properties: { path: { type: "string", description: "Path." } } },
  });
  const c = caps(t);
  assert.ok(c.includes("fs:read"));
  assert.ok(!c.includes("fs:write"));
  assert.ok(!c.includes("fs:delete"));
  assert.ok(!c.includes("net:out"));
  assert.ok(!c.includes("exec:shell"));
});

test("write and delete are not conflated", () => {
  const w = tool({
    name: "write_file",
    description: "Write a string to a file, creating it if needed.",
    inputSchema: {
      type: "object",
      properties: { path: { type: "string" }, content: { type: "string" } },
    },
  });
  assert.ok(caps(w).includes("fs:write"));
  assert.ok(!caps(w).includes("fs:delete"), "overwriting is not deleting");

  const d = tool({
    name: "delete_path",
    description: "Permanently delete a file or directory.",
    inputSchema: { type: "object", properties: { path: { type: "string" } } },
  });
  assert.ok(caps(d).includes("fs:delete"));
});

test("a schema param alone cannot prove a capability", () => {
  // `write_file` and `delete_path` both take `path`. If schema signals were
  // sufficient, every write tool would look like a reader.
  const w = tool({
    name: "write_file",
    description: "Write a string to a file.",
    inputSchema: {
      type: "object",
      properties: { path: { type: "string" }, content: { type: "string" } },
    },
  });
  assert.ok(!caps(w).includes("fs:read"));
});

test("a remote tool is not a filesystem reader", () => {
  const t = tool({
    name: "fetch_url",
    description: "Fetch a URL over HTTP and return the response body.",
    inputSchema: { type: "object", properties: { url: { type: "string" } } },
  });
  const c = caps(t);
  assert.ok(c.includes("net:out"));
  assert.ok(!c.includes("fs:read"), "an HTTP body is not a file");
});

test("an env tool is not a filesystem reader", () => {
  const t = tool({
    name: "read_env",
    description: "Read an environment variable by name.",
    inputSchema: { type: "object", properties: { name: { type: "string" } } },
  });
  const c = caps(t);
  assert.ok(c.includes("env:read"));
  assert.ok(!c.includes("fs:read"));
});

test("searching files is not a database read", () => {
  const t = tool({
    name: "search_files",
    description: "Search file names and contents under a directory.",
    inputSchema: { type: "object", properties: { root: { type: "string" } } },
  });
  assert.ok(!caps(t).includes("db:read"));
});

test("a generic command param grants shell even from an innocuous name", () => {
  const t = tool({
    name: "run",
    description: "Run something.",
    inputSchema: { type: "object", properties: { command: { type: "string" } } },
  });
  assert.ok(caps(t).includes("exec:shell"));
});

test("a raw sql param is db:write unless the tool is explicitly read-only", () => {
  const ambiguous = tool({
    name: "run_query",
    description: "Run a query.",
    inputSchema: { type: "object", properties: { sql: { type: "string" } } },
  });
  assert.ok(caps(ambiguous).includes("db:write"), "ambiguous SQL must assume the worse reading");

  const selectOnly = tool({
    name: "run_select_query",
    description: "Execute a read-only SELECT statement and return rows.",
    inputSchema: { type: "object", properties: { sql: { type: "string" } } },
  });
  assert.ok(caps(selectOnly).includes("db:read"));
  assert.ok(!caps(selectOnly).includes("db:write"));
});

test("readOnlyHint suppresses mutating capabilities", () => {
  const t = tool({
    name: "write_file",
    description: "Write a string to a file.",
    annotations: { readOnlyHint: true },
    inputSchema: { type: "object", properties: { path: { type: "string" } } },
  });
  assert.ok(!caps(t).includes("fs:write"));
});

test("explicit prose denial suppresses the capability", () => {
  const t = tool({
    name: "inspect_file",
    description: "Inspect a file and return its size. Does not write to disk.",
    inputSchema: { type: "object", properties: { path: { type: "string" } } },
  });
  assert.ok(!caps(t).includes("fs:write"));
});

test("every capability claim carries evidence and a confidence", () => {
  const t = tool({
    name: "delete_path",
    description: "Permanently delete a file or directory.",
    inputSchema: { type: "object", properties: { path: { type: "string" } } },
  });
  for (const h of extractCapabilities(t)) {
    assert.ok(h.evidence.length > 0, `${h.capability} has no evidence`);
    assert.ok(h.confidence > 0 && h.confidence <= 1, `${h.capability} confidence out of range`);
  }
});

test("extraction is deterministic", () => {
  const t = tool({ name: "read_file", description: "Read a file from disk." });
  assert.deepEqual(caps(t), caps(t));
});

// ───────────────────────────── risk ─────────────────────────────

test("shell scores higher than reading", () => {
  const reader = tool({ name: "read_file", description: "Read a file from disk." });
  const shell = tool({ name: "run_command", description: "Run a shell command." });
  assert.ok(toolRisk(extractCapabilities(shell)) > toolRisk(extractCapabilities(reader)));
});

test("risk is bounded to 0..100", () => {
  const kitchenSink = tool({
    name: "do_everything",
    description: "Run shell commands, write files, delete files, fetch URLs, read secrets, control aws.",
    inputSchema: {
      type: "object",
      properties: {
        command: { type: "string" },
        sql: { type: "string" },
        url: { type: "string" },
      },
    },
  });
  const r = toolRisk(extractCapabilities(kitchenSink));
  assert.ok(r >= 0 && r <= 100, `risk out of range: ${r}`);
});

test("mutating and networked classifiers agree with the capability names", () => {
  assert.equal(isMutating("fs:write"), true);
  assert.equal(isMutating("fs:read"), false);
  assert.equal(isNetworked("net:out"), true);
  assert.equal(isNetworked("fs:read"), false);
});
