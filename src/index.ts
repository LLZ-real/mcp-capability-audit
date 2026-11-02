/**
 * Public library surface.
 *
 *   import { auditAll, auditServer, extractCapabilities } from "mcp-capability-audit";
 */

export * from "./types.ts";
export {
  extractCapabilities,
  toolRisk,
  isMutating,
  isNetworked,
  CAPABILITY_SIGNALS,
} from "./capabilities.ts";
export { compositionFindings, toolFindings, serverCapabilities, COMBINATION_RULES } from "./composition.ts";
export { generatePolicy, policyToYaml, capabilityAllowed } from "./policy.ts";
export { auditAll, auditServer, auditTool, grade, serverRisk, VERSION } from "./audit.ts";
export { loadAll, loadFixture, parseFixture } from "./loader.ts";
export { renderJson, renderMarkdown, renderTerminal } from "./report.ts";
