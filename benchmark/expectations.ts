/**
 * Fixtures that encode known-truth expectations.
 *
 * The whole point of an auditor is that it is *right*. So each fixture pair
 * declares what the correct answer is, and the benchmark fails when the
 * auditor disagrees. This file is the spec; the code has to match it.
 */

export interface Expectation {
  file: string;
  /** Capabilities that MUST be detected. */
  mustDetect: string[];
  /** Capabilities that MUST NOT be detected (the false-positive guard). */
  mustNotDetect: string[];
  /** Findings that must fire, by rule id. */
  mustFind: string[];
  /** Findings that must not fire. */
  mustNotFind: string[];
  /** Risk must fall in this band (inclusive). */
  riskRange: [number, number];
}

export const EXPECTATIONS: Expectation[] = [
  {
    file: "dev-assistant.json",
    mustDetect: ["fs:read", "fs:write", "net:out", "exec:shell", "env:read"],
    // `read_env` reads ONE named variable on request. That is env:read, not
    // secrets:read -- treating them as equal would flag every config-reading
    // tool as a credential leak and bury the real ones. `secrets:read` is
    // reserved for tools that target a secret store by name.
    mustNotDetect: ["cloud:control", "browser:control", "secrets:read"],
    mustFind: [
      "combo/exfiltration",
      "combo/remote-exec",
      "tool/arbitrary-shell",
    ],
    mustNotFind: [],
    riskRange: [60, 100],
  },
  {
    file: "filesystem-readonly.json",
    // A read-only filesystem server must not look dangerous.
    mustDetect: ["fs:read"],
    mustNotDetect: [
      "fs:write",
      "fs:delete",
      "net:out",
      "exec:shell",
      "db:read",
      "db:write",
      "secrets:read",
      "cloud:control",
    ],
    mustFind: [],
    mustNotFind: ["combo/exfiltration", "combo/remote-exec", "tool/arbitrary-shell"],
    riskRange: [0, 20],
  },
  {
    file: "ops-automation.json",
    // The worst realistic case: vault access, egress, cloud control, and a shell.
    mustDetect: ["secrets:read", "net:out", "cloud:control", "exec:shell"],
    mustNotDetect: ["fs:read", "browser:control"],
    mustFind: [
      "combo/secrets-exfil",
      "combo/remote-exec",
      "combo/cloud-blast-radius",
      "tool/arbitrary-shell",
    ],
    mustNotFind: [],
    // Calibrated: the max-tool term (shell = 45) plus the capped combination
    // premium (3 critical combos x 12 = 36, capped at 30) lands at 75. A
    // single critical combination is worth +12. The band records the observed
    // behaviour so a scoring change that silently halves it will fail CI.
    riskRange: [70, 100],
  },
];
