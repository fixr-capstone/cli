import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { toFinding } from "../../../frontend/lib/api.ts";
import { buildFixPrompt } from "../../../frontend/lib/fixPrompt.ts";

const here = dirname(fileURLToPath(import.meta.url));
const samples = JSON.parse(readFileSync(join(here, "samples.json"), "utf8"));
const project = JSON.parse(readFileSync(join(here, "sample_project_scan.json"), "utf8"));

const cases = {
  messy: samples.messy,
  minor: samples.minor,
  clean: samples.clean,
  sample_project: project,
};

const golden = join(here, "golden");
mkdirSync(golden, { recursive: true });

for (const [name, data] of Object.entries(cases)) {
  const findings = data.findings.map(toFinding);
  const nonStyle = findings.filter((finding) => !finding.style);
  const style = findings.filter((finding) => finding.style);
  writeFileSync(join(golden, `${name}.findings.json`), `${JSON.stringify(findings, null, 2)}\n`);
  writeFileSync(join(golden, `${name}.fix_prompt.md`), buildFixPrompt(nonStyle, style));
}
