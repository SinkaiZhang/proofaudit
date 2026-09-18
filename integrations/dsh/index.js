import { spawn } from "node:child_process";
import { existsSync, realpathSync } from "node:fs";
import { dirname, isAbsolute, relative, resolve } from "node:path";
import { defineTool } from "@deepseek-ai/dsh-tools";

const MAX_CAPTURE_BYTES = 4 * 1024 * 1024;

function isWithin(candidate, root) {
  const rel = relative(root, candidate);
  return rel === "" || (!rel.startsWith("..") && !isAbsolute(rel));
}

function allowedRoots(config) {
  const values = Array.isArray(config?.allowed_roots) && config.allowed_roots.length
    ? config.allowed_roots : [process.cwd()];
  return values.map((value) => realpathSync(resolve(process.cwd(), String(value))));
}

function resolveInput(raw, roots) {
  const path = realpathSync(resolve(process.cwd(), raw));
  if (!roots.some((root) => isWithin(path, root))) throw new Error(`Path outside allowed roots: ${raw}`);
  return path;
}

function resolveOutput(raw, roots) {
  const path = resolve(process.cwd(), raw);
  let probe = path;
  while (!existsSync(probe)) {
    const parent = dirname(probe);
    if (parent === probe) break;
    probe = parent;
  }
  const ancestor = realpathSync(probe);
  if (!roots.some((root) => isWithin(ancestor, root))) throw new Error(`Output outside allowed roots: ${raw}`);
  return path;
}

function executeAudit(args, exec, roots) {
  let casePath;
  let artifactDir;
  try {
    casePath = resolveInput(args.case, roots);
    artifactDir = resolveOutput(args.artifact_dir, roots);
  } catch (error) {
    return Promise.resolve({status: "PLUGIN_ERROR", code: "PATH_POLICY_ERROR", detail: error.message});
  }
  const python = process.env.PROOFAUDIT_PYTHON ?? (process.platform === "win32" ? "python" : "python3");
  const childArgs = ["-m", "proofaudit", "run", "--case", casePath, "--artifact-dir", artifactDir];
  const timeoutMs = args.timeout_ms === undefined ? undefined : Number(args.timeout_ms);
  if (timeoutMs !== undefined) childArgs.push("--timeout-ms", String(timeoutMs));
  return new Promise((complete) => {
    let stdout = "";
    let stderr = "";
    let settled = false;
    let timedOut = false;
    let exceeded = false;
    let timer;
    const finish = (value) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      complete(value);
    };
    const child = spawn(python, childArgs, {cwd: process.cwd(), windowsHide: true, signal: exec.signal});
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    const capture = (target, chunk) => {
      if (Buffer.byteLength(stdout) + Buffer.byteLength(stderr) + Buffer.byteLength(chunk) > MAX_CAPTURE_BYTES) {
        exceeded = true;
        child.kill();
        return target;
      }
      return target + chunk;
    };
    child.stdout.on("data", (chunk) => { stdout = capture(stdout, chunk); });
    child.stderr.on("data", (chunk) => { stderr = capture(stderr, chunk); });
    child.on("error", (error) => finish({status: "PLUGIN_ERROR", code: "SPAWN_ERROR", detail: error.message}));
    child.on("close", (code) => {
      stdout = stdout.trim();
      stderr = stderr.trim();
      if (exceeded) return finish({status: "PLUGIN_ERROR", code: "OUTPUT_LIMIT_EXCEEDED", stderr});
      if (timedOut) return finish({status: "PLUGIN_ERROR", code: "TIMEOUT", timeout_ms: timeoutMs, stderr});
      if (code !== 0) return finish({status: "PLUGIN_ERROR", code: "PYTHON_EXIT_NONZERO", return_code: code, stdout, stderr});
      try { finish(JSON.parse(stdout || "{}")); }
      catch (error) { finish({status: "PLUGIN_ERROR", code: "PYTHON_JSON_ERROR", detail: error.message, stdout, stderr}); }
    });
    if (timeoutMs !== undefined) timer = setTimeout(() => { timedOut = true; child.kill(); }, timeoutMs);
  });
}

export const name = "proofaudit-dsh-plugin";
export const inject = ["tools"];

export function apply(ctx, config = {}) {
  const roots = allowedRoots(config);
  ctx.tools.register(defineTool({
    name: "proof_audit_run",
    description: "Run a standalone ProofAudit case. PASS requires all typed evidence and assurance gates.",
    parameters: {
      case: {type: "string", required: true, description: "CaseSpec path under an allowed root."},
      artifact_dir: {type: "string", required: true, description: "Output directory under an allowed root."},
      timeout_ms: {type: "integer", description: "Optional hard timeout in milliseconds."}
    },
    output: {schema: {type: "json"}, render: (_args, value) => [{type: "text", text: JSON.stringify(value, null, 2)}]},
    isConcurrencySafe: () => false,
    async execute(args, exec) { return executeAudit(args, exec, roots); }
  }));
}

