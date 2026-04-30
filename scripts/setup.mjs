import { createInterface } from "node:readline/promises";
import { stdin as input, stdout as output } from "node:process";
import { existsSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

const ROOT = process.cwd();
const ENV_PATH = resolve(ROOT, ".env");
const DEFAULT_HOST_PATH = "D:/projects/dart-ai-trading-bot";
const CONTAINER_PATH = "/workspace/dart-ai-trading-bot";
const DEFAULT_DB_PATH = "scanner.db";

function normalizeHostPath(raw) {
  return raw.replace(/^['\"]|['\"]$/g, "").trim().replace(/\\/g, "/");
}

function upsertEnvValue(fileContent, key, value) {
  const lines = fileContent.length > 0 ? fileContent.split(/\r?\n/) : [];
  const target = `${key}=${value}`;
  let replaced = false;

  const next = lines.map((line) => {
    if (/^\s*#/.test(line) || !line.includes("=")) return line;
    const eq = line.indexOf("=");
    const lineKey = line.slice(0, eq).trim();
    if (lineKey !== key) return line;
    replaced = true;
    return target;
  });

  if (!replaced) next.push(target);
  return `${next.join("\n").trimEnd()}\n`;
}

async function main() {
  output.write("\n=== Sensitive Info Scanner Setup ===\n");
  output.write("코드 루트, 인증 모드, SQLite 경로를 .env에 기록합니다.\n\n");

  const rl = createInterface({ input, output });
  try {
    const answer = await rl.question(`호스트 프로젝트 경로 [${DEFAULT_HOST_PATH}]: `);
    const selected = normalizeHostPath(answer || DEFAULT_HOST_PATH);

    if (!selected) {
      throw new Error("경로가 비어 있습니다.");
    }

    if (!existsSync(selected) || !statSync(selected).isDirectory()) {
      throw new Error(`유효한 폴더가 아닙니다: ${selected}`);
    }

    const authModeAnswer = await rl.question("인증 모드 [none/proxy] (기본 none): ");
    const authMode = (authModeAnswer || "none").trim().toLowerCase() === "proxy" ? "proxy" : "none";

    const requireAuthAnswer = await rl.question(`인증 강제 여부 [true/false] (기본 ${authMode === "proxy" ? "true" : "false"}): `);
    const requireAuth = (requireAuthAnswer || (authMode === "proxy" ? "true" : "false")).trim().toLowerCase();

    const allowedRootsAnswer = await rl.question(`허용 코드 루트(쉼표 구분) [${CONTAINER_PATH}]: `);
    const allowedCodeRoots = (allowedRootsAnswer || CONTAINER_PATH)
      .split(",")
      .map((value) => value.trim())
      .filter(Boolean)
      .join(",");

    const dbPathAnswer = await rl.question(`SQLite DB 파일명 [${DEFAULT_DB_PATH}]: `);
    const dbPath = (dbPathAnswer || DEFAULT_DB_PATH).trim() || DEFAULT_DB_PATH;

    const proxySecret = authMode === "proxy"
      ? await rl.question("프록시 shared secret (없으면 Enter): ")
      : "";

    const currentEnv = existsSync(ENV_PATH) ? readFileSync(ENV_PATH, "utf-8") : "";
    let updatedEnv = upsertEnvValue(currentEnv, "DART_REPO_HOST_PATH", selected);
    updatedEnv = upsertEnvValue(updatedEnv, "ALLOWED_CODE_ROOTS", allowedCodeRoots);
    updatedEnv = upsertEnvValue(updatedEnv, "AUTH_MODE", authMode);
    updatedEnv = upsertEnvValue(updatedEnv, "REQUIRE_AUTH", requireAuth === "true" || requireAuth === "1" || requireAuth === "yes" ? "true" : "false");
    updatedEnv = upsertEnvValue(updatedEnv, "APP_DB_PATH", dbPath);
    if (authMode === "proxy") {
      updatedEnv = upsertEnvValue(updatedEnv, "PROXY_TENANT_HEADER", "x-auth-request-tenant");
      updatedEnv = upsertEnvValue(updatedEnv, "PROXY_USER_HEADER", "x-auth-request-user");
      updatedEnv = upsertEnvValue(updatedEnv, "PROXY_EMAIL_HEADER", "x-auth-request-email");
      updatedEnv = upsertEnvValue(updatedEnv, "PROXY_ROLES_HEADER", "x-auth-request-groups");
      if (proxySecret.trim()) {
        updatedEnv = upsertEnvValue(updatedEnv, "PROXY_AUTH_SHARED_SECRET", proxySecret.trim());
      }
    }
    writeFileSync(ENV_PATH, updatedEnv, "utf-8");

    output.write("\n설정이 완료되었습니다.\n");
    output.write(`- 저장 파일: ${ENV_PATH}\n`);
    output.write(`- DART_REPO_HOST_PATH=${selected}\n`);
    output.write(`- AUTH_MODE=${authMode}\n`);
    output.write(`- ALLOWED_CODE_ROOTS=${allowedCodeRoots}\n`);
    output.write(`- APP_DB_PATH=${dbPath}\n`);
    output.write(`- 웹 UI 루트 경로 입력값: ${CONTAINER_PATH}\n\n`);
    output.write("다음 명령으로 웹 UI를 다시 올려주세요:\n");
    output.write("docker compose -f docker-compose.yml -f docker-compose.shared-ai-net.yml up -d web\n\n");
  } finally {
    rl.close();
  }
}

main().catch((err) => {
  console.error(`설정 실패: ${err instanceof Error ? err.message : String(err)}`);
  process.exitCode = 1;
});
