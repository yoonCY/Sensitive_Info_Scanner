import { appendFileSync, existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { appDb } from "./app-db.js";
import type { AuthContext } from "./auth-context.js";

export type AuditLogType = "settings" | "report";
const MIRROR_TO_FILES = /^(1|true|yes)$/i.test(process.env.AUDIT_LOG_MIRROR_FILES ?? "");

function ensureDir(path: string): void {
  if (!existsSync(path)) {
    mkdirSync(path, { recursive: true });
  }
}

function timestampUtcCompact(date = new Date()): string {
  const y = date.getUTCFullYear();
  const m = String(date.getUTCMonth() + 1).padStart(2, "0");
  const d = String(date.getUTCDate()).padStart(2, "0");
  const hh = String(date.getUTCHours()).padStart(2, "0");
  const mm = String(date.getUTCMinutes()).padStart(2, "0");
  const ss = String(date.getUTCSeconds()).padStart(2, "0");
  return `${y}${m}${d}${hh}${mm}${ss}`;
}

function safeName(raw: string): string {
  return raw.replace(/[^a-zA-Z0-9._-]/g, "-").replace(/-+/g, "-").replace(/^-|-$/g, "") || "unknown";
}

export function writeAuditLog(type: AuditLogType, name: string, payload: unknown, actor?: Pick<AuthContext, "tenantId" | "userId">): string {
  const action = typeof payload === "object" && payload !== null && "action" in payload && typeof (payload as { action?: unknown }).action === "string"
    ? String((payload as { action: string }).action)
    : type;
  const tenantId = actor?.tenantId ?? "default";
  appDb.writeAuditLog({
    tenantId,
    userId: actor?.userId,
    type,
    name,
    action,
    payload,
  });

  if (!MIRROR_TO_FILES) {
    return appDb.getDatabasePath();
  }

  const root = join(process.cwd(), "logs");
  const dir = join(root, type);
  ensureDir(dir);

  const ts = timestampUtcCompact();
  const fileName = `${safeName(name)}__${ts}__UTC.log`;
  const path = join(dir, fileName);

  const body = {
    loggedAt: new Date().toISOString(),
    type,
    name,
    payload,
  };

  appendFileSync(path, JSON.stringify(body, null, 2) + "\n", "utf-8");
  return path;
}
