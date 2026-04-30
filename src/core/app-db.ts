import Database from "better-sqlite3";
import { existsSync, mkdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { CodeTargetConfig, DbConnectionConfig, RuleOverride, ScanConfig, ScanFinding, ScanReport, ScanSummary } from "../types.js";

type JsonValue = string | number | boolean | null | JsonValue[] | { [key: string]: JsonValue };

export interface PersistedAuthUser {
  tenantId: string;
  userId: string;
  username: string;
  email?: string;
  displayName?: string;
  roles?: string[];
}

export interface AuditLogRecord {
  tenantId: string;
  userId?: string;
  type: string;
  name: string;
  action: string;
  payload: unknown;
}

export interface PersistedScanRecord {
  id: string;
  tenantId: string;
  configId: string;
  configName: string;
  status: ScanReport["status"];
  startedAt: string;
  completedAt?: string;
  errorMessage?: string;
  summary: ScanSummary;
  findings: ScanFinding[];
  createdByUserId?: string;
}

interface ConfigRow {
  id: string;
  tenant_id: string;
  name: string;
  description: string | null;
  db_targets_json: string;
  code_targets_json: string;
  rule_override_json: string | null;
  created_at: string;
  updated_at: string;
}

interface ScanRow {
  id: string;
  tenant_id: string;
  config_id: string;
  config_name: string;
  status: ScanReport["status"];
  started_at: string;
  completed_at: string | null;
  error_message: string | null;
  summary_json: string;
  findings_json: string;
}

const DATA_DIR = join(process.cwd(), "data");
const DB_PATH = join(DATA_DIR, process.env.APP_DB_PATH?.trim() || "scanner.db");
const LEGACY_CONFIG_INDEX_PATH = join(DATA_DIR, "configs", "index.json");

function ensureDir(path: string): void {
  if (!existsSync(path)) {
    mkdirSync(path, { recursive: true });
  }
}

function serializeJson(value: unknown): string {
  return JSON.stringify(value ?? null);
}

function parseJson<T>(value: string | null | undefined, fallback: T): T {
  if (!value) return fallback;
  try {
    return JSON.parse(value) as T;
  } catch {
    return fallback;
  }
}

function toScanConfig(row: ConfigRow): ScanConfig {
  return {
    id: row.id,
    tenantId: row.tenant_id,
    name: row.name,
    description: row.description ?? undefined,
    dbTargets: parseJson<DbConnectionConfig[]>(row.db_targets_json, []),
    codeTargets: parseJson<CodeTargetConfig[]>(row.code_targets_json, []),
    ruleOverride: parseJson<RuleOverride | undefined>(row.rule_override_json, undefined),
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function toScanReport(row: ScanRow): ScanReport {
  return {
    id: row.id,
    tenantId: row.tenant_id,
    configId: row.config_id,
    configName: row.config_name,
    status: row.status,
    startedAt: row.started_at,
    completedAt: row.completed_at ?? undefined,
    errorMessage: row.error_message ?? undefined,
    summary: parseJson<ScanSummary>(row.summary_json, {
      totalFindings: 0,
      bySeverity: { critical: 0, high: 0, medium: 0, low: 0 },
      byCategory: { pii: 0, financial: 0, credentials: 0, health: 0, oauth: 0, device: 0, biometric: 0, certificate: 0, custom: 0 },
      bySource: { code: 0, database: 0 },
      aiDroppedCount: 0,
      tablesScanned: 0,
      columnsScanned: 0,
      filesScanned: 0,
      linesScanned: 0,
      durationMs: 0,
    }),
    findings: parseJson<ScanFinding[]>(row.findings_json, []),
  };
}

class AppDatabase {
  private readonly db: Database.Database;

  constructor() {
    ensureDir(DATA_DIR);
    this.db = new Database(DB_PATH);
    this.db.pragma("journal_mode = WAL");
    this.db.pragma("foreign_keys = ON");
    this.initialize();
    this.importLegacyConfigsIfNeeded();
  }

  private initialize(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS tenants (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        username TEXT NOT NULL,
        email TEXT,
        display_name TEXT,
        roles_json TEXT NOT NULL DEFAULT '[]',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        UNIQUE(tenant_id, username),
        FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
      );

      CREATE TABLE IF NOT EXISTS scan_configs (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        name TEXT NOT NULL,
        description TEXT,
        db_targets_json TEXT NOT NULL,
        code_targets_json TEXT NOT NULL,
        rule_override_json TEXT,
        created_by_user_id TEXT,
        updated_by_user_id TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
        FOREIGN KEY (created_by_user_id) REFERENCES users(id) ON DELETE SET NULL,
        FOREIGN KEY (updated_by_user_id) REFERENCES users(id) ON DELETE SET NULL
      );

      CREATE TABLE IF NOT EXISTS scan_reports (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        config_id TEXT NOT NULL,
        config_name TEXT NOT NULL,
        status TEXT NOT NULL,
        started_at TEXT NOT NULL,
        completed_at TEXT,
        error_message TEXT,
        summary_json TEXT NOT NULL,
        findings_json TEXT NOT NULL,
        created_by_user_id TEXT,
        FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
        FOREIGN KEY (created_by_user_id) REFERENCES users(id) ON DELETE SET NULL
      );

      CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tenant_id TEXT NOT NULL,
        user_id TEXT,
        type TEXT NOT NULL,
        name TEXT NOT NULL,
        action TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
      );

      CREATE INDEX IF NOT EXISTS idx_scan_configs_tenant_id ON scan_configs(tenant_id, updated_at DESC);
      CREATE INDEX IF NOT EXISTS idx_scan_reports_tenant_id ON scan_reports(tenant_id, started_at DESC);
      CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant_id ON audit_logs(tenant_id, created_at DESC);
    `);
  }

  private importLegacyConfigsIfNeeded(): void {
    const countRow = this.db.prepare("SELECT COUNT(*) as count FROM scan_configs").get() as { count: number };
    if (countRow.count > 0 || !existsSync(LEGACY_CONFIG_INDEX_PATH)) return;

    const raw = readFileSync(LEGACY_CONFIG_INDEX_PATH, "utf-8");
    const configs = parseJson<ScanConfig[]>(raw, []);
    const insert = this.db.prepare(`
      INSERT OR IGNORE INTO scan_configs (
        id, tenant_id, name, description, db_targets_json, code_targets_json, rule_override_json,
        created_by_user_id, updated_by_user_id, created_at, updated_at
      ) VALUES (
        @id, @tenantId, @name, @description, @dbTargetsJson, @codeTargetsJson, @ruleOverrideJson,
        NULL, NULL, @createdAt, @updatedAt
      )
    `);

    const transaction = this.db.transaction((items: ScanConfig[]) => {
      for (const config of items) {
        const tenantId = config.tenantId?.trim() || "default";
        this.ensureTenant(tenantId, tenantId);
        insert.run({
          id: config.id,
          tenantId,
          name: config.name,
          description: config.description ?? null,
          dbTargetsJson: serializeJson(config.dbTargets),
          codeTargetsJson: serializeJson(config.codeTargets),
          ruleOverrideJson: config.ruleOverride ? serializeJson(config.ruleOverride) : null,
          createdAt: config.createdAt,
          updatedAt: config.updatedAt,
        });
      }
    });
    transaction(configs);
  }

  ensureTenant(tenantId: string, name?: string): void {
    const now = new Date().toISOString();
    this.db.prepare(`
      INSERT INTO tenants (id, name, created_at, updated_at)
      VALUES (@id, @name, @now, @now)
      ON CONFLICT(id) DO UPDATE SET
        name = excluded.name,
        updated_at = excluded.updated_at
    `).run({
      id: tenantId,
      name: name ?? tenantId,
      now,
    });
  }

  upsertUser(user: PersistedAuthUser): void {
    const now = new Date().toISOString();
    this.ensureTenant(user.tenantId, user.tenantId);
    this.db.prepare(`
      INSERT INTO users (id, tenant_id, username, email, display_name, roles_json, created_at, updated_at)
      VALUES (@id, @tenantId, @username, @email, @displayName, @rolesJson, @now, @now)
      ON CONFLICT(id) DO UPDATE SET
        tenant_id = excluded.tenant_id,
        username = excluded.username,
        email = excluded.email,
        display_name = excluded.display_name,
        roles_json = excluded.roles_json,
        updated_at = excluded.updated_at
    `).run({
      id: user.userId,
      tenantId: user.tenantId,
      username: user.username,
      email: user.email ?? null,
      displayName: user.displayName ?? null,
      rolesJson: serializeJson(user.roles ?? []),
      now,
    });
  }

  listConfigs(tenantId: string): ScanConfig[] {
    const rows = this.db.prepare(`
      SELECT id, tenant_id, name, description, db_targets_json, code_targets_json, rule_override_json, created_at, updated_at
      FROM scan_configs
      WHERE tenant_id = ?
      ORDER BY updated_at DESC
    `).all(tenantId) as ConfigRow[];
    return rows.map(toScanConfig);
  }

  getConfig(id: string, tenantId: string): ScanConfig | null {
    const row = this.db.prepare(`
      SELECT id, tenant_id, name, description, db_targets_json, code_targets_json, rule_override_json, created_at, updated_at
      FROM scan_configs
      WHERE id = ? AND tenant_id = ?
      LIMIT 1
    `).get(id, tenantId) as ConfigRow | undefined;
    return row ? toScanConfig(row) : null;
  }

  saveConfig(config: ScanConfig, actorUserId?: string): ScanConfig {
    this.ensureTenant(config.tenantId ?? "default", config.tenantId ?? "default");
    this.db.prepare(`
      INSERT INTO scan_configs (
        id, tenant_id, name, description, db_targets_json, code_targets_json, rule_override_json,
        created_by_user_id, updated_by_user_id, created_at, updated_at
      ) VALUES (
        @id, @tenantId, @name, @description, @dbTargetsJson, @codeTargetsJson, @ruleOverrideJson,
        @actorUserId, @actorUserId, @createdAt, @updatedAt
      )
      ON CONFLICT(id) DO UPDATE SET
        tenant_id = excluded.tenant_id,
        name = excluded.name,
        description = excluded.description,
        db_targets_json = excluded.db_targets_json,
        code_targets_json = excluded.code_targets_json,
        rule_override_json = excluded.rule_override_json,
        updated_by_user_id = excluded.updated_by_user_id,
        updated_at = excluded.updated_at
    `).run({
      id: config.id,
      tenantId: config.tenantId ?? "default",
      name: config.name,
      description: config.description ?? null,
      dbTargetsJson: serializeJson(config.dbTargets),
      codeTargetsJson: serializeJson(config.codeTargets),
      ruleOverrideJson: config.ruleOverride ? serializeJson(config.ruleOverride as JsonValue) : null,
      actorUserId: actorUserId ?? null,
      createdAt: config.createdAt,
      updatedAt: config.updatedAt,
    });
    return config;
  }

  deleteConfig(id: string, tenantId: string): boolean {
    const result = this.db.prepare("DELETE FROM scan_configs WHERE id = ? AND tenant_id = ?").run(id, tenantId);
    return result.changes > 0;
  }

  upsertScanReport(record: PersistedScanRecord): void {
    this.ensureTenant(record.tenantId, record.tenantId);
    this.db.prepare(`
      INSERT INTO scan_reports (
        id, tenant_id, config_id, config_name, status, started_at, completed_at, error_message,
        summary_json, findings_json, created_by_user_id
      ) VALUES (
        @id, @tenantId, @configId, @configName, @status, @startedAt, @completedAt, @errorMessage,
        @summaryJson, @findingsJson, @createdByUserId
      )
      ON CONFLICT(id) DO UPDATE SET
        tenant_id = excluded.tenant_id,
        config_id = excluded.config_id,
        config_name = excluded.config_name,
        status = excluded.status,
        started_at = excluded.started_at,
        completed_at = excluded.completed_at,
        error_message = excluded.error_message,
        summary_json = excluded.summary_json,
        findings_json = excluded.findings_json,
        created_by_user_id = COALESCE(scan_reports.created_by_user_id, excluded.created_by_user_id)
    `).run({
      id: record.id,
      tenantId: record.tenantId,
      configId: record.configId,
      configName: record.configName,
      status: record.status,
      startedAt: record.startedAt,
      completedAt: record.completedAt ?? null,
      errorMessage: record.errorMessage ?? null,
      summaryJson: serializeJson(record.summary),
      findingsJson: serializeJson(record.findings),
      createdByUserId: record.createdByUserId ?? null,
    });
  }

  getScanReport(scanId: string, tenantId: string): ScanReport | null {
    const row = this.db.prepare(`
      SELECT id, tenant_id, config_id, config_name, status, started_at, completed_at, error_message, summary_json, findings_json
      FROM scan_reports
      WHERE id = ? AND tenant_id = ?
      LIMIT 1
    `).get(scanId, tenantId) as ScanRow | undefined;
    return row ? toScanReport(row) : null;
  }

  listScanReports(tenantId: string): ScanReport[] {
    const rows = this.db.prepare(`
      SELECT id, tenant_id, config_id, config_name, status, started_at, completed_at, error_message, summary_json, findings_json
      FROM scan_reports
      WHERE tenant_id = ?
      ORDER BY started_at DESC
    `).all(tenantId) as ScanRow[];
    return rows.map(toScanReport);
  }

  writeAuditLog(record: AuditLogRecord): number {
    this.ensureTenant(record.tenantId, record.tenantId);
    const now = new Date().toISOString();
    const result = this.db.prepare(`
      INSERT INTO audit_logs (tenant_id, user_id, type, name, action, payload_json, created_at)
      VALUES (@tenantId, @userId, @type, @name, @action, @payloadJson, @createdAt)
    `).run({
      tenantId: record.tenantId,
      userId: record.userId ?? null,
      type: record.type,
      name: record.name,
      action: record.action,
      payloadJson: serializeJson(record.payload),
      createdAt: now,
    });
    return Number(result.lastInsertRowid);
  }

  getDatabasePath(): string {
    return DB_PATH;
  }
}

const appDb = new AppDatabase();

export { appDb, DB_PATH };