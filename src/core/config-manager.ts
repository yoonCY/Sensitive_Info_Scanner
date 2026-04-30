import { v4 as uuidv4 } from "uuid";
import type { ScanConfig, DbConnectionConfig, CodeTargetConfig, RuleOverride } from "../types.js";
import type { AuthContext } from "./auth-context.js";
import { appDb } from "./app-db.js";
import { writeAuditLog } from "../core/audit-logger.js";

const DEFAULT_TENANT_ID = (process.env.DEFAULT_TENANT_ID ?? "default").trim() || "default";

function normalizeTenantId(tenantId?: string): string {
  const value = tenantId?.trim();
  return value || DEFAULT_TENANT_ID;
}

function normalizeConfig(config: ScanConfig): ScanConfig {
  return {
    ...config,
    tenantId: normalizeTenantId(config.tenantId),
  };
}

export class ConfigManager {
  listConfigs(tenantId?: string): ScanConfig[] {
    const normalizedTenantId = normalizeTenantId(tenantId);
    const configs = appDb.listConfigs(normalizedTenantId);
    return configs.filter((config) => config.tenantId === normalizedTenantId);
  }

  getConfig(id: string, tenantId?: string): ScanConfig | null {
    const normalizedTenantId = normalizeTenantId(tenantId);
    const config = appDb.getConfig(id, normalizedTenantId);
    return config ? normalizeConfig(config) : null;
  }

  createConfig(input: {
    tenantId?: string;
    actor?: Pick<AuthContext, "tenantId" | "userId">;
    name: string;
    description?: string;
    dbTargets?: DbConnectionConfig[];
    codeTargets?: CodeTargetConfig[];
    ruleOverride?: RuleOverride;
  }): ScanConfig {
    this.validateDbTargets(input.dbTargets ?? []);

    const now = new Date().toISOString();
    const config: ScanConfig = {
      id: uuidv4(),
      tenantId: normalizeTenantId(input.tenantId),
      name: input.name,
      description: input.description,
      dbTargets: input.dbTargets ?? [],
      codeTargets: input.codeTargets ?? [],
      ruleOverride: input.ruleOverride,
      createdAt: now,
      updatedAt: now,
    };

    appDb.saveConfig(config, input.actor?.userId);
    writeAuditLog("settings", config.name, {
      action: "create",
      configId: config.id,
      config,
    }, { tenantId: config.tenantId ?? DEFAULT_TENANT_ID, userId: input.actor?.userId });
    return config;
  }

  updateConfig(
    id: string,
    patch: Partial<Omit<ScanConfig, "id" | "createdAt">>,
    tenantId?: string,
    actor?: Pick<AuthContext, "tenantId" | "userId">
  ): ScanConfig {
    const normalizedTenantId = normalizeTenantId(tenantId);
    const current = appDb.getConfig(id, normalizedTenantId);
    if (!current) throw new Error(`설정을 찾을 수 없습니다: ${id}`);

    if (patch.dbTargets) {
      this.validateDbTargets(patch.dbTargets);
    }

    const updated: ScanConfig = {
      ...current,
      ...patch,
      tenantId: current.tenantId,
      id,
      updatedAt: new Date().toISOString(),
    };
    appDb.saveConfig(updated, actor?.userId);
    writeAuditLog("settings", updated.name, {
      action: "update",
      configId: updated.id,
      patch,
      updatedConfig: updated,
    }, { tenantId: updated.tenantId ?? DEFAULT_TENANT_ID, userId: actor?.userId });
    return updated;
  }

  deleteConfig(id: string, tenantId?: string, actor?: Pick<AuthContext, "tenantId" | "userId">): void {
    const normalizedTenantId = normalizeTenantId(tenantId);
    const deleted = appDb.getConfig(id, normalizedTenantId);
    if (!deleted || !appDb.deleteConfig(id, normalizedTenantId)) {
      throw new Error(`설정을 찾을 수 없습니다: ${id}`);
    }
    writeAuditLog("settings", deleted?.name ?? id, {
      action: "delete",
      configId: id,
      deletedConfig: deleted ?? null,
    }, { tenantId: normalizedTenantId, userId: actor?.userId });
  }

  private validateDbTargets(targets: DbConnectionConfig[]): void {
    for (const t of targets) {
      if (t.dialect !== "sqlite") {
        // SQLite는 스키마 개념이 단순하므로 예외 허용
        if (!t.schemas || t.schemas.length === 0) {
          throw new Error(
            `DB 대상 "${t.database}"에 스키마를 반드시 지정해야 합니다. ` +
              "스키마 미지정 시 전체 DB 스캔을 수행하지 않습니다."
          );
        }
      }
    }
  }
}
