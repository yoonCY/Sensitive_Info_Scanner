import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { v4 as uuidv4 } from "uuid";
import type { ScanConfig, DbConnectionConfig, CodeTargetConfig, RuleOverride } from "../types.js";

const DATA_DIR = join(process.cwd(), "data", "configs");

function ensureDataDir(): void {
  if (!existsSync(DATA_DIR)) {
    mkdirSync(DATA_DIR, { recursive: true });
  }
}

function configPath(id: string): string {
  return join(DATA_DIR, `${id}.json`);
}

function loadAll(): ScanConfig[] {
  ensureDataDir();
  if (!existsSync(join(DATA_DIR, "index.json"))) return [];
  const raw = readFileSync(join(DATA_DIR, "index.json"), "utf-8");
  return JSON.parse(raw) as ScanConfig[];
}

function saveAll(configs: ScanConfig[]): void {
  ensureDataDir();
  writeFileSync(
    join(DATA_DIR, "index.json"),
    JSON.stringify(configs, null, 2),
    "utf-8"
  );
}

// ─────────────────────────────────────────────

export class ConfigManager {
  listConfigs(): ScanConfig[] {
    return loadAll();
  }

  getConfig(id: string): ScanConfig | null {
    const all = loadAll();
    return all.find((c) => c.id === id) ?? null;
  }

  createConfig(input: {
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
      name: input.name,
      description: input.description,
      dbTargets: input.dbTargets ?? [],
      codeTargets: input.codeTargets ?? [],
      ruleOverride: input.ruleOverride,
      createdAt: now,
      updatedAt: now,
    };

    const all = loadAll();
    all.push(config);
    saveAll(all);
    return config;
  }

  updateConfig(
    id: string,
    patch: Partial<Omit<ScanConfig, "id" | "createdAt">>
  ): ScanConfig {
    const all = loadAll();
    const idx = all.findIndex((c) => c.id === id);
    if (idx === -1) throw new Error(`설정을 찾을 수 없습니다: ${id}`);

    if (patch.dbTargets) {
      this.validateDbTargets(patch.dbTargets);
    }

    const updated: ScanConfig = {
      ...all[idx],
      ...patch,
      id,
      updatedAt: new Date().toISOString(),
    };
    all[idx] = updated;
    saveAll(all);
    return updated;
  }

  deleteConfig(id: string): void {
    const all = loadAll();
    const filtered = all.filter((c) => c.id !== id);
    if (filtered.length === all.length) {
      throw new Error(`설정을 찾을 수 없습니다: ${id}`);
    }
    saveAll(filtered);
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
