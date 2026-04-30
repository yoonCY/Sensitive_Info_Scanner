import type { RuleEngine } from "../../core/rule-engine.js";
import type {
  DbConnectionConfig,
  DbFinding,
  ColumnStats,
} from "../../types.js";
import { PostgresAdapter } from "./adapters/postgres.adapter.js";
import { MysqlAdapter } from "./adapters/mysql.adapter.js";
import { SqliteAdapter } from "./adapters/sqlite.adapter.js";
import type { IDbAdapter } from "./adapters/base.adapter.js";

export interface DbScanOptions {
  dataSamplingEnabled?: boolean;
  sampleRowLimit?: number;
  statsEnabled?: boolean;
  onProgress?: (message: string) => void;
}

function createAdapter(config: DbConnectionConfig): IDbAdapter {
  switch (config.dialect) {
    case "postgresql":
      return new PostgresAdapter(config);
    case "mysql":
      return new MysqlAdapter(config);
    case "sqlite":
      return new SqliteAdapter(config);
    default:
      throw new Error(`지원하지 않는 DB 방언: ${(config as DbConnectionConfig).dialect}`);
  }
}

// ─────────────────────────────────────────────────────────────────────────────

export class DbScanner {
  constructor(private readonly ruleEngine: RuleEngine) {}

  async scan(
    config: DbConnectionConfig,
    options: DbScanOptions = {}
  ): Promise<DbFinding[]> {
    const {
      dataSamplingEnabled = true,
      sampleRowLimit = 100,
      statsEnabled = true,
      onProgress,
    } = options;

    // SQLite가 아닌 경우 스키마 필수 검증
    if (config.dialect !== "sqlite" && (!config.schemas || config.schemas.length === 0)) {
      throw new Error(
        `스키마를 지정하지 않으면 DB 스캔을 수행하지 않습니다. ` +
          `DB: ${config.database}`
      );
    }

    const adapter = createAdapter(config);
    onProgress?.(`[DB] ${config.dialect}://${config.database} 연결 중...`);

    await adapter.connect();
    onProgress?.(`[DB] 읽기전용 세션 확인 완료`);

    const schemas = config.schemas ?? ["main"]; // SQLite 기본값

    try {
      const columns = await adapter.listColumns(schemas);
      onProgress?.(`[DB] 컬럼 ${columns.length}개 로드 완료`);

      const findings: DbFinding[] = [];

      for (const col of columns) {
        // 1단계: 컬럼명 패턴 매칭
        const nameRules = this.ruleEngine.matchColumnName(col.column);

        if (nameRules.length === 0 && !dataSamplingEnabled) continue;

        // 2단계: 통계 + 샘플링
        let stats: ColumnStats | undefined;
        let dataRules: ReturnType<typeof this.ruleEngine.matchDataValue> = [];

        if (statsEnabled || dataSamplingEnabled) {
          try {
            stats = await adapter.getColumnStats(
              col.schema,
              col.table,
              col.column,
              sampleRowLimit
            );

            // 3단계: 샘플 데이터 값 패턴 매칭
            if (dataSamplingEnabled && stats && stats.samples.length > 0) {
              const matched = new Set<string>();
              for (const sample of stats.samples) {
                for (const rule of this.ruleEngine.matchDataValue(sample)) {
                  matched.add(rule.id);
                }
              }
              dataRules = this.ruleEngine
                .getRules()
                .filter((r) => matched.has(r.id));
            }

            // 레드액션: 샘플 값 마스킹
            if (stats) {
              stats = {
                ...stats,
                samples: stats.samples.map((s) =>
                  this.ruleEngine.redactValue(s)
                ),
              };
            }
          } catch {
            // 통계 조회 실패는 무시하고 컬럼명 결과만 사용
          }
        }

        // 결과 병합
        const allRuleIds = new Set([
          ...nameRules.map((r) => r.id),
          ...dataRules.map((r) => r.id),
        ]);

        if (allRuleIds.size === 0) continue;

        const isNameMatch = nameRules.length > 0;
        const isDataMatch = dataRules.length > 0;

        for (const ruleId of allRuleIds) {
          const rule =
            nameRules.find((r) => r.id === ruleId) ??
            dataRules.find((r) => r.id === ruleId)!;

          findings.push({
            source: "database",
            ruleId: rule.id,
            ruleName: rule.name,
            category: rule.category,
            severity: rule.severity,
            dialect: config.dialect,
            database: adapter.databaseName(),
            schema: col.schema,
            table: col.table,
            column: col.column,
            columnType: col.dataType,
            matchedBy:
              isNameMatch && isDataMatch
                ? "both"
                : isDataMatch
                  ? "data_sample"
                  : "column_name",
            stats,
            columnPatternMatched: isNameMatch ? rule.columnPattern?.source : undefined,
            dataPatternMatched: isDataMatch ? rule.dataPattern?.source : undefined,
          });
        }
      }

      onProgress?.(`[DB] 스캔 완료 - 발견 ${findings.length}건`);
      return findings;
    } finally {
      await adapter.disconnect();
    }
  }
}
