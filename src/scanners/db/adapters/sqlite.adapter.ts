import BetterSqlite3 from "better-sqlite3";
import type { IDbAdapter } from "./base.adapter.js";
import type { ColumnInfo, ColumnStats, DbConnectionConfig } from "../../../types.js";

export class SqliteAdapter implements IDbAdapter {
  private db: BetterSqlite3.Database | null = null;
  private config: DbConnectionConfig;

  constructor(config: DbConnectionConfig) {
    this.config = config;
  }

  async connect(): Promise<void> {
    const filePath = this.config.filePath ?? this.config.database;

    // readonly: true → OS 레벨에서 쓰기 불가 (가장 강력한 읽기전용 보장)
    this.db = new BetterSqlite3(filePath, { readonly: true });
  }

  async disconnect(): Promise<void> {
    this.db?.close();
    this.db = null;
  }

  async listColumns(
    _schemas: string[] // SQLite는 스키마 개념이 없으므로 무시
  ): Promise<ColumnInfo[]> {
    if (!this.db) throw new Error("연결되지 않은 상태입니다.");

    const tables = this.db
      .prepare(
        `SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'`
      )
      .all() as { name: string }[];

    const columns: ColumnInfo[] = [];
    for (const t of tables) {
      const info = this.db
        .prepare(`PRAGMA table_info("${t.name}")`)
        .all() as {
        cid: number;
        name: string;
        type: string;
        notnull: number;
      }[];

      for (const col of info) {
        columns.push({
          schema: "main",
          table: t.name,
          column: col.name,
          dataType: col.type || "TEXT",
          isNullable: col.notnull === 0,
        });
      }
    }
    return columns;
  }

  async getColumnStats(
    _schema: string,
    table: string,
    column: string,
    sampleLimit: number
  ): Promise<ColumnStats> {
    if (!this.db) throw new Error("연결되지 않은 상태입니다.");

    const statsRow = this.db
      .prepare(
        `SELECT
           COUNT(*) AS total_rows,
           COUNT("${column}") AS non_null_rows,
           COUNT(DISTINCT "${column}") AS distinct_count,
           MIN(LENGTH(CAST("${column}" AS TEXT))) AS min_len,
           MAX(LENGTH(CAST("${column}" AS TEXT))) AS max_len,
           AVG(LENGTH(CAST("${column}" AS TEXT))) AS avg_len
         FROM "${table}"`
      )
      .get() as {
      total_rows: number;
      non_null_rows: number;
      distinct_count: number;
      min_len: number | null;
      max_len: number | null;
      avg_len: number | null;
    };

    const sampleRows = this.db
      .prepare(
        `SELECT CAST("${column}" AS TEXT) AS val
         FROM "${table}"
         WHERE "${column}" IS NOT NULL
         LIMIT ${sampleLimit}`
      )
      .all() as { val: string }[];

    const totalRows = Number(statsRow.total_rows);
    const nonNullRows = Number(statsRow.non_null_rows);
    const distinctCount = Number(statsRow.distinct_count);

    return {
      totalRows,
      nonNullRows,
      nullRatio: totalRows > 0 ? (totalRows - nonNullRows) / totalRows : 0,
      fillRate: totalRows > 0 ? nonNullRows / totalRows : 0,
      distinctCount,
      distinctRatio: nonNullRows > 0 ? distinctCount / nonNullRows : 0,
      minLength: statsRow.min_len ?? undefined,
      maxLength: statsRow.max_len ?? undefined,
      avgLength: statsRow.avg_len != null ? parseFloat(statsRow.avg_len.toFixed(1)) : undefined,
      samples: sampleRows.map((r) => r.val ?? ""),
    };
  }

  databaseName(): string {
    return this.config.filePath ?? this.config.database;
  }
}
