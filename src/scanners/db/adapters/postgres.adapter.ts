import pg from "pg";
import type { IDbAdapter } from "./base.adapter.js";
import type { ColumnInfo, ColumnStats, DbConnectionConfig } from "../../../types.js";

const { Pool } = pg;

export class PostgresAdapter implements IDbAdapter {
  private pool: pg.Pool | null = null;
  private config: DbConnectionConfig;

  constructor(config: DbConnectionConfig) {
    this.config = config;
  }

  async connect(): Promise<void> {
    this.pool = new Pool({
      host: this.config.host ?? "localhost",
      port: this.config.port ?? 5432,
      database: this.config.database,
      user: this.config.username,
      password: this.config.password,
      ssl: this.config.ssl ? { rejectUnauthorized: false } : false,
      max: 2,
    });

    // 읽기전용 강제: 세션 레벨에서 트랜잭션을 읽기전용으로 설정
    const client = await this.pool.connect();
    try {
      await client.query("SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY");

      // 실제로 읽기전용이 적용됐는지 검증
      const res = await client.query<{ transaction_read_only: string }>(
        "SHOW transaction_read_only"
      );
      const isReadOnly = res.rows[0]?.transaction_read_only === "on";

      if (!isReadOnly) {
        throw new Error(
          "PostgreSQL 세션을 읽기전용으로 설정할 수 없습니다. " +
            "읽기전용 사용자 또는 읽기전용 복제 연결을 사용하세요."
        );
      }
    } finally {
      client.release();
    }
  }

  async disconnect(): Promise<void> {
    await this.pool?.end();
    this.pool = null;
  }

  async listColumns(schemas: string[]): Promise<ColumnInfo[]> {
    if (!this.pool) throw new Error("연결되지 않은 상태입니다.");

    const res = await this.pool.query<{
      table_schema: string;
      table_name: string;
      column_name: string;
      data_type: string;
      is_nullable: string;
      character_maximum_length: number | null;
    }>(
      `SELECT
         table_schema,
         table_name,
         column_name,
         data_type,
         is_nullable,
         character_maximum_length
       FROM information_schema.columns
       WHERE table_schema = ANY($1::text[])
         AND table_schema NOT IN ('pg_catalog','information_schema')
       ORDER BY table_schema, table_name, ordinal_position`,
      [schemas]
    );

    return res.rows.map((r) => ({
      schema: r.table_schema,
      table: r.table_name,
      column: r.column_name,
      dataType: r.data_type,
      isNullable: r.is_nullable === "YES",
      maxLength: r.character_maximum_length ?? undefined,
    }));
  }

  async getColumnStats(
    schema: string,
    table: string,
    column: string,
    sampleLimit: number
  ): Promise<ColumnStats> {
    if (!this.pool) throw new Error("연결되지 않은 상태입니다.");

    const fqn = `"${schema}"."${table}"."${column}"`;
    const fqt = `"${schema}"."${table}"`;

    const statsRes = await this.pool.query<{
      total_rows: string;
      non_null_rows: string;
      distinct_count: string;
      min_len: string | null;
      max_len: string | null;
      avg_len: string | null;
    }>(
      `SELECT
         COUNT(*) AS total_rows,
         COUNT(${fqn}) AS non_null_rows,
         COUNT(DISTINCT ${fqn}) AS distinct_count,
         MIN(LENGTH(${fqn}::text)) AS min_len,
         MAX(LENGTH(${fqn}::text)) AS max_len,
         ROUND(AVG(LENGTH(${fqn}::text)), 1) AS avg_len
       FROM ${fqt}`
    );

    const sampleRes = await this.pool.query<Record<string, unknown>>(
      `SELECT ${fqn}::text AS val
       FROM ${fqt}
       WHERE ${fqn} IS NOT NULL
       LIMIT $1`,
      [sampleLimit]
    );

    const sr = statsRes.rows[0];
    const totalRows = parseInt(sr.total_rows, 10);
    const nonNullRows = parseInt(sr.non_null_rows, 10);
    const distinctCount = parseInt(sr.distinct_count, 10);

    return {
      totalRows,
      nonNullRows,
      nullRatio: totalRows > 0 ? (totalRows - nonNullRows) / totalRows : 0,
      fillRate: totalRows > 0 ? nonNullRows / totalRows : 0,
      distinctCount,
      distinctRatio: nonNullRows > 0 ? distinctCount / nonNullRows : 0,
      minLength: sr.min_len != null ? parseInt(sr.min_len, 10) : undefined,
      maxLength: sr.max_len != null ? parseInt(sr.max_len, 10) : undefined,
      avgLength: sr.avg_len != null ? parseFloat(sr.avg_len) : undefined,
      samples: sampleRes.rows.map((r) => String(r.val ?? "")),
    };
  }

  databaseName(): string {
    return this.config.database;
  }
}
