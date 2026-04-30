import mysql from "mysql2/promise";
import type { IDbAdapter } from "./base.adapter.js";
import type { ColumnInfo, ColumnStats, DbConnectionConfig } from "../../../types.js";

export class MysqlAdapter implements IDbAdapter {
  private connection: mysql.Connection | null = null;
  private config: DbConnectionConfig;

  constructor(config: DbConnectionConfig) {
    this.config = config;
  }

  async connect(): Promise<void> {
    this.connection = await mysql.createConnection({
      host: this.config.host ?? "localhost",
      port: this.config.port ?? 3306,
      database: this.config.database,
      user: this.config.username,
      password: this.config.password,
      ssl: this.config.ssl ? {} : undefined,
    });

    // 읽기전용 강제: 트랜잭션을 READ ONLY로 시작
    await this.connection.query("SET SESSION TRANSACTION READ ONLY");
    await this.connection.beginTransaction();

    // 실제 읽기 검증: 쓰기 시도 시 에러가 나야 함
    // MySQL에서는 READ ONLY 트랜잭션 내에서 DML 실행 시 에러 발생
    // 추가로 global read_only 변수도 확인
    const [rows] = await this.connection.query<mysql.RowDataPacket[]>(
      "SELECT @@SESSION.transaction_read_only AS ro"
    );
    const isReadOnly = rows[0]?.ro === 1;

    if (!isReadOnly) {
      await this.connection.end();
      this.connection = null;
      throw new Error(
        "MySQL 세션을 읽기전용으로 설정할 수 없습니다. " +
          "읽기전용 사용자 계정을 사용하거나 read_only 서버 설정을 확인하세요."
      );
    }
  }

  async disconnect(): Promise<void> {
    if (this.connection) {
      await this.connection.rollback().catch(() => {});
      await this.connection.end();
      this.connection = null;
    }
  }

  async listColumns(schemas: string[]): Promise<ColumnInfo[]> {
    if (!this.connection) throw new Error("연결되지 않은 상태입니다.");

    const placeholders = schemas.map(() => "?").join(",");
    const [rows] = await this.connection.query<mysql.RowDataPacket[]>(
      `SELECT
         TABLE_SCHEMA       AS table_schema,
         TABLE_NAME         AS table_name,
         COLUMN_NAME        AS column_name,
         DATA_TYPE          AS data_type,
         IS_NULLABLE        AS is_nullable,
         CHARACTER_MAXIMUM_LENGTH AS max_length
       FROM information_schema.COLUMNS
       WHERE TABLE_SCHEMA IN (${placeholders})
       ORDER BY TABLE_SCHEMA, TABLE_NAME, ORDINAL_POSITION`,
      schemas
    );

    return (rows as mysql.RowDataPacket[]).map((r) => ({
      schema: String(r.table_schema),
      table: String(r.table_name),
      column: String(r.column_name),
      dataType: String(r.data_type),
      isNullable: r.is_nullable === "YES",
      maxLength: r.max_length != null ? Number(r.max_length) : undefined,
    }));
  }

  async getColumnStats(
    schema: string,
    table: string,
    column: string,
    sampleLimit: number
  ): Promise<ColumnStats> {
    if (!this.connection) throw new Error("연결되지 않은 상태입니다.");

    const fqt = `\`${schema}\`.\`${table}\``;
    const fqc = `\`${column}\``;

    const [statsRows] = await this.connection.query<mysql.RowDataPacket[]>(
      `SELECT
         COUNT(*) AS total_rows,
         COUNT(${fqc}) AS non_null_rows,
         COUNT(DISTINCT ${fqc}) AS distinct_count,
         MIN(CHAR_LENGTH(CAST(${fqc} AS CHAR))) AS min_len,
         MAX(CHAR_LENGTH(CAST(${fqc} AS CHAR))) AS max_len,
         ROUND(AVG(CHAR_LENGTH(CAST(${fqc} AS CHAR))), 1) AS avg_len
       FROM ${fqt}`
    );

    const [sampleRows] = await this.connection.query<mysql.RowDataPacket[]>(
      `SELECT CAST(${fqc} AS CHAR) AS val
       FROM ${fqt}
       WHERE ${fqc} IS NOT NULL
       LIMIT ?`,
      [sampleLimit]
    );

    const sr = (statsRows as mysql.RowDataPacket[])[0];
    const totalRows = Number(sr.total_rows);
    const nonNullRows = Number(sr.non_null_rows);
    const distinctCount = Number(sr.distinct_count);

    return {
      totalRows,
      nonNullRows,
      nullRatio: totalRows > 0 ? (totalRows - nonNullRows) / totalRows : 0,
      fillRate: totalRows > 0 ? nonNullRows / totalRows : 0,
      distinctCount,
      distinctRatio: nonNullRows > 0 ? distinctCount / nonNullRows : 0,
      minLength: sr.min_len != null ? Number(sr.min_len) : undefined,
      maxLength: sr.max_len != null ? Number(sr.max_len) : undefined,
      avgLength: sr.avg_len != null ? Number(sr.avg_len) : undefined,
      samples: (sampleRows as mysql.RowDataPacket[]).map((r) =>
        r.val != null ? String(r.val) : ""
      ),
    };
  }

  databaseName(): string {
    return this.config.database;
  }
}
