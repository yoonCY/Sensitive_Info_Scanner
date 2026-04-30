import type { ColumnInfo, ColumnStats } from "../../../types.js";

export interface IDbAdapter {
  /**
   * DB에 연결하고 세션을 읽기전용으로 설정한다.
   * 읽기전용 설정 불가 시 예외를 던진다.
   */
  connect(): Promise<void>;

  /** 연결 해제 */
  disconnect(): Promise<void>;

  /**
   * 지정한 스키마에 속한 모든 컬럼 목록을 반환한다.
   * SQLite는 schema 파라미터를 무시하고 전체 테이블을 반환한다.
   */
  listColumns(schemas: string[]): Promise<ColumnInfo[]>;

  /**
   * 컬럼 통계 (행 수, NULL 비율, distinct 비율, 샘플 값)를 반환한다.
   * sampleLimit 만큼의 비-NULL 값을 샘플링한다.
   */
  getColumnStats(
    schema: string,
    table: string,
    column: string,
    sampleLimit: number
  ): Promise<ColumnStats>;

  /** 현재 접속된 데이터베이스 이름 */
  databaseName(): string;
}
