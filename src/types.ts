// ─────────────────────────────────────────────
//  민감정보 스캐너 공통 타입 정의
// ─────────────────────────────────────────────

export type SensitivityCategory = "pii" | "financial" | "credentials" | "health" | "oauth" | "device" | "biometric" | "certificate" | "custom";
export type Severity = "critical" | "high" | "medium" | "low";
export type DbDialect = "postgresql" | "mysql" | "sqlite";
export type ScanSource = "code" | "database";
export type ScanStatus = "pending" | "running" | "completed" | "failed";
export type AiReviewDecision = "keep" | "drop" | "skipped" | "error";

// ─── 설정 ──────────────────────────────────────

export interface DbConnectionConfig {
  dialect: DbDialect;
  host?: string;
  port?: number;
  database: string;
  username?: string;
  password?: string;
  filePath?: string;   // SQLite 전용
  ssl?: boolean;
  schemas?: string[];  // 스캔 대상 스키마 (필수 - 미지정 시 거부)
}

export interface CodeTargetConfig {
  path: string;
  excludePatterns?: string[];
  includeExtensions?: string[];
}

export interface RuleOverride {
  enabledCategories?: SensitivityCategory[];
  columnNameSensitivity?: "strict" | "normal";
  dataSamplingEnabled?: boolean;
  sampleRowLimit?: number;
  statsEnabled?: boolean;
  aiReview?: AiReviewOptions;
}

export interface ScanConfig {
  id: string;
  tenantId?: string;
  name: string;
  description?: string;
  dbTargets: DbConnectionConfig[];
  codeTargets: CodeTargetConfig[];
  ruleOverride?: RuleOverride;
  createdAt: string;
  updatedAt: string;
}

export interface ScanExecutionOptions {
  sources?: ScanSource[];
  plugins?: string[];
}

// ─── 룰 엔진 ────────────────────────────────────

export interface SensitivityRule {
  id: string;
  name: string;
  category: SensitivityCategory;
  severity: Severity;
  description: string;
  columnPattern?: RegExp;
  codePattern?: RegExp;
  dataPattern?: RegExp;
}

// ─── DB 스캐너 ──────────────────────────────────

export interface ColumnInfo {
  schema: string;
  table: string;
  column: string;
  dataType: string;
  isNullable: boolean;
  maxLength?: number;
}

export interface ColumnStats {
  totalRows: number;
  nonNullRows: number;
  nullRatio: number;
  fillRate: number;
  distinctCount: number;
  distinctRatio: number;
  minLength?: number;
  maxLength?: number;
  avgLength?: number;
  samples: string[];
}

export interface DbFinding {
  source: "database";
  ruleId: string;
  ruleName: string;
  category: SensitivityCategory;
  severity: Severity;
  dialect: DbDialect;
  database: string;
  schema: string;
  table: string;
  column: string;
  columnType: string;
  matchedBy: "column_name" | "data_sample" | "both";
  stats?: ColumnStats;
  columnPatternMatched?: string;
  dataPatternMatched?: string;
  aiReview?: AiReviewResult;
}

// ─── 코드 스캐너 ────────────────────────────────

export interface CodeFinding {
  source: "code";
  ruleId: string;
  ruleName: string;
  category: SensitivityCategory;
  severity: Severity;
  filePath: string;
  line: number;
  column: number;
  snippet: string;
  matchedBy: "pattern";
  aiReview?: AiReviewResult;
}

export interface AiReviewResult {
  enabled: boolean;
  provider: "none" | "heuristic" | "http";
  model: string;
  decision: AiReviewDecision;
  score: number;
  reason: string;
  latencyMs: number;
}

export interface AiReviewOptions {
  enabled?: boolean;
  mode?: "advisory" | "strict";
  provider?: "heuristic" | "http";
  model?: string;
  timeoutMs?: number;
  minScore?: number;
  maxItems?: number;
}

export type ScanFinding = DbFinding | CodeFinding;

// ─── 스캔 결과 ──────────────────────────────────

export interface ScanSummary {
  totalFindings: number;
  bySeverity: Record<Severity, number>;
  byCategory: Record<SensitivityCategory, number>;
  bySource: Record<ScanSource, number>;
  aiDroppedCount: number;
  tablesScanned: number;
  columnsScanned: number;
  filesScanned: number;
  linesScanned: number;
  durationMs: number;
}

export interface ScanReport {
  id: string;
  tenantId?: string;
  configId: string;
  configName: string;
  status: ScanStatus;
  startedAt: string;
  completedAt?: string;
  errorMessage?: string;
  summary: ScanSummary;
  findings: ScanFinding[];
}

export interface ScanProgress {
  scanId: string;
  tenantId?: string;
  status: ScanStatus;
  currentTarget?: string;
  currentPhase?: string;
  processedItems: number;
  totalItems: number;
  findingsCount: number;
  startedAt: string;
  elapsedMs: number;
}
