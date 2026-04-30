import { v4 as uuidv4 } from "uuid";
import { RuleEngine } from "../core/rule-engine.js";
import { DbScanner } from "../scanners/db/db-scanner.js";
import { CodeScanner } from "../scanners/code/code-scanner.js";
import type {
  ScanConfig,
  ScanReport,
  ScanProgress,
  ScanFinding,
  ScanSummary,
  Severity,
  SensitivityCategory,
  ScanSource,
} from "../types.js";

// ─── 진행 상태 레지스트리 (인메모리) ─────────────────

const progressMap = new Map<string, ScanProgress>();
const reportMap = new Map<string, ScanReport>();

export function getScanProgress(scanId: string): ScanProgress | null {
  return progressMap.get(scanId) ?? null;
}

export function getScanReport(scanId: string): ScanReport | null {
  return reportMap.get(scanId) ?? null;
}

export function listScanReports(): ScanReport[] {
  return [...reportMap.values()].sort((a, b) =>
    b.startedAt.localeCompare(a.startedAt)
  );
}

// ─────────────────────────────────────────────────────────────────────────────

function buildSummary(
  findings: ScanFinding[],
  tablesScanned: number,
  columnsScanned: number,
  filesScanned: number,
  linesScanned: number,
  durationMs: number
): ScanSummary {
  const bySeverity: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  };
  const byCategory: Record<SensitivityCategory, number> = {
    pii: 0,
    financial: 0,
    credentials: 0,
    health: 0,
    custom: 0,
  };
  const bySource: Record<ScanSource, number> = { code: 0, database: 0 };

  for (const f of findings) {
    bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;
    byCategory[f.category] = (byCategory[f.category] ?? 0) + 1;
    bySource[f.source] = (bySource[f.source] ?? 0) + 1;
  }

  return {
    totalFindings: findings.length,
    bySeverity,
    byCategory,
    bySource,
    tablesScanned,
    columnsScanned,
    filesScanned,
    linesScanned,
    durationMs,
  };
}

// ─────────────────────────────────────────────────────────────────────────────

export class ScannerEngine {
  /**
   * 스캔을 비동기로 시작하고 scanId를 즉시 반환한다.
   * 실제 스캔은 백그라운드에서 진행된다.
   */
  startScan(config: ScanConfig): string {
    const scanId = uuidv4();
    const startedAt = new Date().toISOString();

    const progress: ScanProgress = {
      scanId,
      status: "running",
      processedItems: 0,
      totalItems:
        config.dbTargets.length + config.codeTargets.length,
      findingsCount: 0,
      startedAt,
      elapsedMs: 0,
    };
    progressMap.set(scanId, progress);

    // 리포트 초기화
    const report: ScanReport = {
      id: scanId,
      configId: config.id,
      configName: config.name,
      status: "running",
      startedAt,
      summary: buildSummary([], 0, 0, 0, 0, 0),
      findings: [],
    };
    reportMap.set(scanId, report);

    // 비동기 실행
    this.runScan(scanId, config).catch((err: unknown) => {
      const msg = err instanceof Error ? err.message : String(err);
      const p = progressMap.get(scanId);
      if (p) progressMap.set(scanId, { ...p, status: "failed" });
      const r = reportMap.get(scanId);
      if (r)
        reportMap.set(scanId, {
          ...r,
          status: "failed",
          errorMessage: msg,
          completedAt: new Date().toISOString(),
        });
    });

    return scanId;
  }

  private async runScan(scanId: string, config: ScanConfig): Promise<void> {
    const startMs = Date.now();
    const findings: ScanFinding[] = [];
    let tablesScanned = 0;
    let columnsScanned = 0;
    let filesScanned = 0;
    let linesScanned = 0;

    const ruleEngine = new RuleEngine(
      [],
      config.ruleOverride?.enabledCategories
    );
    const dbScanner = new DbScanner(ruleEngine);
    const codeScanner = new CodeScanner(ruleEngine);

    const updateProgress = (msg: string): void => {
      const p = progressMap.get(scanId);
      if (!p) return;
      progressMap.set(scanId, {
        ...p,
        currentTarget: msg,
        findingsCount: findings.length,
        elapsedMs: Date.now() - startMs,
      });
    };

    // ── DB 스캔 ────────────────────────────────────────
    for (const dbTarget of config.dbTargets) {
      updateProgress(
        `DB: ${dbTarget.dialect}://${dbTarget.database}`
      );

      const dbFindings = await dbScanner.scan(dbTarget, {
        dataSamplingEnabled:
          config.ruleOverride?.dataSamplingEnabled ?? true,
        sampleRowLimit: config.ruleOverride?.sampleRowLimit ?? 100,
        statsEnabled: config.ruleOverride?.statsEnabled ?? true,
        onProgress: updateProgress,
      });

      findings.push(...dbFindings);

      // 테이블/컬럼 카운트는 findings에서 추정
      const tables = new Set(
        dbFindings.map((f) => `${f.schema}.${f.table}`)
      );
      tablesScanned += tables.size;
      columnsScanned += dbFindings.length;

      const p = progressMap.get(scanId);
      if (p)
        progressMap.set(scanId, {
          ...p,
          processedItems: p.processedItems + 1,
        });
    }

    // ── 코드 스캔 ─────────────────────────────────────
    for (const codeTarget of config.codeTargets) {
      updateProgress(`Code: ${codeTarget.path}`);
      const currentPhase = "code";

      const p = progressMap.get(scanId);
      if (p) progressMap.set(scanId, { ...p, currentPhase });

      const codeFindings = codeScanner.scan(codeTarget.path, {
        excludePatterns: codeTarget.excludePatterns,
        includeExtensions: codeTarget.includeExtensions,
        onProgress: updateProgress,
      });

      findings.push(...codeFindings);

      // 파일/라인 카운트
      const uniqueFiles = new Set(codeFindings.map((f) => f.filePath));
      filesScanned += uniqueFiles.size;
      linesScanned += codeFindings.reduce((acc, f) => Math.max(acc, f.line), 0);

      const p2 = progressMap.get(scanId);
      if (p2)
        progressMap.set(scanId, {
          ...p2,
          processedItems: p2.processedItems + 1,
        });
    }

    // ── 완료 처리 ──────────────────────────────────────
    const completedAt = new Date().toISOString();
    const durationMs = Date.now() - startMs;

    const summary = buildSummary(
      findings,
      tablesScanned,
      columnsScanned,
      filesScanned,
      linesScanned,
      durationMs
    );

    const finalReport: ScanReport = {
      id: scanId,
      configId: config.id,
      configName: config.name,
      status: "completed",
      startedAt: reportMap.get(scanId)!.startedAt,
      completedAt,
      summary,
      findings,
    };

    reportMap.set(scanId, finalReport);

    const finalProgress: ScanProgress = {
      scanId,
      status: "completed",
      processedItems:
        config.dbTargets.length + config.codeTargets.length,
      totalItems:
        config.dbTargets.length + config.codeTargets.length,
      findingsCount: findings.length,
      startedAt: reportMap.get(scanId)!.startedAt,
      elapsedMs: durationMs,
    };
    progressMap.set(scanId, finalProgress);
  }
}
