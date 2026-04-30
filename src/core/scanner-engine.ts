import { v4 as uuidv4 } from "uuid";
import { RuleEngine } from "../core/rule-engine.js";
import { DbScanner } from "../scanners/db/db-scanner.js";
import { CodeScanner } from "../scanners/code/code-scanner.js";
import { AiReviewer, loadAiReviewerConfig } from "../core/ai-reviewer.js";
import { writeAuditLog } from "../core/audit-logger.js";
import type { AuthContext } from "./auth-context.js";
import { appDb } from "./app-db.js";
import type {
  ScanConfig,
  ScanExecutionOptions,
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
const DEFAULT_TENANT_ID = (process.env.DEFAULT_TENANT_ID ?? "default").trim() || "default";

export function getScanProgress(scanId: string, tenantId?: string): ScanProgress | null {
  const normalizedTenantId = tenantId?.trim() || DEFAULT_TENANT_ID;
  const progress = progressMap.get(scanId) ?? null;
  if (!progress) return null;
  if (progress.tenantId !== normalizedTenantId) return null;
  return progress;
}

export function getScanReport(scanId: string, tenantId?: string): ScanReport | null {
  const normalizedTenantId = tenantId?.trim() || DEFAULT_TENANT_ID;
  const report = reportMap.get(scanId) ?? appDb.getScanReport(scanId, normalizedTenantId);
  if (!report) return null;
  if (report.tenantId !== normalizedTenantId) return null;
  return report;
}

export function listScanReports(tenantId?: string): ScanReport[] {
  const normalizedTenantId = tenantId?.trim() || DEFAULT_TENANT_ID;
  const reports = appDb.listScanReports(normalizedTenantId);
  return reports.sort((a, b) =>
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
  durationMs: number,
  aiDroppedCount = 0
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
    oauth: 0,
    device: 0,
    biometric: 0,
    certificate: 0,
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
    aiDroppedCount,
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
  startScan(config: ScanConfig, options: ScanExecutionOptions = {}, actor?: Pick<AuthContext, "tenantId" | "userId">): string {
    const scanId = uuidv4();
    const startedAt = new Date().toISOString();
    const selectedSources = new Set<ScanSource>(options.sources ?? ["database", "code"]);
    const includeDb = selectedSources.has("database");
    const includeCode = selectedSources.has("code");

    if (!includeDb && !includeCode) {
      throw new Error("최소 1개 스캔 소스(code/database)를 선택해야 합니다.");
    }

    const totalItems =
      (includeDb ? config.dbTargets.length : 0) +
      (includeCode ? config.codeTargets.length : 0);

    const progress: ScanProgress = {
      scanId,
      tenantId: config.tenantId,
      status: "running",
      processedItems: 0,
      totalItems,
      findingsCount: 0,
      startedAt,
      elapsedMs: 0,
    };
    progressMap.set(scanId, progress);

    // 리포트 초기화
    const report: ScanReport = {
      id: scanId,
      tenantId: config.tenantId,
      configId: config.id,
      configName: config.name,
      status: "running",
      startedAt,
      summary: buildSummary([], 0, 0, 0, 0, 0, 0),
      findings: [],
    };
    reportMap.set(scanId, report);
    appDb.upsertScanReport({
      id: scanId,
      tenantId: config.tenantId ?? "default",
      configId: config.id,
      configName: config.name,
      status: "running",
      startedAt,
      summary: report.summary,
      findings: [],
      createdByUserId: actor?.userId,
    });

    // 비동기 실행
    this.runScan(scanId, config, { sources: [...selectedSources], plugins: options.plugins ?? [] }, actor).catch((err: unknown) => {
      const msg = err instanceof Error ? err.message : String(err);
      const p = progressMap.get(scanId);
      if (p) progressMap.set(scanId, { ...p, status: "failed" });
      const r = reportMap.get(scanId);
      if (r) {
        const failedReport = {
          ...r,
          status: "failed" as const,
          errorMessage: msg,
          completedAt: new Date().toISOString(),
        };
        reportMap.set(scanId, failedReport);
        appDb.upsertScanReport({
          id: failedReport.id,
          tenantId: failedReport.tenantId ?? "default",
          configId: failedReport.configId,
          configName: failedReport.configName,
          status: failedReport.status,
          startedAt: failedReport.startedAt,
          completedAt: failedReport.completedAt,
          errorMessage: failedReport.errorMessage,
          summary: failedReport.summary,
          findings: failedReport.findings,
          createdByUserId: actor?.userId,
        });
        writeAuditLog("report", config.name, {
          action: "scan_failed",
          scanId,
          errorMessage: msg,
        }, { tenantId: config.tenantId ?? "default", userId: actor?.userId });
      }
    });

    return scanId;
  }

  private async runScan(
    scanId: string,
    config: ScanConfig,
    options: ScanExecutionOptions,
    actor?: Pick<AuthContext, "tenantId" | "userId">
  ): Promise<void> {
    const startMs = Date.now();
    const selectedSources = new Set<ScanSource>(options.sources ?? ["database", "code"]);
    const includeDb = selectedSources.has("database");
    const includeCode = selectedSources.has("code");
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
    const aiReviewer = new AiReviewer(loadAiReviewerConfig(config.ruleOverride?.aiReview));

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
    if (includeDb) {
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
    }

    // ── 코드 스캔 ─────────────────────────────────────
    if (includeCode) {
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
    }

    // ── AI 보조 판별 (선택) ────────────────────────────
    updateProgress("AI 보조 판별 실행 중...");
    const aiReviewed = await aiReviewer.review(findings);
    const finalFindings = aiReviewed.findings;

    // ── 완료 처리 ──────────────────────────────────────
    const completedAt = new Date().toISOString();
    const durationMs = Date.now() - startMs;

    const summary = buildSummary(
      finalFindings,
      tablesScanned,
      columnsScanned,
      filesScanned,
      linesScanned,
      durationMs,
      aiReviewed.dropped
    );

    const finalReport: ScanReport = {
      id: scanId,
      tenantId: config.tenantId,
      configId: config.id,
      configName: config.name,
      status: "completed",
      startedAt: reportMap.get(scanId)!.startedAt,
      completedAt,
      summary,
      findings: finalFindings,
    };

    reportMap.set(scanId, finalReport);
    appDb.upsertScanReport({
      id: finalReport.id,
      tenantId: finalReport.tenantId ?? "default",
      configId: finalReport.configId,
      configName: finalReport.configName,
      status: finalReport.status,
      startedAt: finalReport.startedAt,
      completedAt: finalReport.completedAt,
      summary: finalReport.summary,
      findings: finalReport.findings,
      createdByUserId: actor?.userId,
    });

    writeAuditLog("report", config.name, {
      action: "scan_completed",
      scanId,
      completedAt,
      searchConditions: {
        dbTargets: config.dbTargets,
        codeTargets: config.codeTargets,
        executionOptions: {
          sources: [...selectedSources],
          plugins: options.plugins ?? [],
        },
        ruleOverride: config.ruleOverride,
      },
      summary,
      report: finalReport,
    }, { tenantId: config.tenantId ?? "default", userId: actor?.userId });

    const finalProgress: ScanProgress = {
      scanId,
      tenantId: config.tenantId,
      status: "completed",
      processedItems:
        (includeDb ? config.dbTargets.length : 0) +
        (includeCode ? config.codeTargets.length : 0),
      totalItems:
        (includeDb ? config.dbTargets.length : 0) +
        (includeCode ? config.codeTargets.length : 0),
      findingsCount: finalFindings.length,
      startedAt: reportMap.get(scanId)!.startedAt,
      elapsedMs: durationMs,
    };
    progressMap.set(scanId, finalProgress);
  }
}
