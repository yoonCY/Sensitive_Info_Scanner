import type { ScanReport, ScanFinding, DbFinding, CodeFinding, Severity } from "../types.js";

const SEVERITY_COLOR: Record<Severity, string> = {
  critical: "#dc2626",
  high: "#ea580c",
  medium: "#d97706",
  low: "#65a30d",
};

const SEVERITY_BG: Record<Severity, string> = {
  critical: "#fef2f2",
  high: "#fff7ed",
  medium: "#fffbeb",
  low: "#f7fee7",
};

function badge(severity: Severity): string {
  return `<span style="background:${SEVERITY_BG[severity]};color:${SEVERITY_COLOR[severity]};
    border:1px solid ${SEVERITY_COLOR[severity]};border-radius:4px;
    padding:1px 6px;font-size:11px;font-weight:700;">${severity.toUpperCase()}</span>`;
}

function formatMatchedBy(matchedBy: DbFinding["matchedBy"]): string {
  if (matchedBy === "column_name") return "컬럼명 패턴";
  if (matchedBy === "data_sample") return "샘플값 패턴";
  return "컬럼명 + 샘플값";
}

function formatStats(finding: DbFinding): string {
  if (!finding.stats) return "-";
  return `채움률 ${(finding.stats.fillRate * 100).toFixed(1)}%<br>총 ${finding.stats.totalRows.toLocaleString()}행`;
}

function formatAiDecision(ai: DbFinding["aiReview"] | CodeFinding["aiReview"]): string {
  if (!ai) return "-";

  if (ai.decision === "skipped") {
    if (!ai.enabled) return "건너뜀 (비활성화)";
    if (ai.reason.includes("상한")) return "건너뜀 (평가 상한 초과)";
    return `건너뜀 (${escapeHtml(ai.reason)})`;
  }

  if (ai.decision === "error") {
    return `오류 (원본 유지)`;
  }

  return `${ai.decision} (${(ai.score * 100).toFixed(0)}%)`;
}

function renderDbFinding(f: DbFinding): string {
  return `
    <tr>
      <td>${badge(f.severity)}</td>
      <td>${f.category}</td>
      <td>${f.ruleName}</td>
      <td><code>${f.database}.${f.schema}.${f.table}.<strong>${f.column}</strong></code></td>
      <td>${f.columnType}</td>
      <td>${formatMatchedBy(f.matchedBy)}</td>
      <td>${formatStats(f)}</td>
      <td>${formatAiDecision(f.aiReview)}</td>
    </tr>`;
}

function renderCodeFinding(f: CodeFinding): string {
  return `
    <tr>
      <td>${badge(f.severity)}</td>
      <td>${f.category}</td>
      <td>${f.ruleName}</td>
      <td><code>${f.filePath}</code></td>
      <td>Line ${f.line}:${f.column}</td>
      <td><code style="word-break:break-all;">${escapeHtml(f.snippet)}</code></td>
      <td>${formatAiDecision(f.aiReview)}</td>
    </tr>`;
}

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// ─────────────────────────────────────────────────────────────────────────────

export class ReportGenerator {
  toJson(report: ScanReport): string {
    return JSON.stringify(report, null, 2);
  }

  toHtml(report: ScanReport): string {
    const { summary, findings } = report;
    const dbFindings = findings.filter((f): f is DbFinding => f.source === "database");
    const codeFindings = findings.filter((f): f is CodeFinding => f.source === "code");

    const severityRows = (Object.entries(summary.bySeverity) as [Severity, number][])
      .map(
        ([sev, cnt]) =>
          `<tr><td>${badge(sev)}</td><td><strong>${cnt}</strong></td></tr>`
      )
      .join("");

    const dbRows = dbFindings.map(renderDbFinding).join("");
    const codeRows = codeFindings.map(renderCodeFinding).join("");

    return `<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8">
  <title>민감정보 스캔 리포트 - ${escapeHtml(report.configName)}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
           margin: 0; padding: 24px; background: #f8fafc; color: #1e293b; }
    h1 { font-size: 22px; margin: 0 0 4px; }
    .meta { color: #64748b; font-size: 13px; margin-bottom: 24px; }
    .cards { display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 28px; }
    .card { background: #fff; border: 1px solid #e2e8f0; border-radius: 8px;
            padding: 16px 20px; min-width: 120px; }
    .card-label { font-size: 11px; color: #94a3b8; text-transform: uppercase;
                  letter-spacing: .05em; margin-bottom: 4px; }
    .card-value { font-size: 28px; font-weight: 700; }
    .critical { color: #dc2626; } .high { color: #ea580c; }
    .medium { color: #d97706; } .low { color: #65a30d; }
    section { background: #fff; border: 1px solid #e2e8f0; border-radius: 8px;
              margin-bottom: 24px; overflow: hidden; }
    section h2 { font-size: 15px; margin: 0; padding: 14px 20px;
                 border-bottom: 1px solid #e2e8f0; background: #f8fafc; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th { background: #f1f5f9; padding: 8px 12px; text-align: left;
         font-weight: 600; border-bottom: 1px solid #e2e8f0; white-space: nowrap; }
    td { padding: 8px 12px; border-bottom: 1px solid #f1f5f9; vertical-align: middle; }
    tr:last-child td { border-bottom: none; }
    code { background: #f1f5f9; padding: 1px 5px; border-radius: 3px; font-size: 12px; }
  </style>
</head>
<body>
  <h1>🔍 민감정보 스캔 리포트</h1>
  <div class="meta">
    설정: <strong>${escapeHtml(report.configName)}</strong> &nbsp;|&nbsp;
    완료: ${report.completedAt ?? "진행 중"} &nbsp;|&nbsp;
    소요: ${(summary.durationMs / 1000).toFixed(1)}s
  </div>

  <div class="cards">
    <div class="card">
      <div class="card-label">총 발견</div>
      <div class="card-value">${summary.totalFindings}</div>
    </div>
    <div class="card">
      <div class="card-label">Critical</div>
      <div class="card-value critical">${summary.bySeverity.critical}</div>
    </div>
    <div class="card">
      <div class="card-label">High</div>
      <div class="card-value high">${summary.bySeverity.high}</div>
    </div>
    <div class="card">
      <div class="card-label">Medium</div>
      <div class="card-value medium">${summary.bySeverity.medium}</div>
    </div>
    <div class="card">
      <div class="card-label">Low</div>
      <div class="card-value low">${summary.bySeverity.low}</div>
    </div>
    <div class="card">
      <div class="card-label">스캔 테이블</div>
      <div class="card-value">${summary.tablesScanned}</div>
    </div>
    <div class="card">
      <div class="card-label">스캔 파일</div>
      <div class="card-value">${summary.filesScanned}</div>
    </div>
    <div class="card">
      <div class="card-label">AI Strict Drop</div>
      <div class="card-value">${summary.aiDroppedCount ?? 0}</div>
    </div>
  </div>

  <section>
    <h2>심각도별 요약</h2>
    <table><tbody>${severityRows}</tbody></table>
  </section>

  ${dbFindings.length > 0 ? `
  <section>
    <h2>DB 민감정보 발견 (${dbFindings.length}건)</h2>
    <table>
      <thead>
        <tr>
          <th>심각도</th><th>카테고리</th><th>룰</th>
          <th>경로 (DB.스키마.테이블.컬럼)</th><th>타입</th>
          <th>탐지방식</th><th>통계</th><th>AI 판별</th>
        </tr>
      </thead>
      <tbody>${dbRows}</tbody>
    </table>
  </section>` : ""}

  ${codeFindings.length > 0 ? `
  <section>
    <h2>코드 민감정보 발견 (${codeFindings.length}건)</h2>
    <table>
      <thead>
        <tr>
          <th>심각도</th><th>카테고리</th><th>룰</th>
          <th>파일</th><th>위치</th><th>코드 (레드액션)</th><th>AI 판별</th>
        </tr>
      </thead>
      <tbody>${codeRows}</tbody>
    </table>
  </section>` : ""}

  ${findings.length === 0 ? `
  <section>
    <h2>발견 없음</h2>
    <p style="padding:16px 20px;color:#64748b;">민감정보를 발견하지 못했습니다.</p>
  </section>` : ""}
</body>
</html>`;
  }
}
