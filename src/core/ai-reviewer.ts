import type { ScanFinding, Severity, SensitivityCategory, AiReviewResult, AiReviewOptions } from "../types.js";

export interface AiReviewerConfig {
  enabled: boolean;
  mode: "advisory" | "strict";
  provider: "heuristic" | "http";
  model: string;
  endpoint?: string;
  timeoutMs: number;
  minScore: number;
  maxItems: number;
}

function clamp(v: number, min = 0, max = 1): number {
  return Math.max(min, Math.min(max, v));
}

function scoreBySeverity(severity: Severity): number {
  switch (severity) {
    case "critical":
      return 0.25;
    case "high":
      return 0.15;
    case "medium":
      return 0.07;
    case "low":
      return 0.03;
    default:
      return 0;
  }
}

function scoreByCategory(category: SensitivityCategory): number {
  switch (category) {
    case "credentials":
    case "oauth":
    case "biometric":
      return 0.14;
    case "financial":
      return 0.1;
    case "pii":
      return 0.08;
    case "health":
      return 0.09;
    case "device":
      return 0.06;
    case "certificate":
      return 0.12;
    case "custom":
      return 0.03;
    default:
      return 0;
  }
}

function heuristicReview(finding: ScanFinding, minScore: number, model: string): AiReviewResult {
  const start = Date.now();
  let score = 0.35;

  score += scoreBySeverity(finding.severity);
  score += scoreByCategory(finding.category);

  if (finding.source === "database") {
    if (finding.matchedBy === "both") score += 0.2;
    else if (finding.matchedBy === "data_sample") score += 0.12;
    else score += 0.06;
  } else {
    const lowered = finding.snippet.toLowerCase();
    if (lowered.includes("process.env")) score -= 0.22;
    if (lowered.includes("example") || lowered.includes("sample")) score -= 0.12;
    if (lowered.includes("token") || lowered.includes("secret")) score += 0.1;
    score += 0.06;
  }

  score = clamp(score);
  return {
    enabled: true,
    provider: "heuristic",
    model,
    decision: score >= minScore ? "keep" : "drop",
    score,
    reason:
      score >= minScore
        ? "정규식 탐지와 심각도/문맥 점수가 임계값 이상입니다."
        : "문맥 점수가 낮아 오탐 가능성이 높습니다.",
    latencyMs: Date.now() - start,
  };
}

async function httpReview(
  finding: ScanFinding,
  endpoint: string,
  timeoutMs: number,
  minScore: number,
  model: string
): Promise<AiReviewResult> {
  const start = Date.now();
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);

  try {
    const payload = {
      version: "1.0",
      task: "sensitive-info-review",
      input: {
        model,
        threshold: minScore,
        finding: {
          source: finding.source,
          category: finding.category,
          severity: finding.severity,
          ruleId: finding.ruleId,
          ruleName: finding.ruleName,
          matchedBy: finding.matchedBy,
          content:
            finding.source === "database"
              ? `${finding.database}.${finding.schema}.${finding.table}.${finding.column}`
              : `${finding.filePath}:${finding.line}:${finding.column}`,
          snippet: finding.source === "code" ? finding.snippet : undefined,
        },
      },
    };

    const res = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      signal: ctrl.signal,
    });

    if (!res.ok) {
      throw new Error(`AI endpoint error: ${res.status}`);
    }

    const raw = (await res.json()) as Record<string, unknown>;
    const data = (raw.result ?? raw) as Partial<{
      score: number;
      decision: "keep" | "drop";
      reason: string;
      model: string;
    }>;

    const score = clamp(typeof data.score === "number" ? data.score : 0.5);
    const decision = data.decision === "drop" || data.decision === "keep"
      ? data.decision
      : (score >= minScore ? "keep" : "drop");

    return {
      enabled: true,
      provider: "http",
      model: data.model ?? model,
      decision,
      score,
      reason: data.reason ?? "공용 모델 엔드포인트 판별 결과",
      latencyMs: Date.now() - start,
    };
  } finally {
    clearTimeout(timer);
  }
}

function disabledReview(): AiReviewResult {
  return {
    enabled: false,
    provider: "none",
    model: "disabled",
    decision: "skipped",
    score: 1,
    reason: "AI 보조 판별이 비활성화되어 원본 결과를 유지합니다.",
    latencyMs: 0,
  };
}

export function loadAiReviewerConfig(override?: AiReviewOptions): AiReviewerConfig {
  const enabledFromEnv = (process.env.AI_REVIEW_ENABLED ?? "false") === "true";
  const modeFromEnv = (process.env.AI_REVIEW_MODE ?? "advisory") === "strict" ? "strict" : "advisory";
  const providerFromEnv = (process.env.AI_REVIEW_PROVIDER ?? "heuristic") === "http" ? "http" : "heuristic";

  return {
    enabled: override?.enabled ?? enabledFromEnv,
    mode: override?.mode ?? modeFromEnv,
    provider: override?.provider ?? providerFromEnv,
    model: override?.model ?? process.env.AI_REVIEW_MODEL ?? "exaone-4.5-1.2b",
    endpoint: process.env.AI_REVIEW_ENDPOINT,
    timeoutMs: override?.timeoutMs ?? Number.parseInt(process.env.AI_REVIEW_TIMEOUT_MS ?? "3000", 10),
    minScore: override?.minScore ?? Number.parseFloat(process.env.AI_REVIEW_MIN_SCORE ?? "0.45"),
    maxItems: override?.maxItems ?? Number.parseInt(process.env.AI_REVIEW_MAX_ITEMS ?? "300", 10),
  };
}

export class AiReviewer {
  constructor(private readonly config: AiReviewerConfig) {}

  async review(findings: ScanFinding[]): Promise<{ findings: ScanFinding[]; dropped: number }> {
    if (!this.config.enabled) {
      return {
        findings: findings.map((f) => ({ ...f, aiReview: disabledReview() })),
        dropped: 0,
      };
    }

    const reviewed: ScanFinding[] = [];
    let dropped = 0;

    for (let i = 0; i < findings.length; i += 1) {
      const finding = findings[i];

      if (i >= this.config.maxItems) {
        const skipped: AiReviewResult = {
          enabled: true,
          provider: this.config.provider,
          model: this.config.model,
          decision: "skipped",
          score: 1,
          reason: `AI 처리 상한(${this.config.maxItems}) 초과로 원본 결과를 유지합니다.`,
          latencyMs: 0,
        };
        reviewed.push({ ...finding, aiReview: skipped });
        continue;
      }

      let aiReview: AiReviewResult;
      try {
        if (this.config.provider === "http" && this.config.endpoint) {
          aiReview = await httpReview(
            finding,
            this.config.endpoint,
            this.config.timeoutMs,
            this.config.minScore,
            this.config.model
          );
        } else {
          aiReview = heuristicReview(finding, this.config.minScore, this.config.model);
        }
      } catch (err) {
        aiReview = {
          enabled: true,
          provider: this.config.provider,
          model: this.config.model,
          decision: "error",
          score: 1,
          reason: `AI 판별 실패로 원본 결과를 유지합니다: ${err instanceof Error ? err.message : String(err)}`,
          latencyMs: 0,
        };
      }

      const next = { ...finding, aiReview };
      if (this.config.mode === "strict" && aiReview.decision === "drop") {
        dropped += 1;
        continue;
      }
      reviewed.push(next);
    }

    return { findings: reviewed, dropped };
  }
}
