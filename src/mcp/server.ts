import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { ConfigManager } from "../core/config-manager.js";
import {
  ScannerEngine,
  getScanProgress,
  getScanReport,
  listScanReports,
} from "../core/scanner-engine.js";
import { ReportGenerator } from "../core/report-generator.js";

const server = new McpServer({
  name: "sensitive-info-scanner",
  version: "0.1.0",
});

const configManager = new ConfigManager();
const scannerEngine = new ScannerEngine();
const reportGen = new ReportGenerator();

// ─── 도구: 설정 목록 ────────────────────────────────────────────────────────

server.tool(
  "list_configs",
  "저장된 스캔 설정 목록을 반환합니다.",
  { tenantId: z.string().optional().describe("테넌트 ID (미지정 시 default)") },
  async ({ tenantId }: { tenantId?: string }) => {
    const configs = configManager.listConfigs(tenantId);
    return {
      content: [{ type: "text", text: JSON.stringify(configs, null, 2) }],
    };
  }
);

// ─── 도구: 설정 생성 ─────────────────────────────────────────────────────────

server.tool(
  "create_config",
  "새 스캔 설정을 생성합니다. DB 대상에는 schemas 필드가 필수입니다.",
  {
    tenantId: z.string().optional().describe("테넌트 ID (미지정 시 default)"),
    userId: z.string().optional().describe("실행 사용자 ID"),
    name: z.string().describe("설정 이름"),
    description: z.string().optional().describe("설명"),
    dbTargets: z
      .array(
        z.object({
          dialect: z.enum(["postgresql", "mysql", "sqlite"]),
          host: z.string().optional(),
          port: z.number().optional(),
          database: z.string(),
          username: z.string().optional(),
          password: z.string().optional(),
          filePath: z.string().optional(),
          ssl: z.boolean().optional(),
          schemas: z.array(z.string()).optional(),
        })
      )
      .default([])
      .describe("DB 연결 설정 목록"),
    codeTargets: z
      .array(
        z.object({
          path: z.string(),
          excludePatterns: z.array(z.string()).optional(),
          includeExtensions: z.array(z.string()).optional(),
        })
      )
      .default([])
      .describe("코드 경로 목록"),
    ruleOverride: z
      .object({
        enabledCategories: z
          .array(z.enum(["pii", "financial", "credentials", "health", "oauth", "device", "biometric", "certificate", "custom"]))
          .optional(),
        columnNameSensitivity: z.enum(["strict", "normal"]).optional(),
        dataSamplingEnabled: z.boolean().optional(),
        sampleRowLimit: z.number().optional(),
        statsEnabled: z.boolean().optional(),
        aiReview: z
          .object({
            enabled: z.boolean().optional(),
            mode: z.enum(["advisory", "strict"]).optional(),
            provider: z.enum(["heuristic", "http"]).optional(),
            model: z.string().optional(),
            timeoutMs: z.number().optional(),
            minScore: z.number().optional(),
            maxItems: z.number().optional(),
          })
          .optional(),
      })
      .optional()
      .describe("룰/AI 보조 판별 설정"),
  },
  async (args: {
    tenantId?: string;
    userId?: string;
    name: string;
    description?: string;
    dbTargets: Array<{
      dialect: "postgresql" | "mysql" | "sqlite";
      host?: string;
      port?: number;
      database: string;
      username?: string;
      password?: string;
      filePath?: string;
      ssl?: boolean;
      schemas?: string[];
    }>;
    codeTargets: Array<{
      path: string;
      excludePatterns?: string[];
      includeExtensions?: string[];
    }>;
    ruleOverride?: {
      enabledCategories?: Array<"pii" | "financial" | "credentials" | "health" | "oauth" | "device" | "biometric" | "certificate" | "custom">;
      columnNameSensitivity?: "strict" | "normal";
      dataSamplingEnabled?: boolean;
      sampleRowLimit?: number;
      statsEnabled?: boolean;
      aiReview?: {
        enabled?: boolean;
        mode?: "advisory" | "strict";
        provider?: "heuristic" | "http";
        model?: string;
        timeoutMs?: number;
        minScore?: number;
        maxItems?: number;
      };
    };
  }) => {
    try {
      const config = configManager.createConfig({
        ...args,
        actor: args.userId ? { tenantId: args.tenantId ?? "default", userId: args.userId } : undefined,
      });
      return {
        content: [{ type: "text", text: JSON.stringify(config, null, 2) }],
      };
    } catch (err) {
      return {
        content: [
          { type: "text", text: `오류: ${err instanceof Error ? err.message : String(err)}` },
        ],
        isError: true,
      };
    }
  }
);

// ─── 도구: 스캔 시작 ─────────────────────────────────────────────────────────

server.tool(
  "start_scan",
  "지정한 설정으로 민감정보 스캔을 시작하고 scanId를 반환합니다.",
  {
    configId: z.string().describe("실행할 스캔 설정 ID"),
    tenantId: z.string().optional().describe("테넌트 ID (미지정 시 default)"),
    userId: z.string().optional().describe("실행 사용자 ID"),
  },
  async ({ configId, tenantId, userId }: { configId: string; tenantId?: string; userId?: string }) => {
    const config = configManager.getConfig(configId, tenantId);
    if (!config) {
      return {
        content: [{ type: "text", text: `설정을 찾을 수 없습니다: ${configId}` }],
        isError: true,
      };
    }
    const scanId = scannerEngine.startScan(
      config,
      {},
      userId ? { tenantId: tenantId ?? "default", userId } : undefined
    );
    return {
      content: [
        { type: "text", text: JSON.stringify({ scanId, message: "스캔이 시작되었습니다." }) },
      ],
    };
  }
);

// ─── 도구: 스캔 진행 상태 ────────────────────────────────────────────────────

server.tool(
  "get_scan_progress",
  "스캔 진행 상태를 반환합니다.",
  {
    scanId: z.string().describe("스캔 ID"),
    tenantId: z.string().optional().describe("테넌트 ID (미지정 시 default)"),
  },
  async ({ scanId, tenantId }: { scanId: string; tenantId?: string }) => {
    const progress = getScanProgress(scanId, tenantId);
    if (!progress) {
      return {
        content: [{ type: "text", text: `스캔을 찾을 수 없습니다: ${scanId}` }],
        isError: true,
      };
    }
    return { content: [{ type: "text", text: JSON.stringify(progress, null, 2) }] };
  }
);

// ─── 도구: 스캔 결과 ─────────────────────────────────────────────────────────

server.tool(
  "get_scan_report",
  "스캔 결과 리포트를 반환합니다.",
  {
    scanId: z.string().describe("스캔 ID"),
    tenantId: z.string().optional().describe("테넌트 ID (미지정 시 default)"),
    format: z
      .enum(["json", "summary"])
      .default("summary")
      .describe("json = 전체 JSON, summary = 요약만"),
  },
  async ({ scanId, tenantId, format }: { scanId: string; tenantId?: string; format: "json" | "summary" }) => {
    const report = getScanReport(scanId, tenantId);
    if (!report) {
      return {
        content: [{ type: "text", text: `리포트를 찾을 수 없습니다: ${scanId}` }],
        isError: true,
      };
    }
    if (format === "summary") {
      const { summary, configName, status, completedAt } = report;
      return {
        content: [
          { type: "text", text: JSON.stringify({ scanId, configName, status, completedAt, summary }, null, 2) },
        ],
      };
    }
    return { content: [{ type: "text", text: reportGen.toJson(report) }] };
  }
);

// ─── 도구: 스캔 목록 ─────────────────────────────────────────────────────────

server.tool(
  "list_scans",
  "스캔 결과 목록을 반환합니다.",
  { tenantId: z.string().optional().describe("테넌트 ID (미지정 시 default)") },
  async ({ tenantId }: { tenantId?: string }) => {
    const scans = listScanReports(tenantId).map(({ id, configName, status, completedAt, summary }) => ({
      id,
      configName,
      status,
      completedAt,
      totalFindings: summary.totalFindings,
      critical: summary.bySeverity.critical,
      high: summary.bySeverity.high,
    }));
    return { content: [{ type: "text", text: JSON.stringify(scans, null, 2) }] };
  }
);

// ─────────────────────────────────────────────────────────────────────────────

const transport = new StdioServerTransport();
await server.connect(transport);
