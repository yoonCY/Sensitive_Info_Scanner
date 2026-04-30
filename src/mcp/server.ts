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

server.tool("list_configs", "저장된 스캔 설정 목록을 반환합니다.", {}, async () => {
  const configs = configManager.listConfigs();
  return {
    content: [{ type: "text", text: JSON.stringify(configs, null, 2) }],
  };
});

// ─── 도구: 설정 생성 ─────────────────────────────────────────────────────────

server.tool(
  "create_config",
  "새 스캔 설정을 생성합니다. DB 대상에는 schemas 필드가 필수입니다.",
  {
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
  },
  async (args) => {
    try {
      const config = configManager.createConfig(args);
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
  },
  async ({ configId }) => {
    const config = configManager.getConfig(configId);
    if (!config) {
      return {
        content: [{ type: "text", text: `설정을 찾을 수 없습니다: ${configId}` }],
        isError: true,
      };
    }
    const scanId = scannerEngine.startScan(config);
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
  { scanId: z.string().describe("스캔 ID") },
  async ({ scanId }) => {
    const progress = getScanProgress(scanId);
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
    format: z
      .enum(["json", "summary"])
      .default("summary")
      .describe("json = 전체 JSON, summary = 요약만"),
  },
  async ({ scanId, format }) => {
    const report = getScanReport(scanId);
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

server.tool("list_scans", "스캔 결과 목록을 반환합니다.", {}, async () => {
  const scans = listScanReports().map(({ id, configName, status, completedAt, summary }) => ({
    id,
    configName,
    status,
    completedAt,
    totalFindings: summary.totalFindings,
    critical: summary.bySeverity.critical,
    high: summary.bySeverity.high,
  }));
  return { content: [{ type: "text", text: JSON.stringify(scans, null, 2) }] };
});

// ─────────────────────────────────────────────────────────────────────────────

const transport = new StdioServerTransport();
await server.connect(transport);
