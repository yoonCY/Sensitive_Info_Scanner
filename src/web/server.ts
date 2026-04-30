import express, { type Request, type Response } from "express";
import { existsSync, readdirSync, statSync, accessSync, constants as fsConstants } from "node:fs";
import { join, dirname, isAbsolute, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import pg from "pg";
import mysql from "mysql2/promise";
import { ConfigManager } from "../core/config-manager.js";
import { ScannerEngine, getScanProgress, getScanReport, listScanReports } from "../core/scanner-engine.js";
import { ReportGenerator } from "../core/report-generator.js";
import { DbScanner } from "../scanners/db/db-scanner.js";
import { RuleEngine } from "../core/rule-engine.js";
import { PostgresAdapter } from "../scanners/db/adapters/postgres.adapter.js";
import { MysqlAdapter } from "../scanners/db/adapters/mysql.adapter.js";
import { SqliteAdapter } from "../scanners/db/adapters/sqlite.adapter.js";
import type { CodeTargetConfig, DbConnectionConfig, DbDialect, ScanExecutionOptions, ScanSource } from "../types.js";
import { writeAuditLog } from "../core/audit-logger.js";
import { appDb } from "../core/app-db.js";
import { getAuthRuntimeFlags, resolveAuthContext, type AuthContext } from "../core/auth-context.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const distPublicDir = join(__dirname, "public");
const srcPublicDir = join(process.cwd(), "src", "web", "public");
const publicDir = existsSync(distPublicDir) ? distPublicDir : srcPublicDir;
const ALLOWED_CODE_ROOTS = (process.env.ALLOWED_CODE_ROOTS ?? "/workspace,/app")
  .split(",")
  .map((value: string) => value.trim())
  .filter(Boolean);
const runtimeFlags = getAuthRuntimeFlags();

const app = express();
app.use(express.json());
app.use(express.static(publicDir));

const configManager = new ConfigManager();
const scannerEngine = new ScannerEngine();
const reportGen = new ReportGenerator();

function isReadonlyUser(username?: string): boolean {
  if (!username) return false;
  return /readonly|read_only|scanner_ro|_ro$|^ro_/i.test(username);
}

function registerAuthContext(auth: AuthContext): AuthContext {
  appDb.ensureTenant(auth.tenantId, auth.tenantId);
  if (auth.userId && auth.username) {
    appDb.upsertUser({
      tenantId: auth.tenantId,
      userId: auth.userId,
      username: auth.username,
      email: auth.email,
      displayName: auth.displayName,
      roles: auth.roles,
    });
  }
  return auth;
}

function getRequestAuth(req: Request): AuthContext {
  return registerAuthContext(resolveAuthContext(req));
}

function isWithinAllowedRoot(candidatePath: string, allowedRoot: string): boolean {
  const root = resolve(allowedRoot);
  const candidate = resolve(candidatePath);
  const rel = relative(root, candidate);
  return rel === "" || (!rel.startsWith("..") && !isAbsolute(rel));
}

function assertAllowedRoot(rootPath: string): void {
  if (!ALLOWED_CODE_ROOTS.length) return;
  if (ALLOWED_CODE_ROOTS.some((allowedRoot: string) => isWithinAllowedRoot(rootPath, allowedRoot))) return;
  throw new Error(`허용된 코드 루트만 스캔할 수 있습니다: ${ALLOWED_CODE_ROOTS.join(", ")}`);
}

function assertAllowedCodeTargets(codeTargets: CodeTargetConfig[] = []): void {
  for (const target of codeTargets) {
    assertAllowedRoot(target.path);
  }
}

function collectFsInfo(rootPath: string): { readable: boolean; directories: string[]; extensions: string[] } {
  try {
    accessSync(rootPath, fsConstants.R_OK);
  } catch {
    return { readable: false, directories: [], extensions: [] };
  }

  const directories: string[] = [];
  const extensions = new Set<string>();

  const queue: string[] = [rootPath];
  let scanned = 0;
  while (queue.length > 0 && scanned < 1500) {
    const current = queue.shift()!;
    let entries: string[] = [];
    try {
      entries = readdirSync(current);
    } catch {
      continue;
    }

    for (const entry of entries) {
      if (entry === "node_modules" || entry === ".git" || entry === "dist" || entry === "build") continue;
      const full = join(current, entry);
      let st;
      try {
        st = statSync(full);
      } catch {
        continue;
      }
      scanned += 1;
      if (st.isDirectory()) {
        if (current === rootPath) directories.push(entry);
        queue.push(full);
      } else if (st.isFile()) {
        const idx = entry.lastIndexOf(".");
        if (idx > 0) {
          extensions.add(entry.slice(idx + 1).toLowerCase());
        }
      }
    }
  }

  return {
    readable: true,
    directories: directories.sort((a, b) => a.localeCompare(b)),
    extensions: Array.from(extensions).sort((a, b) => a.localeCompare(b)),
  };
}

// ── 설정 API ──────────────────────────────────────────────────────────────────

app.get("/api/runtime-context", (req: Request, res: Response) => {
  try {
    const auth = getRequestAuth(req);
    res.json({
      tenantId: auth.tenantId,
      authMode: runtimeFlags.authMode,
      requireAuth: runtimeFlags.requireAuth,
      allowedCodeRoots: ALLOWED_CODE_ROOTS,
      auth: {
        tenantId: auth.tenantId,
        userId: auth.userId,
        username: auth.username,
        displayName: auth.displayName,
        email: auth.email,
        roles: auth.roles,
        isAuthenticated: auth.isAuthenticated,
      },
    });
  } catch (err) {
    res.status(400).json({ error: err instanceof Error ? err.message : String(err) });
  }
});

app.get("/api/configs", (req: Request, res: Response) => {
  try {
    const auth = getRequestAuth(req);
    res.json(configManager.listConfigs(auth.tenantId));
  } catch (err) {
    res.status(400).json({ error: err instanceof Error ? err.message : String(err) });
  }
});

app.get("/api/configs/:id", (req: Request, res: Response) => {
  try {
    const auth = getRequestAuth(req);
    const config = configManager.getConfig(req.params.id, auth.tenantId);
    if (!config) return res.status(404).json({ error: "설정을 찾을 수 없습니다." });
    return res.json(config);
  } catch (err) {
    return res.status(400).json({ error: err instanceof Error ? err.message : String(err) });
  }
});

app.post("/api/configs", (req: Request, res: Response) => {
  try {
    const auth = getRequestAuth(req);
    assertAllowedCodeTargets(req.body?.codeTargets);
    const config = configManager.createConfig({ ...req.body, tenantId: auth.tenantId, actor: auth });
    res.status(201).json(config);
  } catch (err) {
    res.status(400).json({ error: err instanceof Error ? err.message : String(err) });
  }
});

app.put("/api/configs/:id", (req: Request, res: Response) => {
  try {
    const auth = getRequestAuth(req);
    assertAllowedCodeTargets(req.body?.codeTargets);
    const config = configManager.updateConfig(req.params.id, req.body, auth.tenantId, auth);
    res.json(config);
  } catch (err) {
    res.status(400).json({ error: err instanceof Error ? err.message : String(err) });
  }
});

app.delete("/api/configs/:id", (req: Request, res: Response) => {
  try {
    const auth = getRequestAuth(req);
    configManager.deleteConfig(req.params.id, auth.tenantId, auth);
    res.status(204).send();
  } catch (err) {
    res.status(404).json({ error: err instanceof Error ? err.message : String(err) });
  }
});

// ── 스캔 API ──────────────────────────────────────────────────────────────────

app.post("/api/scans", (req: Request, res: Response) => {
  const { configId, sources, plugins } = req.body as {
    configId: string;
    sources?: ScanSource[];
    plugins?: string[];
  };
  let auth: AuthContext;
  try {
    auth = getRequestAuth(req);
  } catch (err) {
    return res.status(400).json({ error: err instanceof Error ? err.message : String(err) });
  }
  if (!configId) {
    return res.status(400).json({ error: "configId 필드가 필요합니다." });
  }

  if (sources && !Array.isArray(sources)) {
    return res.status(400).json({ error: "sources 필드는 배열이어야 합니다." });
  }

  const allowedSources: ScanSource[] = ["database", "code"];
  const normalizedSources = (sources ?? allowedSources).filter(
    (s): s is ScanSource => allowedSources.includes(s as ScanSource)
  );

  if (!normalizedSources.length) {
    return res.status(400).json({ error: "최소 1개 유효한 스캔 소스(code/database)를 선택해야 합니다." });
  }

  const normalizedPlugins = Array.isArray(plugins)
    ? plugins.filter((v): v is string => typeof v === "string" && v.trim().length > 0)
    : [];

  const config = configManager.getConfig(configId, auth.tenantId);
  if (!config) {
    return res.status(404).json({ error: "설정을 찾을 수 없습니다." });
  }

  try {
    assertAllowedCodeTargets(config.codeTargets);
  } catch (err) {
    return res.status(400).json({ error: err instanceof Error ? err.message : String(err) });
  }

  try {
    const executionOptions: ScanExecutionOptions = {
      sources: normalizedSources,
      plugins: normalizedPlugins,
    };
    const scanId = scannerEngine.startScan(config, executionOptions, auth);
    return res.status(202).json({ scanId });
  } catch (err) {
    return res.status(400).json({ error: err instanceof Error ? err.message : String(err) });
  }
});

app.get("/api/scans", (req: Request, res: Response) => {
  try {
    const auth = getRequestAuth(req);
    res.json(listScanReports(auth.tenantId));
  } catch (err) {
    res.status(400).json({ error: err instanceof Error ? err.message : String(err) });
  }
});

app.get("/api/scans/:id/progress", (req: Request, res: Response) => {
  try {
    const auth = getRequestAuth(req);
    const progress = getScanProgress(req.params.id, auth.tenantId);
    if (!progress) return res.status(404).json({ error: "스캔을 찾을 수 없습니다." });
    return res.json(progress);
  } catch (err) {
    return res.status(400).json({ error: err instanceof Error ? err.message : String(err) });
  }
});

app.get("/api/scans/:id", (req: Request, res: Response) => {
  try {
    const auth = getRequestAuth(req);
    const report = getScanReport(req.params.id, auth.tenantId);
    if (!report) return res.status(404).json({ error: "스캔 결과를 찾을 수 없습니다." });
    return res.json(report);
  } catch (err) {
    return res.status(400).json({ error: err instanceof Error ? err.message : String(err) });
  }
});

// ── DB 연결 테스트 API ────────────────────────────────────────────────────────

app.post("/api/db-test", async (req: Request, res: Response) => {
  const { dialect, host, port, database, username, password, filePath, ssl, schemas } = req.body;
  
  try {
    // SQLite 아닌 경우 스키마 필수
    if (dialect !== "sqlite" && (!schemas || schemas.length === 0)) {
      return res.status(400).json({
        success: false,
        error: "PostgreSQL/MySQL은 schemas 필드가 필수입니다."
      });
    }

    let adapter;
    const config: DbConnectionConfig = {
      dialect: dialect as DbDialect,
      host,
      port,
      database,
      username,
      password,
      filePath,
      ssl,
      schemas: schemas || []
    };

    // 어댑터 생성
    switch (config.dialect) {
      case "postgresql":
        adapter = new PostgresAdapter(config);
        break;
      case "mysql":
        adapter = new MysqlAdapter(config);
        break;
      case "sqlite":
        adapter = new SqliteAdapter(config);
        break;
      default:
        return res.status(400).json({ success: false, error: "지원하지 않는 DB" });
    }

    // 연결 테스트
    await adapter.connect();
    
    // 스키마/테이블 목록 조회
    let tables: any[] = [];
    try {
      if (dialect === "postgresql" || dialect === "mysql") {
        const columns = await adapter.listColumns(schemas || []);
        const tableSet = new Set(columns.map(c => c.schema + "." + c.table));
        tables = Array.from(tableSet).slice(0, 10); // 최대 10개
      }
    } catch (e) {
      // 무시 - 기본 연결은 성공한 상태
    }

    await adapter.disconnect();

    return res.json({
      success: true,
      message: "연결 성공! (" + tables.length + "개 테이블)",
      tables
    });
  } catch (err) {
    return res.status(400).json({
      success: false,
      error: err instanceof Error ? err.message : String(err)
    });
  }
});

app.post("/api/db-introspect", async (req: Request, res: Response) => {
  const { dialect, host, port, database, username, password, filePath, ssl } = req.body as {
    dialect: DbDialect;
    host?: string;
    port?: number;
    database: string;
    username?: string;
    password?: string;
    filePath?: string;
    ssl?: boolean;
  };

  try {
    let schemas: string[] = [];
    let databases: string[] = [];

    if (dialect === "postgresql") {
      const pool = new pg.Pool({
        host: host ?? "localhost",
        port: port ?? 5432,
        database,
        user: username,
        password,
        ssl: ssl ? { rejectUnauthorized: false } : false,
        max: 1,
      });
      try {
        const dbRes = await pool.query<{ datname: string }>(
          "SELECT datname FROM pg_database WHERE datistemplate = false ORDER BY datname"
        );
        databases = dbRes.rows.map((r: { datname: string }) => r.datname);

        const schemaRes = await pool.query<{ schema_name: string }>(
          "SELECT schema_name FROM information_schema.schemata WHERE schema_name NOT IN ('pg_catalog','information_schema') ORDER BY schema_name"
        );
        schemas = schemaRes.rows.map((r: { schema_name: string }) => r.schema_name);
      } finally {
        await pool.end();
      }
    } else if (dialect === "mysql") {
      const conn = await mysql.createConnection({
        host: host ?? "localhost",
        port: port ?? 3306,
        database,
        user: username,
        password,
        ssl: ssl ? {} : undefined,
      });
      try {
        const [dbRows] = await conn.query<mysql.RowDataPacket[]>("SHOW DATABASES");
        databases = dbRows.map((r: mysql.RowDataPacket) => String(Object.values(r)[0]));

        const [schemaRows] = await conn.query<mysql.RowDataPacket[]>(
          "SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME = DATABASE() ORDER BY SCHEMA_NAME"
        );
        schemas = schemaRows.map((r: mysql.RowDataPacket) => String(r.SCHEMA_NAME));
      } finally {
        await conn.end();
      }
    } else {
      databases = [database];
      schemas = ["main"];
    }

    const readonlyOk = isReadonlyUser(username);
    return res.json({
      success: true,
      readonlyOk,
      readonlyMessage: readonlyOk ? "읽기전용 계정으로 보입니다." : "읽기전용 계정이 아닐 수 있습니다. 운영 DB는 read-only 계정을 권장합니다.",
      database,
      databases,
      schemas,
    });
  } catch (err) {
    return res.status(400).json({
      success: false,
      error: err instanceof Error ? err.message : String(err),
    });
  }
});

app.post("/api/fs/inspect", (req: Request, res: Response) => {
  const { rootPath } = req.body as { rootPath?: string };
  if (!rootPath) {
    return res.status(400).json({ readable: false, error: "rootPath 필드가 필요합니다." });
  }
  try {
    assertAllowedRoot(rootPath);
  } catch (err) {
    return res.status(403).json({ readable: false, error: err instanceof Error ? err.message : String(err) });
  }
  const result = collectFsInfo(rootPath);
  if (!result.readable) {
    return res.status(403).json({ readable: false, error: "지정 경로를 읽을 권한이 없습니다." });
  }
  return res.json({ ...result, allowedCodeRoots: ALLOWED_CODE_ROOTS });
});

// ── 리포트 API ────────────────────────────────────────────────────────────────

app.get("/api/scans/:id/report.html", (req: Request, res: Response) => {
  try {
    const auth = getRequestAuth(req);
    const report = getScanReport(req.params.id, auth.tenantId);
    if (!report) return res.status(404).send("리포트를 찾을 수 없습니다.");
    writeAuditLog("report", report.configName, {
      action: "view_html",
      scanId: report.id,
      requestedAt: new Date().toISOString(),
      searchConditions: {
        configId: report.configId,
        configName: report.configName,
      },
    }, auth);
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    return res.send(reportGen.toHtml(report));
  } catch (err) {
    return res.status(400).send(err instanceof Error ? err.message : String(err));
  }
});

app.get("/api/scans/:id/report.json", (req: Request, res: Response) => {
  try {
    const auth = getRequestAuth(req);
    const report = getScanReport(req.params.id, auth.tenantId);
    if (!report) return res.status(404).json({ error: "리포트를 찾을 수 없습니다." });
    writeAuditLog("report", report.configName, {
      action: "download_json",
      scanId: report.id,
      requestedAt: new Date().toISOString(),
      searchConditions: {
        configId: report.configId,
        configName: report.configName,
      },
    }, auth);
    res.setHeader("Content-Disposition", `attachment; filename="report-${req.params.id.slice(0, 8)}.json"`);
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    return res.send(reportGen.toJson(report));
  } catch (err) {
    return res.status(400).json({ error: err instanceof Error ? err.message : String(err) });
  }
});

// ─────────────────────────────────────────────────────────────────────────────

const PORT = parseInt(process.env.PORT ?? "3300", 10);
app.listen(PORT, () => {
  console.log(`🔍 민감정보 스캐너 UI → http://localhost:${PORT}`);
});

export { app };
