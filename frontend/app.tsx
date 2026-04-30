import React, { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";

type ApiArray<T> = T[] | { value: T[] };

type ScanStatus = "pending" | "running" | "completed" | "failed";

interface DbTarget {
  dialect: "postgresql" | "mysql" | "sqlite";
  host?: string;
  port?: number;
  database: string;
  username?: string;
  password?: string;
  filePath?: string;
  ssl?: boolean;
  schemas?: string[];
}

interface CodeTarget {
  path: string;
  includeExtensions?: string[];
  excludePatterns?: string[];
}

interface ConfigItem {
  id: string;
  tenantId?: string;
  name: string;
  description?: string;
  dbTargets: DbTarget[];
  codeTargets: CodeTarget[];
}

interface ScanSummary {
  totalFindings: number;
  aiDroppedCount?: number;
  bySeverity: Record<"critical" | "high" | "medium" | "low", number>;
}

interface ScanListItem {
  id: string;
  tenantId?: string;
  configName: string;
  status: ScanStatus;
  completedAt?: string;
  summary: ScanSummary;
}

interface ScanProgress {
  status: ScanStatus;
  findingsCount: number;
  processedItems: number;
  totalItems: number;
  elapsedMs: number;
  currentTarget?: string;
}

type ScanScope = "database" | "code";

interface ScanPluginOption {
  id: string;
  label: string;
  description: string;
  enabled: boolean;
}

interface ScanFinding {
  source: "database" | "code";
  severity: "critical" | "high" | "medium" | "low";
  category: string;
  ruleName: string;
  ruleId: string;
  aiReview?: { decision: string; score: number };
  database?: string;
  schema?: string;
  table?: string;
  column?: string;
  filePath?: string;
  line?: number;
}

interface ScanReport {
  id: string;
  tenantId?: string;
  configName: string;
  summary: ScanSummary;
  findings: ScanFinding[];
}

interface FsInspectResult {
  readable: boolean;
  directories: string[];
  extensions: string[];
  allowedCodeRoots?: string[];
}

interface RuntimeContext {
  tenantId: string;
  authMode: "none" | "proxy";
  requireAuth: boolean;
  allowedCodeRoots: string[];
  auth: {
    tenantId: string;
    userId?: string;
    username?: string;
    displayName?: string;
    email?: string;
    roles: string[];
    isAuthenticated: boolean;
  };
}

interface DbIntrospectResult {
  success: boolean;
  readonlyOk: boolean;
  readonlyMessage: string;
  database: string;
  databases: string[];
  schemas: string[];
}

const DEFAULT_EXTS = ["ts", "tsx", "js", "jsx", "php", "java", "kt", "py", "go", "cs", "rb", "sql", "prisma", "env", "yaml", "yml", "json"];
const RUN_SCOPES: Array<{ id: ScanScope; label: string; description: string }> = [
  { id: "database", label: "DB 스캔", description: "설정된 데이터베이스 대상을 검사합니다." },
  { id: "code", label: "코드 스캔", description: "설정된 소스코드 대상을 검사합니다." },
];
const PLUGIN_OPTIONS: ScanPluginOption[] = [
  { id: "iso27001", label: "ISO 27001", description: "정책/통제항목 컴플라이언스 플러그인 (준비중)", enabled: false },
  { id: "isms-p", label: "ISMS-P", description: "국내 정보보호 인증 점검 플러그인 (준비중)", enabled: false },
  { id: "pci-dss", label: "PCI-DSS", description: "결제/카드 데이터 보호 규격 플러그인 (준비중)", enabled: false },
];
const TENANT_STORAGE_KEY = "scannerTenantId";
const AUTH_MODE_STORAGE_KEY = "scannerAuthMode";
const USER_ID_STORAGE_KEY = "scannerUserId";

function getStoredTenantId(): string {
  if (typeof window === "undefined") return "default";
  const value = window.localStorage.getItem(TENANT_STORAGE_KEY)?.trim();
  return value || "default";
}

function getStoredAuthMode(): "none" | "proxy" {
  if (typeof window === "undefined") return "none";
  return window.localStorage.getItem(AUTH_MODE_STORAGE_KEY) === "proxy" ? "proxy" : "none";
}

function getStoredUserId(): string {
  if (typeof window === "undefined") return "local-admin";
  const value = window.localStorage.getItem(USER_ID_STORAGE_KEY)?.trim();
  return value || "local-admin";
}

function normalizeArray<T>(payload: ApiArray<T>): T[] {
  if (Array.isArray(payload)) return payload;
  if (payload && Array.isArray((payload as { value: T[] }).value)) return (payload as { value: T[] }).value;
  return [];
}

async function api<T>(path: string, options: RequestInit = {}): Promise<T> {
  const tenantId = getStoredTenantId();
  const authMode = getStoredAuthMode();
  const headers: HeadersInit = {
    "Content-Type": "application/json",
    ...(options.headers || {}),
  };

  if (authMode !== "proxy") {
    headers["X-Tenant-Id"] = tenantId;
    headers["X-User-Id"] = getStoredUserId();
  }

  const res = await fetch(path, { ...options, headers });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error((data as { error?: string }).error ?? `HTTP ${res.status}`);
  }
  return data as T;
}

function getCommonRoot(paths: string[]): string {
  if (!paths.length) return "";
  const split = paths.map((p) => p.split("/").filter(Boolean));
  const minLen = Math.min(...split.map((s) => s.length));
  const out: string[] = [];
  for (let i = 0; i < minLen - 1; i += 1) {
    const token = split[0][i];
    if (split.every((s) => s[i] === token)) out.push(token);
    else break;
  }
  return out.length ? `/${out.join("/")}` : "";
}

type ToastState = { msg: string; error?: boolean } | null;

type TabKey = "configs" | "scans" | "reports";

function App(): JSX.Element {
  const [tab, setTab] = useState<TabKey>("configs");
  const [toast, setToast] = useState<ToastState>(null);

  const [configs, setConfigs] = useState<ConfigItem[]>([]);
  const [scans, setScans] = useState<ScanListItem[]>([]);
  const [tenantId, setTenantId] = useState<string>(() => getStoredTenantId());
  const [authMode, setAuthMode] = useState<"none" | "proxy">(() => getStoredAuthMode());
  const [userDisplay, setUserDisplay] = useState("local-admin");
  const [allowedCodeRoots, setAllowedCodeRoots] = useState<string[]>([]);
  const [requireAuth, setRequireAuth] = useState(false);

  const [configId, setConfigId] = useState("");
  const [configName, setConfigName] = useState("");
  const [configDesc, setConfigDesc] = useState("");

  const [dbDialect, setDbDialect] = useState<DbTarget["dialect"] | "">("");
  const [dbHost, setDbHost] = useState("localhost");
  const [dbPort, setDbPort] = useState("5432");
  const [dbName, setDbName] = useState("");
  const [dbUser, setDbUser] = useState("");
  const [dbPassword, setDbPassword] = useState("");
  const [dbFilePath, setDbFilePath] = useState("");
  const [dbSsl, setDbSsl] = useState(false);
  const [dbTargets, setDbTargets] = useState<DbTarget[]>([]);
  const [dbReadonlyHint, setDbReadonlyHint] = useState("");
  const [dbMeta, setDbMeta] = useState<DbIntrospectResult | null>(null);
  const [selectedSchemas, setSelectedSchemas] = useState<string[]>([]);

  const [rootPath, setRootPath] = useState("");
  const [fsReadable, setFsReadable] = useState<boolean | null>(null);
  const [fsError, setFsError] = useState("");
  const [dirs, setDirs] = useState<string[]>([]);
  const [exts, setExts] = useState<string[]>([...DEFAULT_EXTS]);
  const [selectedDirs, setSelectedDirs] = useState<string[]>([]);
  const [selectedExts, setSelectedExts] = useState<string[]>([...DEFAULT_EXTS]);

  const [scanConfigId, setScanConfigId] = useState("");
  const [selectedScanScopes, setSelectedScanScopes] = useState<ScanScope[]>(["database", "code"]);
  const [selectedPlugins, setSelectedPlugins] = useState<string[]>([]);
  const [activeScanId, setActiveScanId] = useState("");
  const [progress, setProgress] = useState<ScanProgress | null>(null);
  const [expandedConfigId, setExpandedConfigId] = useState<string | null>(null);

  const [report, setReport] = useState<ScanReport | null>(null);

  const notify = (msg: string, error = false): void => {
    setToast({ msg, error });
    setTimeout(() => setToast(null), 2600);
  };

  const clearForm = (): void => {
    setConfigId("");
    setConfigName("");
    setConfigDesc("");
    setDbDialect("");
    setDbHost("localhost");
    setDbPort("5432");
    setDbName("");
    setDbUser("");
    setDbPassword("");
    setDbFilePath("");
    setDbSsl(false);
    setDbTargets([]);
    setDbReadonlyHint("");
    setDbMeta(null);
    setSelectedSchemas([]);
    setRootPath("");
    setFsReadable(null);
    setFsError("");
    setDirs([]);
    setExts([...DEFAULT_EXTS]);
    setSelectedDirs([]);
    setSelectedExts([...DEFAULT_EXTS]);
  };

  const loadConfigs = async (): Promise<void> => {
    const data = await api<ApiArray<ConfigItem>>("/api/configs");
    setConfigs(normalizeArray(data));
  };

  const loadScans = async (): Promise<void> => {
    const data = await api<ApiArray<ScanListItem>>("/api/scans");
    setScans(normalizeArray(data));
  };

  useEffect(() => {
    window.localStorage.setItem(TENANT_STORAGE_KEY, tenantId.trim() || "default");
    window.localStorage.setItem(AUTH_MODE_STORAGE_KEY, authMode);
    loadConfigs().catch((e) => notify((e as Error).message, true));
    loadScans().catch((e) => notify((e as Error).message, true));
  }, [tenantId, authMode]);

  useEffect(() => {
    api<RuntimeContext>("/api/runtime-context")
      .then((context) => {
        setAllowedCodeRoots(context.allowedCodeRoots || []);
        setRequireAuth(Boolean(context.requireAuth));
        setAuthMode(context.authMode);
        if (context.authMode === "proxy") {
          setTenantId(context.auth.tenantId);
        }
        if (context.auth.userId) {
          window.localStorage.setItem(USER_ID_STORAGE_KEY, context.auth.userId);
        }
        setUserDisplay(context.auth.displayName || context.auth.username || context.auth.userId || "anonymous");
      })
      .catch((e) => notify((e as Error).message, true));
  }, []);

  useEffect(() => {
    if (!activeScanId) return;
    const timer = window.setInterval(async () => {
      try {
        const p = await api<ScanProgress>(`/api/scans/${activeScanId}/progress`);
        setProgress(p);
        if (p.status === "completed" || p.status === "failed") {
          setActiveScanId("");
          await loadScans();
          setTab("reports");
        }
      } catch {
        setActiveScanId("");
      }
    }, 700);
    return () => window.clearInterval(timer);
  }, [activeScanId]);

  const progressPct = useMemo(() => {
    if (!progress || !progress.totalItems) return 0;
    return Math.round((progress.processedItems / progress.totalItems) * 100);
  }, [progress]);

  const dialectDisabled = dbDialect === "";
  const sqlite = dbDialect === "sqlite";

  const inspectRoot = async (): Promise<void> => {
    const path = rootPath.trim();
    if (!path) {
      notify("프로젝트 루트 경로를 입력하세요.", true);
      return;
    }
    try {
      const fs = await api<FsInspectResult>("/api/fs/inspect", {
        method: "POST",
        body: JSON.stringify({ rootPath: path }),
      });
      const nextDirs = fs.directories || [];
      const nextExts = fs.extensions.length ? fs.extensions : [...DEFAULT_EXTS];
      setFsReadable(true);
      setFsError("");
      setDirs(nextDirs);
      setSelectedDirs(nextDirs);
      setExts(nextExts);
      setSelectedExts(nextExts);
      setAllowedCodeRoots(fs.allowedCodeRoots || []);
      notify(`읽기 가능: 디렉토리 ${nextDirs.length}개, 포맷 ${nextExts.length}개`);
    } catch (e) {
      setFsReadable(false);
      setFsError((e as Error).message);
      notify((e as Error).message, true);
    }
  };

  const introspectDb = async (): Promise<void> => {
    if (!dbDialect) {
      notify("DB 종류를 선택하세요.", true);
      return;
    }
    try {
      const data = await api<DbIntrospectResult>("/api/db-introspect", {
        method: "POST",
        body: JSON.stringify({
          dialect: dbDialect,
          host: dbHost || undefined,
          port: dbPort ? Number(dbPort) : undefined,
          database: dbName,
          username: dbUser || undefined,
          password: dbPassword || undefined,
          filePath: dbFilePath || undefined,
          ssl: dbSsl,
        }),
      });
      setDbMeta(data);
      setDbReadonlyHint(data.readonlyMessage || "");
      setSelectedSchemas(data.schemas || []);
      notify("DB 메타 조회 완료");
    } catch (e) {
      notify((e as Error).message, true);
    }
  };

  const testDb = async (): Promise<void> => {
    if (!dbDialect) {
      notify("DB 종류를 선택하세요.", true);
      return;
    }
    try {
      const data = await api<{ success: boolean; message?: string }>("/api/db-test", {
        method: "POST",
        body: JSON.stringify({
          dialect: dbDialect,
          host: dbHost || undefined,
          port: dbPort ? Number(dbPort) : undefined,
          database: dbName,
          username: dbUser || undefined,
          password: dbPassword || undefined,
          filePath: dbFilePath || undefined,
          ssl: dbSsl,
          schemas: selectedSchemas,
        }),
      });
      notify(data.message || "연결 성공");
    } catch (e) {
      notify((e as Error).message, true);
    }
  };

  const addDbTarget = (): void => {
    if (!dbDialect || !dbName) {
      notify("DB 종류/데이터베이스를 입력하세요.", true);
      return;
    }
    const target: DbTarget = {
      dialect: dbDialect,
      host: dbHost || undefined,
      port: dbPort ? Number(dbPort) : undefined,
      database: dbName,
      username: dbUser || undefined,
      password: dbPassword || undefined,
      filePath: dbFilePath || undefined,
      ssl: dbSsl || undefined,
      schemas: selectedSchemas,
    };
    setDbTargets((prev) => [...prev, target]);
    notify("DB 대상이 추가되었습니다.");
  };

  const removeDbTarget = (idx: number): void => {
    setDbTargets((prev) => prev.filter((_, i) => i !== idx));
  };

  const collectCodeTargets = (): CodeTarget[] => {
    const root = rootPath.trim();
    if (!root) return [];
    const dirsToUse = selectedDirs.length ? selectedDirs : dirs;
    const extsToUse = selectedExts.length ? selectedExts : exts;

    if (!dirsToUse.length) {
      return [{
        path: root,
        includeExtensions: extsToUse,
        excludePatterns: ["node_modules", "dist", ".git", "build", "logs"],
      }];
    }

    return dirsToUse.map((d) => ({
      path: `${root.replace(/\/$/, "")}/${d}`,
      includeExtensions: extsToUse,
      excludePatterns: ["node_modules", "dist", ".git", "build", "logs"],
    }));
  };

  const saveConfig = async (): Promise<void> => {
    if (!configName.trim()) {
      notify("설정 이름을 입력하세요.", true);
      return;
    }
    if (!dbTargets.length) {
      notify("최소 1개 DB 대상을 추가하세요.", true);
      return;
    }
    const codeTargets = collectCodeTargets();
    if (!codeTargets.length) {
      notify("코드 루트/대상을 설정하세요.", true);
      return;
    }

    const payload = {
      tenantId,
      name: configName.trim(),
      description: configDesc.trim(),
      dbTargets,
      codeTargets,
      ruleOverride: {
        aiReview: {
          enabled: true,
          mode: "advisory",
          provider: "http",
          model: "exaone-4.5-1.2b",
          minScore: 0.45,
          maxItems: 300,
          timeoutMs: 3000,
        },
      },
    };

    const isEdit = Boolean(configId);
    await api(isEdit ? `/api/configs/${configId}` : "/api/configs", {
      method: isEdit ? "PUT" : "POST",
      body: JSON.stringify(payload),
    });

    notify(isEdit ? "설정이 수정되었습니다." : "설정이 저장되었습니다.");
    clearForm();
    await loadConfigs();
  };

  const editConfig = async (id: string): Promise<void> => {
    const cfg = await api<ConfigItem>(`/api/configs/${id}`);
    setConfigId(cfg.id);
    setConfigName(cfg.name || "");
    setConfigDesc(cfg.description || "");

    const firstDb = cfg.dbTargets[0];
    if (firstDb) {
      setDbDialect(firstDb.dialect);
      setDbHost(firstDb.host || "localhost");
      setDbPort(firstDb.port ? String(firstDb.port) : "");
      setDbName(firstDb.database || "");
      setDbUser(firstDb.username || "");
      setDbPassword(firstDb.password || "");
      setDbFilePath(firstDb.filePath || "");
      setDbSsl(Boolean(firstDb.ssl));
      setSelectedSchemas(firstDb.schemas || []);
    }

    setDbTargets(cfg.dbTargets || []);

    const paths = cfg.codeTargets.map((c) => c.path);
    const root = getCommonRoot(paths);
    setRootPath(root || "");

    if (root) {
      await inspectRoot();
      const dirNames = cfg.codeTargets
        .map((c) => c.path.replace(root.replace(/\/$/, "") + "/", "").split("/")[0])
        .filter(Boolean);
      const extNames = [...new Set(cfg.codeTargets.flatMap((c) => c.includeExtensions || []))];
      setSelectedDirs(dirNames);
      if (extNames.length) setSelectedExts(extNames);
    }

    setTab("configs");
    notify("설정을 불러왔습니다.");
  };

  const deleteConfig = async (id: string): Promise<void> => {
    if (!window.confirm("설정을 삭제하시겠습니까?")) return;
    await api(`/api/configs/${id}`, { method: "DELETE" });
    notify("삭제되었습니다.");
    await loadConfigs();
  };

  const startScan = async (): Promise<void> => {
    if (!scanConfigId) {
      notify("실행할 설정을 선택하세요.", true);
      return;
    }
    if (!selectedScanScopes.length) {
      notify("최소 1개 스캔 소스를 선택하세요.", true);
      return;
    }

    const selectedConfig = configs.find((c) => c.id === scanConfigId);
    const estimatedItems = Math.max(
      1,
      (selectedScanScopes.includes("database") ? selectedConfig?.dbTargets?.length ?? 0 : 0) +
        (selectedScanScopes.includes("code") ? selectedConfig?.codeTargets?.length ?? 0 : 0)
    );

    const data = await api<{ scanId: string }>("/api/scans", {
      method: "POST",
      body: JSON.stringify({
        configId: scanConfigId,
        sources: selectedScanScopes,
        plugins: selectedPlugins,
      }),
    });

    setActiveScanId(data.scanId);
    setProgress({
      status: "running",
      findingsCount: 0,
      processedItems: 0,
      totalItems: estimatedItems,
      elapsedMs: 0,
      currentTarget: "준비 중",
    });
    notify("스캔 시작됨");
  };

  const openReport = async (id: string): Promise<void> => {
    const data = await api<ScanReport>(`/api/scans/${id}`);
    setReport(data);
  };

  const toggleConfigExpand = (id: string): void => {
    setExpandedConfigId((prev) => (prev === id ? null : id));
  };

  return (
    <div className="shell">
      <header className="topbar">
        <div>
          <h1>민감정보 스캐너</h1>
          <p>TypeScript + React UI. 정보 밀도 높은 그리드 운영 화면</p>
        </div>
        <div style={{ display: "grid", gap: 8, minWidth: 280 }}>
          <label className="hint" style={{ display: "grid", gap: 4 }}>
            <span>{authMode === "proxy" ? "Tenant ID (프록시 고정)" : requireAuth ? "Tenant ID (필수)" : "Tenant ID"}</span>
            <input value={tenantId} onChange={(e) => setTenantId(e.target.value)} placeholder="customer-a" disabled={authMode === "proxy"} />
          </label>
          <div className="hint">사용자 {userDisplay} | 설정 {configs.length}개 | 리포트 {scans.length}개</div>
        </div>
      </header>

      <div className="tabbar">
        <button className={`tab-btn ${tab === "configs" ? "active" : ""}`} onClick={() => setTab("configs")}>설정</button>
        <button className={`tab-btn ${tab === "scans" ? "active" : ""}`} onClick={() => setTab("scans")}>스캔 실행</button>
        <button className={`tab-btn ${tab === "reports" ? "active" : ""}`} onClick={() => { setTab("reports"); loadScans().catch(() => undefined); }}>리포트</button>
      </div>

      {tab === "configs" && (
        <div className="layout">
          <section className="card">
            <h2>{configId ? "스캔 설정 수정" : "새 스캔 설정"}</h2>

            <div className="grid-2">
              <div className="field full">
                <label>설정 이름</label>
                <input value={configName} onChange={(e) => setConfigName(e.target.value)} placeholder="예: 운영 DB 점검" />
              </div>

              <div className="field full">
                <label>설명</label>
                <input value={configDesc} onChange={(e) => setConfigDesc(e.target.value)} placeholder="선택사항" />
              </div>

              <div className="field full section-title">DB 연결 설정</div>

              <div className="field">
                <label>DB 종류</label>
                <select value={dbDialect} onChange={(e) => setDbDialect(e.target.value as DbTarget["dialect"] | "") }>
                  <option value="">-- 선택 --</option>
                  <option value="postgresql">PostgreSQL</option>
                  <option value="mysql">MySQL</option>
                  <option value="sqlite">SQLite</option>
                </select>
              </div>

              <div className="field">
                <label>데이터베이스</label>
                <input value={dbName} onChange={(e) => setDbName(e.target.value)} disabled={dialectDisabled} />
              </div>

              <div className="field">
                <label>호스트</label>
                <input value={dbHost} onFocus={() => setDbReadonlyHint("운영 DB는 readonly/ro 계정 사용 권장")} onChange={(e) => setDbHost(e.target.value)} disabled={dialectDisabled || sqlite} />
              </div>

              <div className="field">
                <label>포트</label>
                <input value={dbPort} onFocus={() => setDbReadonlyHint("운영 DB는 readonly/ro 계정 사용 권장")} onChange={(e) => setDbPort(e.target.value)} disabled={dialectDisabled || sqlite} />
              </div>

              <div className="field">
                <label>사용자명</label>
                <input value={dbUser} onFocus={() => setDbReadonlyHint("운영 DB는 readonly/ro 계정 사용 권장")} onChange={(e) => setDbUser(e.target.value)} disabled={dialectDisabled || sqlite} />
              </div>

              <div className="field">
                <label>비밀번호</label>
                <input type="password" value={dbPassword} onFocus={() => setDbReadonlyHint("운영 DB는 readonly/ro 계정 사용 권장")} onChange={(e) => setDbPassword(e.target.value)} disabled={dialectDisabled || sqlite} />
              </div>

              <div className="field full">
                <label className="check-item">
                  <input type="checkbox" checked={dbSsl} onChange={(e) => setDbSsl(e.target.checked)} /> SSL 사용
                </label>
              </div>

              <div className="field full actions">
                <button className="btn outline" onClick={introspectDb} disabled={dialectDisabled}>메타 조회</button>
                <button className="btn outline" onClick={testDb} disabled={dialectDisabled}>연결 테스트</button>
                <button className="btn primary" onClick={addDbTarget} disabled={dialectDisabled}>DB 대상 추가</button>
              </div>

              {dbReadonlyHint && <div className="field full hint warn">{dbReadonlyHint}</div>}

              {dbMeta && (
                <div className="field full">
                  <div className="hint">현재 DB: {dbMeta.database || "-"}</div>
                  <div className="hint">사용 가능 DB: {(dbMeta.databases || []).join(", ") || "-"}</div>
                  <div className="section-title">검사할 스키마 (기본 전체)</div>
                  <div className="pillbox check-grid">
                    {(dbMeta.schemas || []).map((s) => (
                      <label key={s} className="check-item">
                        <input
                          type="checkbox"
                          checked={selectedSchemas.includes(s)}
                          onChange={(e) => {
                            setSelectedSchemas((prev) =>
                              e.target.checked ? [...new Set([...prev, s])] : prev.filter((x) => x !== s)
                            );
                          }}
                        />
                        {s}
                      </label>
                    ))}
                  </div>
                </div>
              )}

              {dbTargets.length > 0 && (
                <div className="field full">
                  <div className="section-title">추가된 DB 대상</div>
                  <div className="pillbox">
                    {dbTargets.map((t, i) => (
                      <div key={`${t.dialect}-${t.database}-${i}`} style={{ display: "grid", gridTemplateColumns: "1fr auto", gap: 8, marginBottom: 6 }}>
                        <div className="hint">{`${t.dialect.toUpperCase()} ${t.host || t.filePath}:${t.database} (${(t.schemas || []).join(",") || "-"})`}</div>
                        <button className="btn danger" onClick={() => removeDbTarget(i)}>삭제</button>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <div className="field full section-title">코드 스캔 설정</div>

              <div className="field full">
                <label>프로젝트 루트 경로</label>
                <input value={rootPath} onChange={(e) => setRootPath(e.target.value)} placeholder="/workspace/dart-ai-trading-bot" />
              </div>

              {allowedCodeRoots.length > 0 && (
                <div className="field full hint">
                  허용 루트: {allowedCodeRoots.join(", ")}
                </div>
              )}

              <div className="field full actions">
                <button className="btn outline" onClick={inspectRoot}>루트 권한/목록 조회</button>
                <button className="btn outline" onClick={() => { setRootPath('/app'); setTimeout(() => { inspectRoot().catch(() => undefined); }, 0); }}>샘플</button>
                <button className="btn outline" onClick={() => { setRootPath('/workspace/dart-ai-trading-bot'); setTimeout(() => { inspectRoot().catch(() => undefined); }, 0); }}>DART</button>
              </div>

              {fsReadable === true && <div className="field full hint ok">읽기 가능: 디렉토리 {dirs.length}개 / 포맷 {exts.length}개</div>}
              {fsReadable === false && <div className="field full hint err">{fsError || "읽기 권한 없음"}</div>}

              <div className="field full">
                <div className="section-title">검사할 디렉토리 (기본 전체)</div>
                <div className="pillbox check-grid">
                  {dirs.map((d) => (
                    <label key={d} className="check-item">
                      <input
                        type="checkbox"
                        checked={selectedDirs.includes(d)}
                        onChange={(e) => {
                          setSelectedDirs((prev) =>
                            e.target.checked ? [...new Set([...prev, d])] : prev.filter((x) => x !== d)
                          );
                        }}
                      />
                      {d}
                    </label>
                  ))}
                </div>
              </div>

              <div className="field full">
                <div className="section-title">검사할 파일 포맷 (기본 전체)</div>
                <div className="pillbox check-grid">
                  {exts.map((ext) => (
                    <label key={ext} className="check-item">
                      <input
                        type="checkbox"
                        checked={selectedExts.includes(ext)}
                        onChange={(e) => {
                          setSelectedExts((prev) =>
                            e.target.checked ? [...new Set([...prev, ext])] : prev.filter((x) => x !== ext)
                          );
                        }}
                      />
                      .{ext}
                    </label>
                  ))}
                </div>
              </div>

              <div className="field full actions">
                <button className="btn primary" onClick={() => { saveConfig().catch((e) => notify((e as Error).message, true)); }}>{configId ? "설정 업데이트" : "설정 저장"}</button>
                {configId && <button className="btn neutral" onClick={clearForm}>편집 취소</button>}
              </div>
            </div>
          </section>

          <section className="card">
            <h2>저장된 설정</h2>
            {configs.length === 0 && <div className="hint">저장된 설정이 없습니다.</div>}
            <div className="config-accordion">
              {configs.map((c) => {
                const expanded = expandedConfigId === c.id;
                return (
                  <article key={c.id} className="config-item">
                    <button
                      type="button"
                      className="config-head"
                      onClick={() => toggleConfigExpand(c.id)}
                      aria-expanded={expanded}
                    >
                      <div>
                        <strong>{c.name}</strong>
                        <div className="hint">{c.id.slice(0, 8)}</div>
                      </div>
                      <div className="config-meta">
                        <span className="config-chip">DB {c.dbTargets?.length ?? 0}</span>
                        <span className="config-chip">CODE {c.codeTargets?.length ?? 0}</span>
                        <span className="config-arrow">{expanded ? "-" : "+"}</span>
                      </div>
                    </button>

                    {expanded && (
                      <div className="config-body">
                        <div className="hint">{c.description || "설명 없음"}</div>
                        <div className="section-title">DB Targets</div>
                        <div className="pillbox">
                          {(c.dbTargets || []).map((t, i) => (
                            <div key={`${c.id}-db-${i}`} className="hint">
                              {`${t.dialect.toUpperCase()} ${t.host || t.filePath || "-"}:${t.database} / schemas: ${(t.schemas || []).join(",") || "all"}`}
                            </div>
                          ))}
                        </div>
                        <div className="section-title">Code Targets</div>
                        <div className="pillbox">
                          {(c.codeTargets || []).map((t, i) => (
                            <div key={`${c.id}-code-${i}`} className="hint">
                              {`${t.path} / ext: ${(t.includeExtensions || []).join(",") || "all"}`}
                            </div>
                          ))}
                        </div>
                        <div className="actions">
                          <button className="btn outline" onClick={() => { editConfig(c.id).catch((e) => notify((e as Error).message, true)); }}>수정</button>
                          <button className="btn danger" onClick={() => { deleteConfig(c.id).catch((e) => notify((e as Error).message, true)); }}>삭제</button>
                        </div>
                      </div>
                    )}
                  </article>
                );
              })}
            </div>
          </section>
        </div>
      )}

      {tab === "scans" && (
        <div className="layout">
          <section className="card">
            <h2>스캔 실행</h2>
            <div className="field">
              <label>실행할 설정</label>
              <select value={scanConfigId} onChange={(e) => setScanConfigId(e.target.value)}>
                <option value="">-- 설정 선택 --</option>
                {configs.map((c) => <option value={c.id} key={c.id}>{c.name}</option>)}
              </select>
            </div>

            <div className="field full">
              <div className="section-title">실행 소스 선택 (복수 선택)</div>
              <div className="pillbox check-grid run-scope-grid">
                {RUN_SCOPES.map((scope) => (
                  <label key={scope.id} className="check-item run-scope-item">
                    <input
                      type="checkbox"
                      checked={selectedScanScopes.includes(scope.id)}
                      onChange={(e) => {
                        setSelectedScanScopes((prev) =>
                          e.target.checked
                            ? [...new Set([...prev, scope.id])]
                            : prev.filter((v) => v !== scope.id)
                        );
                      }}
                    />
                    <span>
                      <strong>{scope.label}</strong>
                      <small>{scope.description}</small>
                    </span>
                  </label>
                ))}
              </div>
            </div>

            <div className="field full">
              <div className="section-title">플러그인 선택 (로드맵)</div>
              <div className="pillbox check-grid plugin-grid">
                {PLUGIN_OPTIONS.map((plugin) => (
                  <label key={plugin.id} className={`check-item plugin-item ${plugin.enabled ? "" : "is-disabled"}`}>
                    <input
                      type="checkbox"
                      checked={selectedPlugins.includes(plugin.id)}
                      onChange={(e) => {
                        setSelectedPlugins((prev) =>
                          e.target.checked
                            ? [...new Set([...prev, plugin.id])]
                            : prev.filter((v) => v !== plugin.id)
                        );
                      }}
                      disabled={!plugin.enabled}
                    />
                    <span>
                      <strong>{plugin.label}</strong>
                      <small>{plugin.description}</small>
                    </span>
                  </label>
                ))}
              </div>
              <div className="hint">현재는 DB/코드 스캔 엔진이 활성화되어 있고, 플러그인 엔진은 순차 확장 예정입니다.</div>
            </div>

            <div className="actions">
              <button className="btn primary" onClick={() => { startScan().catch((e) => notify((e as Error).message, true)); }}>스캔 시작</button>
            </div>
          </section>

          <section className="card">
            <h2>진행 상태</h2>
            {progress ? (
              <>
                <div className={`hint status-${progress.status}`}>{progress.status}</div>
                <div className="progress"><div style={{ width: `${progressPct}%` }} /></div>
                <div className="hint">진행률: {progressPct}% ({progress.processedItems}/{progress.totalItems})</div>
                <div className="hint">발견: {progress.findingsCount}건</div>
                <div className="hint">대상: {progress.currentTarget || "-"}</div>
                <div className="hint">경과: {(progress.elapsedMs / 1000).toFixed(1)}s</div>
              </>
            ) : (
              <div className="hint">실행 중인 스캔이 없습니다.</div>
            )}
          </section>
        </div>
      )}

      {tab === "reports" && (
        <div className="layout">
          <section className="card">
            <h2>스캔 결과 목록</h2>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>설정</th>
                    <th>상태</th>
                    <th>발견</th>
                    <th>AI Drop</th>
                    <th>완료시각</th>
                    <th>작업</th>
                  </tr>
                </thead>
                <tbody>
                  {scans.length === 0 && <tr><td colSpan={6}>스캔 결과가 없습니다.</td></tr>}
                  {scans.map((s) => (
                    <tr key={s.id}>
                      <td>{s.configName}</td>
                      <td className={`status-${s.status}`}>{s.status}</td>
                      <td>{s.summary?.totalFindings ?? 0}</td>
                      <td>{s.summary?.aiDroppedCount ?? 0}</td>
                      <td>{s.completedAt ? s.completedAt.replace("T", " ").slice(0, 19) : "-"}</td>
                      <td>
                        <div className="actions">
                          <button className="btn outline" onClick={() => { openReport(s.id).catch((e) => notify((e as Error).message, true)); }}>상세</button>
                          <a
                            className="btn outline"
                            href={authMode === "proxy" ? `/api/scans/${s.id}/report.html` : `/api/scans/${s.id}/report.html?tenantId=${encodeURIComponent(tenantId)}`}
                            target="_blank"
                            rel="noreferrer"
                          >
                            HTML
                          </a>
                          <a
                            className="btn outline"
                            href={authMode === "proxy" ? `/api/scans/${s.id}/report.json` : `/api/scans/${s.id}/report.json?tenantId=${encodeURIComponent(tenantId)}`}
                          >
                            JSON
                          </a>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>

          <section className="card">
            <h2>{report ? `상세 결과 - ${report.configName}` : "상세 결과"}</h2>
            {!report ? (
              <div className="hint">목록에서 상세를 선택하세요.</div>
            ) : (
              <>
                <div className="kpi-grid">
                  {[
                    ["총 발견", report.summary.totalFindings],
                    ["Critical", report.summary.bySeverity.critical],
                    ["High", report.summary.bySeverity.high],
                    ["Medium", report.summary.bySeverity.medium],
                    ["Low", report.summary.bySeverity.low],
                    ["AI Drop", report.summary.aiDroppedCount ?? 0],
                  ].map(([k, v]) => (
                    <div key={String(k)} className="kpi">
                      <div className="label">{k}</div>
                      <div className="value">{String(v)}</div>
                    </div>
                  ))}
                </div>

                <div className="table-wrap report-findings-desktop">
                  <table>
                    <thead>
                      <tr>
                        <th>출처</th>
                        <th>심각도</th>
                        <th>카테고리</th>
                        <th>룰</th>
                        <th>대상</th>
                        <th>AI</th>
                      </tr>
                    </thead>
                    <tbody>
                      {report.findings.length === 0 && <tr><td colSpan={6}>발견 항목이 없습니다.</td></tr>}
                      {report.findings.map((f, idx) => (
                        <tr key={`${f.ruleId}-${idx}`}>
                          <td>{f.source}</td>
                          <td>{f.severity}</td>
                          <td>{f.category}</td>
                          <td>{f.ruleName}</td>
                          <td className="target-cell">
                            {f.source === "database"
                              ? `${f.database}.${f.schema}.${f.table}.${f.column}`
                              : `${f.filePath}:${f.line}`}
                          </td>
                          <td>{f.aiReview ? `${f.aiReview.decision} (${Math.round(f.aiReview.score * 100)}%)` : "-"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>

                <div className="report-findings-mobile">
                  {report.findings.length === 0 && <div className="hint">발견 항목이 없습니다.</div>}
                  {report.findings.map((f, idx) => (
                    <article className="finding-card" key={`mobile-${f.ruleId}-${idx}`}>
                      <div className="finding-head">
                        <span className={`badge status-${f.severity}`}>{f.severity}</span>
                        <strong>{f.ruleName}</strong>
                      </div>
                      <div className="finding-row"><b>출처</b><span>{f.source}</span></div>
                      <div className="finding-row"><b>카테고리</b><span>{f.category}</span></div>
                      <div className="finding-row">
                        <b>대상</b>
                        <span className="target-cell">
                          {f.source === "database"
                            ? `${f.database}.${f.schema}.${f.table}.${f.column}`
                            : `${f.filePath}:${f.line}`}
                        </span>
                      </div>
                      <div className="finding-row">
                        <b>AI</b>
                        <span>{f.aiReview ? `${f.aiReview.decision} (${Math.round(f.aiReview.score * 100)}%)` : "-"}</span>
                      </div>
                    </article>
                  ))}
                </div>
              </>
            )}
          </section>
        </div>
      )}

      {toast && <div className="toast" style={{ background: toast.error ? "#b91c1c" : "#0f172a" }}>{toast.msg}</div>}
    </div>
  );
}

createRoot(document.getElementById("root") as HTMLElement).render(<App />);
