import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, extname, relative } from "node:path";
import type { RuleEngine } from "../../core/rule-engine.js";
import type { CodeFinding } from "../../types.js";

const DEFAULT_EXTENSIONS = new Set([
  ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs",
  ".py", ".rb", ".java", ".go", ".cs", ".php",
  ".env", ".env.local", ".env.production", ".env.development",
  ".yml", ".yaml", ".json", ".toml", ".ini", ".conf",
  ".xml", ".properties",
]);

const DEFAULT_EXCLUDE = [
  "node_modules",
  ".git",
  "dist",
  "build",
  ".next",
  "__pycache__",
  ".venv",
  "vendor",
];

export interface CodeScanOptions {
  excludePatterns?: string[];
  includeExtensions?: string[];
  onProgress?: (message: string) => void;
}

function shouldExclude(filePath: string, excludes: string[]): boolean {
  const parts = filePath.replace(/\\/g, "/").split("/");
  return excludes.some((ex) => parts.includes(ex));
}

function collectFiles(
  dir: string,
  extensions: Set<string>,
  excludes: string[]
): string[] {
  const results: string[] = [];

  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return results;
  }

  for (const entry of entries) {
    const fullPath = join(dir, entry);
    if (shouldExclude(fullPath, excludes)) continue;

    let stat;
    try {
      stat = statSync(fullPath);
    } catch {
      continue;
    }

    if (stat.isDirectory()) {
      results.push(...collectFiles(fullPath, extensions, excludes));
    } else if (stat.isFile()) {
      const ext = extname(entry).toLowerCase();
      // .env 파일은 확장자가 없거나 .env 자체인 경우 포함
      const isEnvFile =
        entry.startsWith(".env") ||
        entry === ".env";
      if (extensions.has(ext) || isEnvFile) {
        results.push(fullPath);
      }
    }
  }
  return results;
}

// ─────────────────────────────────────────────────────────────────────────────

export class CodeScanner {
  constructor(private readonly ruleEngine: RuleEngine) {}

  scan(rootPath: string, options: CodeScanOptions = {}): CodeFinding[] {
    const {
      excludePatterns = DEFAULT_EXCLUDE,
      includeExtensions,
      onProgress,
    } = options;

    const extensions = includeExtensions
      ? new Set(includeExtensions.map((e) => (e.startsWith(".") ? e : `.${e}`)))
      : DEFAULT_EXTENSIONS;

    const files = collectFiles(rootPath, extensions, [
      ...DEFAULT_EXCLUDE,
      ...excludePatterns,
    ]);

    onProgress?.(`[Code] 파일 ${files.length}개 스캔 시작`);

    const findings: CodeFinding[] = [];

    for (const filePath of files) {
      let content: string;
      try {
        content = readFileSync(filePath, "utf-8");
      } catch {
        continue;
      }

      const lines = content.split(/\r?\n/);
      const relPath = relative(rootPath, filePath).replace(/\\/g, "/");

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const matchedRules = this.ruleEngine.matchCodeLine(line);

        for (const rule of matchedRules) {
          if (!rule.codePattern) continue;

          // 컬럼 위치 계산
          rule.codePattern.lastIndex = 0;
          const match = rule.codePattern.exec(line);
          const col = match?.index ?? 0;

          findings.push({
            source: "code",
            ruleId: rule.id,
            ruleName: rule.name,
            category: rule.category,
            severity: rule.severity,
            filePath: relPath,
            line: i + 1,
            column: col + 1,
            snippet: this.ruleEngine.redactCodeLine(line),
            matchedBy: "pattern",
          });
        }
      }
    }

    onProgress?.(`[Code] 스캔 완료 - 발견 ${findings.length}건`);
    return findings;
  }
}
