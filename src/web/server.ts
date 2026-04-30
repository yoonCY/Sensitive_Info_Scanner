import express from "express";
import { existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { ConfigManager } from "../core/config-manager.js";
import { ScannerEngine, getScanProgress, getScanReport, listScanReports } from "../core/scanner-engine.js";
import { ReportGenerator } from "../core/report-generator.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const distPublicDir = join(__dirname, "public");
const srcPublicDir = join(process.cwd(), "src", "web", "public");
const publicDir = existsSync(distPublicDir) ? distPublicDir : srcPublicDir;

const app = express();
app.use(express.json());
app.use(express.static(publicDir));

const configManager = new ConfigManager();
const scannerEngine = new ScannerEngine();
const reportGen = new ReportGenerator();

// ── 설정 API ──────────────────────────────────────────────────────────────────

app.get("/api/configs", (_req, res) => {
  res.json(configManager.listConfigs());
});

app.get("/api/configs/:id", (req, res) => {
  const config = configManager.getConfig(req.params.id);
  if (!config) return res.status(404).json({ error: "설정을 찾을 수 없습니다." });
  return res.json(config);
});

app.post("/api/configs", (req, res) => {
  try {
    const config = configManager.createConfig(req.body);
    res.status(201).json(config);
  } catch (err) {
    res.status(400).json({ error: err instanceof Error ? err.message : String(err) });
  }
});

app.put("/api/configs/:id", (req, res) => {
  try {
    const config = configManager.updateConfig(req.params.id, req.body);
    res.json(config);
  } catch (err) {
    res.status(400).json({ error: err instanceof Error ? err.message : String(err) });
  }
});

app.delete("/api/configs/:id", (req, res) => {
  try {
    configManager.deleteConfig(req.params.id);
    res.status(204).send();
  } catch (err) {
    res.status(404).json({ error: err instanceof Error ? err.message : String(err) });
  }
});

// ── 스캔 API ──────────────────────────────────────────────────────────────────

app.post("/api/scans", (req, res) => {
  const { configId } = req.body as { configId: string };
  if (!configId) {
    return res.status(400).json({ error: "configId 필드가 필요합니다." });
  }

  const config = configManager.getConfig(configId);
  if (!config) {
    return res.status(404).json({ error: "설정을 찾을 수 없습니다." });
  }

  const scanId = scannerEngine.startScan(config);
  return res.status(202).json({ scanId });
});

app.get("/api/scans", (_req, res) => {
  res.json(listScanReports());
});

app.get("/api/scans/:id/progress", (req, res) => {
  const progress = getScanProgress(req.params.id);
  if (!progress) return res.status(404).json({ error: "스캔을 찾을 수 없습니다." });
  return res.json(progress);
});

app.get("/api/scans/:id", (req, res) => {
  const report = getScanReport(req.params.id);
  if (!report) return res.status(404).json({ error: "스캔 결과를 찾을 수 없습니다." });
  return res.json(report);
});

// ── 리포트 API ────────────────────────────────────────────────────────────────

app.get("/api/scans/:id/report.html", (req, res) => {
  const report = getScanReport(req.params.id);
  if (!report) return res.status(404).send("리포트를 찾을 수 없습니다.");
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  return res.send(reportGen.toHtml(report));
});

app.get("/api/scans/:id/report.json", (req, res) => {
  const report = getScanReport(req.params.id);
  if (!report) return res.status(404).json({ error: "리포트를 찾을 수 없습니다." });
  res.setHeader("Content-Disposition", `attachment; filename="report-${req.params.id.slice(0, 8)}.json"`);
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  return res.send(reportGen.toJson(report));
});

// ─────────────────────────────────────────────────────────────────────────────

const PORT = parseInt(process.env.PORT ?? "3300", 10);
app.listen(PORT, () => {
  console.log(`🔍 민감정보 스캐너 UI → http://localhost:${PORT}`);
});

export { app };
