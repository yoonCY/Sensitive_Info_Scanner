# Changelog

All notable changes to this project are documented in this file.

## [Unreleased] - 2026-05-01

### Added
- Added SQLite-backed application data layer with tenant/user/auth context support (`src/core/app-db.ts`, `src/core/auth-context.ts`).
- Added audit logging components for scan and operational events (`src/core/audit-logger.ts`).
- Added AI-assisted review module and integration points for beta secondary decisioning (`src/core/ai-reviewer.ts`, `src/core/rule-engine.ts`, `src/core/scanner-engine.ts`).
- Added frontend source entry for bundled web UI (`frontend/app.tsx`) and generated app bundle (`src/web/public/app.js`).
- Added setup script for local environment bootstrap (`scripts/setup.mjs`) and `npm run setup` command.
- Added shared network compose override for local AI network integration (`docker-compose.shared-ai-net.yml`).

### Changed
- Changed config persistence from JSON-focused flow toward SQLite-backed storage with broader runtime config handling (`src/core/config-manager.ts`).
- Changed scan orchestration and report lifecycle with expanded result handling (`src/core/scanner-engine.ts`, `src/core/report-generator.ts`).
- Changed MCP and web server request handling/auth flow for multi-tenant and proxy header scenarios (`src/mcp/server.ts`, `src/web/server.ts`, `src/types.ts`).
- Changed package build pipeline to include web UI bundling and type checks.
- Changed container/runtime configuration for updated deployment flow (`docker-compose.yml`, `docker/Dockerfile`, `.gitignore`).
- Updated web index shell/layout for the new UI flow (`src/web/public/index.html`).

### Dependencies
- Added runtime dependencies: `react`, `react-dom`.
- Added dev dependencies: `@types/react`, `@types/react-dom`, `esbuild`.

### Documentation
- Expanded runbook and productization notes in README, including setup flow, auth/proxy environment variables, AI beta mode guidance, and compose run modes (`README.md`).
