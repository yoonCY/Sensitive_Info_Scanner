# Sensitive Info Scanner MCP

로컬 저장소(코드 파일)와 RDBMS(PostgreSQL / MySQL / SQLite)를 스캔해 민감정보를 탐지하고 리포트를 생성하는 MCP 서버 + 웹 UI입니다.

## 아키텍처

```
Core
├── RuleEngine       ← 민감정보 룰 정의 (PII / Financial / Credentials / Health)
├── ConfigManager    ← 스캔 설정 CRUD (JSON 파일 영속)
├── ScannerEngine    ← 스캔 오케스트레이터 (비동기 실행 + 진행상태)
└── ReportGenerator  ← JSON / HTML 리포트 생성

Scanners
├── DbScanner        ← DB 스캔 (컬럼명 패턴 + 데이터 샘플링 + 통계)
│   ├── PostgresAdapter  (읽기전용 세션 강제)
│   ├── MysqlAdapter     (READ ONLY 트랜잭션)
│   └── SqliteAdapter    (readonly 플래그)
└── CodeScanner      ← 코드 파일 스캔 (정규식 패턴 매칭)

Interface
├── Web UI    → http://localhost:3300  (설정 / 스캔 실행 / 리포트)
└── MCP Tools → list_configs / create_config / start_scan /
                get_scan_progress / get_scan_report / list_scans
```

## 신뢰성 원칙

| 규칙 | 세부 내용 |
|------|---------|
| **읽기전용 강제** | PostgreSQL: `SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY` · MySQL: `SET SESSION TRANSACTION READ ONLY` · SQLite: `readonly: true` 플래그 |
| **스키마 필수** | PostgreSQL / MySQL은 `schemas` 미지정 시 스캔 거부 |
| **데이터 레드액션** | 샘플 값과 코드 스니펫은 마스킹 처리 후 리포트에 저장 |

## 탐지 카테고리

| 카테고리 | 대표 룰 | 기본 심각도 |
|---------|--------|-----------|
| **PII** | 이름·이메일·전화·주소·주민번호·생년월일·IP | medium ~ critical |
| **Financial** | 카드번호·CVV·계좌번호·급여 | high ~ critical |
| **Credentials** | 비밀번호·API키·JWT·PEM 개인키·하드코딩 시크릿 | critical |
| **Health** | 진단·처방·혈액형·BMI | medium ~ critical |

## 탐지 방식 (DB)

1. **컬럼명 패턴 매칭** — 정규식으로 컬럼 이름 검사
2. **데이터 샘플링** — 비-NULL 값 최대 100행 추출 후 값 패턴 매칭
3. **통계 수집** — NULL 비율, fill rate, distinct 비율, 길이 통계

## 실행

### Docker로 웹 UI 실행 (권장)

```bash
docker compose up --build web
# → http://localhost:3300
```

### Docker로 MCP 서버 실행 (stdio)

```bash
docker compose run --rm mcp
```

### 로컬 Node 실행 (선택)

```bash
npm install
npm run build
npm run web
```

### MCP 클라이언트 설정 예시

```json
{
  "mcpServers": {
    "sensitive-info-scanner": {
      "command": "node",
      "args": ["dist/mcp/server.js"],
      "cwd": "/path/to/sensitive-info-scanner-mcp"
    }
  }
}
```

## MCP 도구 목록

| 도구 | 설명 |
|------|------|
| `list_configs` | 저장된 스캔 설정 목록 |
| `create_config` | 새 스캔 설정 생성 |
| `start_scan` | 스캔 시작 → scanId 반환 |
| `get_scan_progress` | 스캔 진행 상태 조회 |
| `get_scan_report` | 스캔 결과 조회 (요약 / 전체 JSON) |
| `list_scans` | 완료된 스캔 목록 |

## 웹 UI 사용 흐름

1. **설정 탭** → DB 연결 정보(dialect/host/database/schemas) + 코드 경로 입력 → 저장
2. **스캔 실행 탭** → 설정 선택 → ▶ 스캔 시작 → 실시간 진행 상태 확인
3. **리포트 탭** → 발견 목록 확인 · HTML 리포트 열기 · JSON 다운로드

## Phase 2 계획

- NoSQL 스캐너 (MongoDB, Redis)
- 언어별 취약점 탐지 (OWASP 패턴)
- 스캔 결과 영속화 (파일 저장)
- 알림 연동 (Slack / 이메일)
