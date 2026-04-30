# Sensitive Info Scanner MCP

로컬 저장소(코드 파일)와 RDBMS(PostgreSQL / MySQL / SQLite)를 스캔해 민감정보를 탐지하고 리포트를 생성하는 MCP 서버 + 웹 UI입니다.

## 아키텍처

```
Core
├── RuleEngine       ← 민감정보 룰 정의 (PII / Financial / Credentials / Health)
├── ConfigManager    ← 스캔 설정 CRUD (SQLite 영속)
├── ScannerEngine    ← 스캔 오케스트레이터 (비동기 실행 + 진행상태 + 결과 영속)
├── AuthContext      ← 프록시 헤더 기반 tenant/user 컨텍스트 해석
├── AppDatabase      ← tenants / users / scan_configs / scan_reports / audit_logs
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

### 초기 경로 설정 (권장)

Docker 컨테이너가 읽을 코드 저장소의 호스트 경로를 먼저 등록합니다.

```bash
npm run setup
```

- 입력값은 `.env`의 `DART_REPO_HOST_PATH`로 저장됩니다.
- `AUTH_MODE`, `REQUIRE_AUTH`, `ALLOWED_CODE_ROOTS`, `APP_DB_PATH`도 함께 저장할 수 있습니다.
- 웹 UI의 "프로젝트 루트 경로"에는 호스트 경로가 아니라 컨테이너 경로 `/workspace/dart-ai-trading-bot`를 입력해야 합니다.

### Docker로 웹 UI 실행 (권장)

```bash
docker compose up --build web
# → http://localhost:3300
```

### 멀티 사용자 배포용 환경변수

- `APP_DB_PATH`: SQLite DB 파일명. 기본 `scanner.db`
- `DEFAULT_TENANT_ID`: tenant 미지정 시 사용할 기본값. 기본 `default`
- `AUTH_MODE`: `none|proxy`. `proxy`면 리버스 프록시 헤더를 신뢰
- `REQUIRE_AUTH`: `true`면 인증 사용자/tenant 헤더가 필수
- `ALLOWED_CODE_ROOTS`: 코드 스캔 허용 루트 목록. 쉼표로 구분. 예: `/workspace/team-a,/workspace/team-b`
- `PROXY_TENANT_HEADER`: 프록시가 주입하는 tenant 헤더명. 기본 `x-auth-request-tenant`
- `PROXY_USER_HEADER`: 프록시가 주입하는 사용자 헤더명. 기본 `x-auth-request-user`
- `PROXY_EMAIL_HEADER`: 프록시가 주입하는 이메일 헤더명. 기본 `x-auth-request-email`
- `PROXY_ROLES_HEADER`: 프록시가 주입하는 그룹/역할 헤더명. 기본 `x-auth-request-groups`
- `PROXY_AUTH_SHARED_SECRET`: 프록시와 앱 사이 shared secret. 설정 시 `x-auth-proxy-secret` 검증
- `AUDIT_LOG_MIRROR_FILES`: `true`면 DB 저장 외에 기존 로그 파일도 계속 남김

예시:

```bash
APP_DB_PATH=scanner.db
AUTH_MODE=proxy
REQUIRE_AUTH=true
ALLOWED_CODE_ROOTS=/workspace/customer-a,/workspace/customer-b
PROXY_TENANT_HEADER=x-auth-request-tenant
PROXY_USER_HEADER=x-auth-request-user
PROXY_EMAIL_HEADER=x-auth-request-email
PROXY_ROLES_HEADER=x-auth-request-groups
PROXY_AUTH_SHARED_SECRET=change-me
```

- `AUTH_MODE=proxy`일 때 웹 UI의 Tenant ID는 읽기 전용이며, 서버가 프록시 헤더 기준으로 tenant/user를 강제합니다.
- `AUTH_MODE=none`일 때만 웹 UI가 `X-Tenant-Id`, `X-User-Id`를 보냅니다.
- 설정, 스캔 리포트, audit log, tenant, user 정보는 SQLite에 저장됩니다.
- 기존 `data/configs/index.json`가 있으면 DB가 비어 있는 첫 실행 시 한 번 가져옵니다.

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

## 4주 제품화 플랜 (유료 파일럿 기준)

### Week 1 - 신뢰도 계측

1. 샘플 데이터셋(정답 라벨 포함) 200~500건 구축
2. 카테고리별 Precision / Recall 측정 스크립트 추가
3. 오탐/미탐 사례를 리포트에서 태깅할 수 있는 검수 포맷 확정

### Week 2 - AI 보조 판별기(Beta)

1. 정규식 매치 결과에만 2차 판별(LLM) 적용
2. 결과 필드에 `aiScore`, `aiDecision`, `aiReason` 추가
3. 실패 시 정규식 결과로 자동 폴백(서비스 중단 방지)

### Week 3 - 운영성/배포성 강화

1. 환경변수로 AI 기능 on/off 및 타임아웃/토큰 제한 제어
2. 스캔 성능 지표(총 시간, 후보 수, LLM 호출 수) 수집
3. 배포 모드 분리: 공용 기본 compose + 로컬 오버라이드 compose

### Week 4 - 유료 파일럿 준비

1. CI 연동(스캔 실패 시 PR 경고 또는 차단 옵션)
2. 고객용 운영 문서(설치/장애/성능튜닝) 정리
3. 파일럿용 성공 지표: Precision 개선율, 재현성, 평균 스캔 시간

## 온디바이스 AI 데모 정책 (EXAONE 4.5 1.2B)

`EXAONE 4.5 1.2B`는 데모 기본 제공으로 적합하되, **정규식 대체가 아니라 보조 판별기(Beta)** 로 운영하는 것을 권장합니다.

### 권장 실행 모드

1. `GA` : 정규식 기반 탐지(기본)
2. `Beta` : LLM 2차 판별(오탐 감소, 우선순위화)
3. `Fallback` : LLM 실패/타임아웃 시 정규식 결과 유지

### 공용 쉐어 패키지 모델 사용 vs 별도 구현

#### 1) 공용 쉐어 패키지 모델 사용 (권장 시작점)

- 장점: 구현 속도 빠름, 배포 용량/시간 절감, 업데이트 단순
- 단점: 버전 고정/재현성 관리 필요, 외부 패키지 정책 의존
- 적합: 데모/파일럿 초기, 빠른 검증 단계

#### 2) 별도 구현(프로젝트 전용 모델 관리)

- 장점: 버전/캐시/보안 정책 완전 통제, 장기 운영 안정성
- 단점: 초기 구현 복잡도와 유지보수 비용 상승
- 적합: 유료 고객 온프렘/에어갭 요구가 명확한 단계

### 의사결정 가이드

1. 지금은 공용 쉐어 패키지로 시작
2. 파일럿 고객 2~3곳 확보 후 전용 다운로드/캐시 레이어 분리
3. 장기적으로는 모델 레지스트리(버전 pinning + checksum 검증)로 이관

### 이번 릴리즈 반영 사항 (AI Beta 시작)

1. `AI_REVIEW_ENDPOINT`는 환경변수로 유지
2. AI on/off, mode, provider, model, minScore, timeout, maxItems는 스캔 설정에 저장
3. `AI_REVIEW_PROVIDER=heuristic|http` 지원
4. AI 실패 시 원본 정규식 결과 자동 유지 (폴백)
5. 리포트에 `aiReview.decision`, `aiReview.score` 표시

### AI Beta 환경변수

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `AI_REVIEW_ENABLED` | `false` | 전역 기본값. 개별 스캔 설정에서 override 가능 |
| `AI_REVIEW_MODE` | `advisory` | 전역 기본값. 개별 스캔 설정에서 override 가능 |
| `AI_REVIEW_PROVIDER` | `heuristic` | 전역 기본값. 개별 스캔 설정에서 override 가능 |
| `AI_REVIEW_MODEL` | `exaone-4.5-1.2b` | 전역 기본값. 개별 스캔 설정에서 override 가능 |
| `AI_REVIEW_ENDPOINT` | (없음) | `http` provider 호출 URL |
| `AI_REVIEW_TIMEOUT_MS` | `3000` | 전역 기본 타임아웃(ms). 개별 스캔 설정에서 override 가능 |
| `AI_REVIEW_MIN_SCORE` | `0.45` | 전역 기본 keep/drop 임계값 |
| `AI_REVIEW_MAX_ITEMS` | `300` | 전역 기본 스캔당 AI 평가 상한 |

## 상용화/소스 제공 전략

로컬 배포형 제품도 유료 판매가 가능하며, 소스 제공 여부는 계약 모델로 분리합니다.

### 권장 모델

1. 오픈코어: 코어 스캐너 공개 + 운영/정책/자동화는 상용 모듈
2. 소스 포함 상용: 고객사에 소스 제공 + 재배포 금지/용도 제한 계약
3. 듀얼 라이선스: 커뮤니티 라이선스 + 상용 라이선스 병행

### 초기 실행 방안

1. 데모/파일럿 단계: 커뮤니티 버전 + 공용 쉐어 패키지 모델
2. 유료 전환 단계: 전용 모델 관리 레이어(캐시, 버전 pinning, checksum)
3. 엔터프라이즈 단계: 에어갭 설치 번들 + SLA + 유지보수 계약

## Docker 실행 모드

### 공용 배포 기본 모드

```bash
docker compose -f docker-compose.yml up --build web
```

### 로컬 shared_ai_net 연동 모드

```bash
docker compose -f docker-compose.yml -f docker-compose.shared-ai-net.yml up --build web
```

## Phase 2 계획

- NoSQL 스캐너 (MongoDB, Redis)
- 언어별 취약점 탐지 (OWASP 패턴)
- 스캔 결과 영속화 (파일 저장)
- 알림 연동 (Slack / 이메일)
