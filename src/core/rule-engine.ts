import type { SensitivityRule, SensitivityCategory, ScanFinding } from "../types.js";

// ─────────────────────────────────────────────────────────────────────────────
//  민감정보 룰 정의
//
//  columnPattern  : DB 컬럼명에 매칭 (case-insensitive)
//  codePattern    : 소스 코드 한 줄에 매칭 (값 할당/전달 패턴)
//  dataPattern    : DB 샘플 데이터 값에 매칭
// ─────────────────────────────────────────────────────────────────────────────

export const BUILTIN_RULES: SensitivityRule[] = [
  // ── PII: 이름 ──────────────────────────────────────────────────────────────
  {
    id: "pii-name",
    name: "개인 이름",
    category: "pii",
    severity: "medium",
    description: "성명, 이름 관련 필드",
    columnPattern: /\b(full_?name|first_?name|last_?name|given_?name|family_?name|display_?name|real_?name|user_?name|nickname|성명|이름|성함)\b/i,
  },
  // ── PII: 이메일 ─────────────────────────────────────────────────────────────
  {
    id: "pii-email",
    name: "이메일 주소",
    category: "pii",
    severity: "high",
    description: "이메일 주소 필드",
    columnPattern: /\b(e_?mail|email_?address|mail|contact_?email)\b/i,
    dataPattern: /^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$/,
  },
  // ── PII: 전화번호 ────────────────────────────────────────────────────────────
  {
    id: "pii-phone",
    name: "전화번호",
    category: "pii",
    severity: "high",
    description: "전화번호, 휴대폰 번호 필드",
    columnPattern: /\b(phone|phone_?number|mobile|cell|telephone|tel|contact_?no|연락처|전화|휴대폰)\b/i,
    dataPattern: /^(\+?\d[\d\s\-().]{6,}\d)$/,
  },
  // ── PII: 주소 ───────────────────────────────────────────────────────────────
  {
    id: "pii-address",
    name: "주소",
    category: "pii",
    severity: "medium",
    description: "실거주 주소 관련 필드",
    columnPattern: /\b(address|street|city|state|province|zip|postal_?code|주소|도로명|우편번호)\b/i,
  },
  // ── PII: 주민등록번호 / 국가ID ──────────────────────────────────────────────
  {
    id: "pii-national-id",
    name: "주민등록번호 / 국가 식별번호",
    category: "pii",
    severity: "critical",
    description: "주민번호, 여권번호, 국가ID 필드",
    columnPattern: /\b(ssn|social_?security|national_?id|passport_?(no|number)?|resident_?(no|number|reg)?|rrn|id_?number|주민|여권번호)\b/i,
    dataPattern: /^\d{6}[-\s]?\d{7}$/,  // 주민등록번호 형식
  },
  // ── PII: 생년월일 ────────────────────────────────────────────────────────────
  {
    id: "pii-dob",
    name: "생년월일",
    category: "pii",
    severity: "high",
    description: "생년월일 필드",
    columnPattern: /\b(birth_?(date|day|year)?|dob|date_?of_?birth|birthdate|birthday|생년월일|생일)\b/i,
  },
  // ── PII: IP 주소 ─────────────────────────────────────────────────────────────
  {
    id: "pii-ip",
    name: "IP 주소",
    category: "pii",
    severity: "medium",
    description: "클라이언트 IP 주소 필드",
    columnPattern: /\b(ip_?address|remote_?ip|client_?ip|user_?ip|ip)\b/i,
    dataPattern: /^(\d{1,3}\.){3}\d{1,3}$|^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/,
  },
  // ── PII: 위치정보 ────────────────────────────────────────────────────────────
  {
    id: "pii-location",
    name: "위치 좌표",
    category: "pii",
    severity: "medium",
    description: "GPS 좌표, 위도/경도 필드",
    columnPattern: /\b(latitude|longitude|lat|lng|lon|gps|coordinates|위도|경도|좌표)\b/i,
  },

  // ── Financial: 카드번호 ──────────────────────────────────────────────────────
  {
    id: "financial-card-number",
    name: "신용카드 번호",
    category: "financial",
    severity: "critical",
    description: "신용/체크카드 번호",
    columnPattern: /\b(credit_?card|card_?number|ccn|pan|debit_?card|card_?no)\b/i,
    dataPattern: /^\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}$/,
  },
  // ── Financial: CVV ────────────────────────────────────────────────────────────
  {
    id: "financial-cvv",
    name: "카드 보안코드 (CVV/CVC)",
    category: "financial",
    severity: "critical",
    description: "카드 CVV/CVC 코드",
    columnPattern: /\b(cvv|cvc|cvn|security_?code|card_?code)\b/i,
  },
  // ── Financial: 계좌번호 ──────────────────────────────────────────────────────
  {
    id: "financial-bank-account",
    name: "은행 계좌번호",
    category: "financial",
    severity: "critical",
    description: "은행 계좌번호, 라우팅 번호",
    columnPattern: /\b(bank_?account|account_?number|routing_?number|iban|swift|bic|계좌번호|계좌)\b/i,
  },
  // ── Financial: 급여/소득 ──────────────────────────────────────────────────────
  {
    id: "financial-salary",
    name: "급여 / 소득",
    category: "financial",
    severity: "high",
    description: "급여, 소득, 임금 관련 필드",
    columnPattern: /\b(salary|wage|income|earning|compensation|pay|급여|소득|임금)\b/i,
  },

  // ── Credentials: 비밀번호 ─────────────────────────────────────────────────────
  {
    id: "creds-password",
    name: "비밀번호 / 해시",
    category: "credentials",
    severity: "critical",
    description: "비밀번호, 패스워드 해시 저장 필드",
    columnPattern: /\b(password|passwd|pwd|pass|passphrase|pw|비밀번호|암호)\b/i,
    codePattern: /\b(password|passwd|pwd)\s*[:=]\s*["']?(?!\s*process\.env)[^"'\s]{6,}["']?/i,
  },
  // ── Credentials: API 키 / 토큰 ────────────────────────────────────────────────
  {
    id: "creds-api-key",
    name: "API 키 / 토큰",
    category: "credentials",
    severity: "critical",
    description: "API 키, 액세스 토큰, 시크릿 키",
    columnPattern: /\b(api_?key|access_?key|secret_?key|auth_?token|session_?token|bearer|private_?key|client_?secret)\b/i,
    codePattern: /\b(api_?key|token|secret|access_?key)\s*[:=]\s*["'][A-Za-z0-9_\-./+]{10,}["']/i,
    dataPattern: /^(ghp_|gho_|ghu_|ghs_|ghr_)[A-Za-z0-9]{36}$|^sk-[A-Za-z0-9]{32,}$/,
  },
  // ── Credentials: JWT ─────────────────────────────────────────────────────────
  {
    id: "creds-jwt",
    name: "JWT 토큰",
    category: "credentials",
    severity: "high",
    description: "JWT 형식의 토큰 값",
    dataPattern: /^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/,
    codePattern: /\b(jwt|token|bearer)\s*[:=]\s*["']eyJ[A-Za-z0-9_\-.]+["']/i,
  },
  // ── Credentials: Private Key ──────────────────────────────────────────────────
  {
    id: "creds-private-key",
    name: "개인 키 (PEM)",
    category: "credentials",
    severity: "critical",
    description: "PEM 형식의 개인 키",
    codePattern: /-----BEGIN\s+(RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE KEY-----/,
  },
  // ── Credentials: 환경변수 하드코딩 ────────────────────────────────────────────
  {
    id: "creds-hardcoded-env",
    name: "하드코딩된 시크릿",
    category: "credentials",
    severity: "critical",
    description: "환경변수 없이 코드에 직접 삽입된 시크릿 값",
    codePattern: /\b[A-Z][A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASS|PWD)\s*=\s*["'][^"']{8,}["']/,
  },

  // ── Health: 진단 / 의료정보 ───────────────────────────────────────────────────
  {
    id: "health-diagnosis",
    name: "진단 / 의료 정보",
    category: "health",
    severity: "critical",
    description: "질병, 진단, 처방 관련 필드",
    columnPattern: /\b(diagnosis|medical|health|prescription|drug|medication|disease|condition|allergy|진단|처방|질병|건강)\b/i,
  },
  // ── Health: 신체 정보 ─────────────────────────────────────────────────────────
  {
    id: "health-physical",
    name: "신체 측정 정보",
    category: "health",
    severity: "medium",
    description: "혈액형, BMI, 체중, 키 등",
    columnPattern: /\b(blood_?type|bmi|weight|height|키|체중|혈액형)\b/i,
  },

  // ── OAuth / Auth 토큰 ───────────────────────────────────────────────────────
  {
    id: "oauth-access-token",
    name: "OAuth 액세스 토큰",
    category: "oauth",
    severity: "critical",
    description: "OAuth 플랫폼 액세스 토큰",
    columnPattern: /\b(oauth_?token|access_?token|oauth_?access|bearer_?token)\b/i,
    codePattern: /\b(oauth_?token|access_?token)\s*[:=]\s*["'][A-Za-z0-9_\-\.]{20,}["']/i,
  },
  {
    id: "oauth-refresh-token",
    name: "OAuth 리프레시 토큰",
    category: "oauth",
    severity: "critical",
    description: "OAuth 리프레시 토큰",
    columnPattern: /\b(refresh_?token|oauth_?refresh)\b/i,
    codePattern: /\b(refresh_?token)\s*[:=]\s*["'][A-Za-z0-9_\-\.]{20,}["']/i,
  },
  {
    id: "oauth-client-id-secret",
    name: "OAuth 클라이언트 ID/시크릿",
    category: "oauth",
    severity: "critical",
    description: "OAuth 클라이언트 ID, 시크릿키",
    columnPattern: /\b(client_?id|client_?secret|oauth_?id|app_?secret)\b/i,
  },

  // ── Device ID ────────────────────────────────────────────────────────────────
  {
    id: "device-mac-address",
    name: "MAC 주소",
    category: "device",
    severity: "high",
    description: "기기 MAC 주소",
    columnPattern: /\b(mac|mac_?address|hardware_?address|mac_?addr|device_?id|mac_?id)\b/i,
    dataPattern: /^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/,
  },
  {
    id: "device-imei",
    name: "IMEI 번호",
    category: "device",
    severity: "high",
    description: "휴대폰 IMEI 번호",
    columnPattern: /\b(imei|international_?mobile_?equipment|device_?imei|mobile_?id)\b/i,
    dataPattern: /^\d{15}$/,
  },
  {
    id: "device-udid",
    name: "UDID / Device UUID",
    category: "device",
    severity: "high",
    description: "iOS UDID, 기기 고유 식별자",
    columnPattern: /\b(udid|unique_?device_?identifier|device_?uuid|uuid|ios_?id)\b/i,
    dataPattern: /^[0-9a-f]{40}$|^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
  },
  {
    id: "device-android-id",
    name: "Android 기기 ID",
    category: "device",
    severity: "high",
    description: "Android 기기 식별 번호",
    columnPattern: /\b(android_?id|android_?device|device_?serial|serial_?number)\b/i,
  },

  // ── Biometric ────────────────────────────────────────────────────────────────
  {
    id: "biometric-fingerprint",
    name: "지문 데이터",
    category: "biometric",
    severity: "critical",
    description: "지문 생체 데이터",
    columnPattern: /\b(fingerprint|finger_?print|biometric_?data|fingerprint_?data|fpr_?data)\b/i,
  },
  {
    id: "biometric-iris",
    name: "홍채 데이터",
    category: "biometric",
    severity: "critical",
    description: "홍채 생체 정보",
    columnPattern: /\b(iris|iris_?scan|iris_?data|eye_?scan|ocular_?data)\b/i,
  },
  {
    id: "biometric-face",
    name: "얼굴 인식 데이터",
    category: "biometric",
    severity: "critical",
    description: "얼굴 생체 데이터, 안면 인식",
    columnPattern: /\b(face_?data|facial_?data|face_?recognition|face_?print|face_?id|facial_?recognition)\b/i,
  },
  {
    id: "biometric-voice",
    name: "음성 바이오메트릭",
    category: "biometric",
    severity: "high",
    description: "음성 인식, 성문인식 데이터",
    columnPattern: /\b(voice|voice_?data|voice_?print|speaker_?id|voice_?recognition)\b/i,
  },

  // ── Certificate / Key ────────────────────────────────────────────────────────
  {
    id: "certificate-ssl-cert",
    name: "SSL 인증서",
    category: "certificate",
    severity: "high",
    description: "SSL/TLS 인증서",
    columnPattern: /\b(ssl_?cert|certificate|cert|x509|tls_?cert)\b/i,
    codePattern: /-----BEGIN\s+CERTIFICATE-----/,
  },
  {
    id: "certificate-ca-key",
    name: "CA 개인 키",
    category: "certificate",
    severity: "critical",
    description: "CA 인증기관 개인키",
    columnPattern: /\b(ca_?key|certificate_?authority|ca_?private|root_?key)\b/i,
    codePattern: /-----BEGIN\s+(RSA|EC|DSA)\s+PRIVATE KEY-----.*-----END\s+(RSA|EC|DSA)\s+PRIVATE KEY-----/s,
  },
  {
    id: "certificate-pfx-p12",
    name: "PFX/P12 인증서 패키지",
    category: "certificate",
    severity: "critical",
    description: "PKCS#12 형식의 인증서 번들",
    columnPattern: /\b(pfx|p12|pkcs12|certificate_?bundle)\b/i,
  },
];

// ─────────────────────────────────────────────────────────────────────────────

export class RuleEngine {
  private rules: SensitivityRule[];

  constructor(
    extraRules: SensitivityRule[] = [],
    enabledCategories?: Array<SensitivityCategory>
  ) {
    let base = [...BUILTIN_RULES, ...extraRules];
    if (enabledCategories && enabledCategories.length > 0) {
      base = base.filter((r) => enabledCategories.includes(r.category));
    }
    this.rules = base;
  }

  getRules(): SensitivityRule[] {
    return this.rules;
  }

  matchColumnName(columnName: string): SensitivityRule[] {
    return this.rules.filter(
      (r) => r.columnPattern && r.columnPattern.test(columnName)
    );
  }

  matchCodeLine(line: string): SensitivityRule[] {
    return this.rules.filter(
      (r) => r.codePattern && r.codePattern.test(line)
    );
  }

  matchDataValue(value: string): SensitivityRule[] {
    return this.rules.filter(
      (r) => r.dataPattern && r.dataPattern.test(value.trim())
    );
  }

  redactValue(value: string): string {
    if (value.length <= 4) return "****";
    return value.slice(0, 2) + "*".repeat(Math.min(value.length - 4, 6)) + value.slice(-2);
  }

  redactCodeLine(line: string): string {
    let result = line;
    for (const rule of this.rules) {
      if (!rule.codePattern) continue;
      result = result.replace(rule.codePattern, (match) => {
        const eqIdx = match.search(/[:=]/);
        if (eqIdx === -1) return match.slice(0, 4) + "...[REDACTED]";
        return match.slice(0, eqIdx + 1) + " [REDACTED]";
      });
    }
    return result.trim();
  }
}
