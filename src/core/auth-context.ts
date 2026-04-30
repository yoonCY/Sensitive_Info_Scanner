import type { Request } from "express";

export interface AuthContext {
  tenantId: string;
  userId?: string;
  username?: string;
  email?: string;
  displayName?: string;
  roles: string[];
  isAuthenticated: boolean;
  authMode: "none" | "proxy";
}

const DEFAULT_TENANT_ID = (process.env.DEFAULT_TENANT_ID ?? "default").trim() || "default";
const DEFAULT_USER_ID = (process.env.DEFAULT_USER_ID ?? "local-admin").trim() || "local-admin";
const DEFAULT_USERNAME = (process.env.DEFAULT_USERNAME ?? "local-admin").trim() || "local-admin";
const AUTH_MODE = (process.env.AUTH_MODE ?? "none").trim().toLowerCase() === "proxy" ? "proxy" : "none";
const REQUIRE_AUTH = /^(1|true|yes)$/i.test(process.env.REQUIRE_AUTH ?? "");
const PROXY_AUTH_SECRET = (process.env.PROXY_AUTH_SHARED_SECRET ?? "").trim();
const TENANT_HEADER = (process.env.PROXY_TENANT_HEADER ?? "x-auth-request-tenant").toLowerCase();
const USER_HEADER = (process.env.PROXY_USER_HEADER ?? "x-auth-request-user").toLowerCase();
const EMAIL_HEADER = (process.env.PROXY_EMAIL_HEADER ?? "x-auth-request-email").toLowerCase();
const NAME_HEADER = (process.env.PROXY_NAME_HEADER ?? "x-auth-request-name").toLowerCase();
const ROLES_HEADER = (process.env.PROXY_ROLES_HEADER ?? "x-auth-request-groups").toLowerCase();
const SHARED_SECRET_HEADER = (process.env.PROXY_SHARED_SECRET_HEADER ?? "x-auth-proxy-secret").toLowerCase();

function normalizeTenantId(input?: string | null): string {
  const value = input?.trim();
  return value || DEFAULT_TENANT_ID;
}

function parseRoles(raw?: string | null): string[] {
  if (!raw) return [];
  return raw
    .split(/[;,]/)
    .map((value) => value.trim())
    .filter(Boolean);
}

function getHeader(req: Request, headerName: string): string | undefined {
  const value = req.header(headerName);
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function resolveProxyAuth(req: Request): AuthContext {
  if (PROXY_AUTH_SECRET) {
    const secret = getHeader(req, SHARED_SECRET_HEADER);
    if (secret !== PROXY_AUTH_SECRET) {
      throw new Error("신뢰할 수 없는 프록시 인증 헤더입니다.");
    }
  }

  const tenantIdHeader = getHeader(req, TENANT_HEADER);
  if (REQUIRE_AUTH && !tenantIdHeader) {
    throw new Error("프록시 테넌트 헤더가 필요합니다.");
  }
  const tenantId = normalizeTenantId(tenantIdHeader);
  const username = getHeader(req, USER_HEADER);
  const email = getHeader(req, EMAIL_HEADER);
  const displayName = getHeader(req, NAME_HEADER) ?? username;
  const roles = parseRoles(getHeader(req, ROLES_HEADER));

  if (REQUIRE_AUTH && !username) {
    throw new Error("프록시 인증 사용자 헤더가 필요합니다.");
  }

  return {
    tenantId,
    userId: username ? `${tenantId}:${username}` : undefined,
    username: username ?? undefined,
    email,
    displayName,
    roles,
    isAuthenticated: Boolean(username),
    authMode: "proxy",
  };
}

function resolveLocalAuth(req: Request): AuthContext {
  const headerTenantId = getHeader(req, "x-tenant-id");
  const queryTenantId = typeof req.query.tenantId === "string" ? req.query.tenantId : undefined;
  const bodyTenantId = req.body && typeof req.body.tenantId === "string" ? req.body.tenantId : undefined;
  const username = getHeader(req, "x-user-id") ?? DEFAULT_USERNAME;
  const tenantId = normalizeTenantId(headerTenantId ?? queryTenantId ?? bodyTenantId);

  if (REQUIRE_AUTH && !username) {
    throw new Error("인증된 사용자 정보가 필요합니다.");
  }

  return {
    tenantId,
    userId: username ? `${tenantId}:${username}` : DEFAULT_USER_ID,
    username,
    displayName: username,
    roles: ["admin"],
    isAuthenticated: Boolean(username),
    authMode: "none",
  };
}

export function resolveAuthContext(req: Request): AuthContext {
  return AUTH_MODE === "proxy" ? resolveProxyAuth(req) : resolveLocalAuth(req);
}

export function getAuthRuntimeFlags(): { authMode: "none" | "proxy"; requireAuth: boolean } {
  return { authMode: AUTH_MODE, requireAuth: REQUIRE_AUTH };
}