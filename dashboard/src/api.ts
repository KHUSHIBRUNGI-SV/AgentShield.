export class ApiError extends Error {
  constructor(message: string, readonly status?: number) {
    super(message);
    this.name = "ApiError";
  }
}

const configuredApiUrl = import.meta.env.VITE_API_URL || import.meta.env.VITE_API_BASE;

export const API_BASE = (configuredApiUrl || "http://127.0.0.1:8000")
  .trim()
  .replace(/\/+$/, "");

const REQUEST_TIMEOUT_MS = 12_000;
const HEALTH_PROBE_TIMEOUT_MS = 3_000;

async function diagnoseNetworkFailure(): Promise<string> {
  const controller = new AbortController();
  const timeout = window.setTimeout(
    () => controller.abort(),
    HEALTH_PROBE_TIMEOUT_MS,
  );
  try {
    const response = await fetch(`${API_BASE}/health`, {
      method: "GET",
      headers: { Accept: "application/json" },
      credentials: "omit",
      signal: controller.signal,
    });
    if (response.ok) {
      return `The AgentShield API at ${API_BASE} is reachable, but the request was blocked. Check that the dashboard origin is allowed in AGENTSHIELD_CORS_ORIGINS and that preflight OPTIONS requests reach the API.`;
    }

    let detail = "";
    try {
      const body: unknown = await response.json();
      if (
        typeof body === "object" &&
        body !== null &&
        "detail" in body &&
        typeof body.detail === "string"
      ) {
        detail = body.detail;
      }
    } catch {
      detail = "";
    }
    if (detail) {
      return `The AgentShield API responded, but its health check failed (${response.status}): ${detail}`;
    }
    return `The AgentShield API responded to its health check with HTTP ${response.status}. Check backend configuration and service logs.`;
  } catch {
    return `Cannot reach the AgentShield API at ${API_BASE}. Check that the backend is running and that the browser can access it; a CORS or network configuration issue may also block the request.`;
  } finally {
    window.clearTimeout(timeout);
  }
}

export async function apiRequest<T>(
  path: string,
  init: RequestInit = {},
  token?: string,
): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set("Accept", "application/json");
  if (init.body) headers.set("Content-Type", "application/json");
  if (token) headers.set("Authorization", `Bearer ${token}`);

  const controller = new AbortController();
  const timeout = window.setTimeout(
    () => controller.abort(),
    REQUEST_TIMEOUT_MS,
  );

  try {
    const response = await fetch(`${API_BASE}${path}`, {
      ...init,
      headers,
      signal: controller.signal,
      credentials: "omit",
    });
    const responseText = await response.text();
    let body: unknown;
    try {
      body = responseText ? JSON.parse(responseText) : {};
    } catch {
      body = {};
    }

    if (!response.ok) {
      const detail =
        typeof body === "object" &&
        body !== null &&
        "detail" in body &&
        typeof body.detail === "string"
          ? body.detail
          : `AgentShield API request failed (${response.status})`;
      if (response.status >= 500) {
        throw new ApiError(
          response.status === 503
            ? detail
            : "The AgentShield API encountered a server error. Check backend logs and database/service configuration.",
          response.status,
        );
      }
      throw new ApiError(detail, response.status);
    }

    return body as T;
  } catch (error) {
    if (error instanceof ApiError) throw error;
    if (
      typeof error === "object" &&
      error !== null &&
      "name" in error &&
      error.name === "AbortError"
    ) {
      throw new ApiError(
        "The request timed out. Check that the AgentShield API and its services are available.",
      );
    }
    if (error instanceof TypeError) {
      throw new ApiError(await diagnoseNetworkFailure());
    }
    throw new ApiError("The AgentShield request failed unexpectedly.");
  } finally {
    window.clearTimeout(timeout);
  }
}
