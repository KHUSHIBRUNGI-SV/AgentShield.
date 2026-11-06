import { afterEach, describe, expect, it, vi } from "vitest";
import { apiRequest } from "./api";

describe("API request failure handling", () => {
  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it("aborts a stalled request and reports a finite timeout error", async () => {
    vi.useFakeTimers();
    let requestSignal: AbortSignal | undefined;
    vi.stubGlobal(
      "fetch",
      vi.fn((_input: RequestInfo | URL, init?: RequestInit) => new Promise<Response>((_resolve, reject) => {
        requestSignal = init?.signal ?? undefined;
        requestSignal?.addEventListener("abort", () => {
          reject(new DOMException("Aborted", "AbortError"));
        });
      })),
    );

    const request = apiRequest("/auth/login", { method: "POST" });
    const rejection = expect(request).rejects.toThrow("request timed out");
    await vi.advanceTimersByTimeAsync(12_000);

    await rejection;
    expect(requestSignal?.aborted).toBe(true);
  });

  it("preserves the backend database-unavailable message and HTTP status", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => ({
        ok: false,
        status: 503,
        text: async () => JSON.stringify({
          detail: "Authentication database is unavailable. Check GET /health.",
        }),
      })),
    );

    await expect(apiRequest("/auth/login", { method: "POST" }))
      .rejects.toMatchObject({
        message: "Authentication database is unavailable. Check GET /health.",
        status: 503,
      });
  });

  it("distinguishes an unreachable backend from database storage errors", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => {
      throw new TypeError("fetch failed");
    }));

    await expect(apiRequest("/auth/login", { method: "POST" }))
      .rejects.toThrow("Cannot reach the AgentShield API");
  });

  it("reports likely CORS or preflight configuration when health is reachable", async () => {
    vi.stubGlobal("fetch", vi.fn()
      .mockRejectedValueOnce(new TypeError("blocked by browser"))
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ status: "ok" }),
      }));

    await expect(apiRequest("/auth/login", { method: "POST" }))
      .rejects.toThrow("is reachable, but the request was blocked");
  });

  it("reports a health-check service failure separately from a network failure", async () => {
    vi.stubGlobal("fetch", vi.fn()
      .mockRejectedValueOnce(new TypeError("network error"))
      .mockResolvedValueOnce({
        ok: false,
        status: 503,
        json: async () => ({ detail: "Redis rate-limiting service is unavailable." }),
      }));

    await expect(apiRequest("/auth/login", { method: "POST" }))
      .rejects.toThrow("health check failed (503): Redis rate-limiting service is unavailable.");
  });

  it("preserves invalid-credential responses without probing the backend", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => ({
      ok: false,
      status: 401,
      text: async () => JSON.stringify({ detail: "Invalid username or password" }),
    })));

    await expect(apiRequest("/auth/login", { method: "POST" }))
      .rejects.toMatchObject({
        message: "Invalid username or password",
        status: 401,
      });
    expect(fetch).toHaveBeenCalledTimes(1);
  });
});
