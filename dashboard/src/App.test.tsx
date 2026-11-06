import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import App from "./App";

vi.mock("./ShieldScene", () => ({
  default: ({ mode }: { mode: string }) => (
    <div data-testid="shield-scene">{mode}</div>
  ),
}));

function jsonResponse(body: unknown, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    text: async () => JSON.stringify(body),
  };
}
const defaultPreferences = {
  animations_enabled: true,
  refresh_seconds: 15,
  auto_refresh: true,
  compact_mode: false,
  notifications_enabled: true,
  critical_notifications_only: false,
  desktop_notifications: false,
};

describe("AgentShield reviewer sign-in", () => {
  beforeEach(() => {
    sessionStorage.clear();
    localStorage.clear();
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it("authenticates through the API and validates the reviewer session", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const path = new URL(String(input)).pathname;
      if (path === "/auth/login") {
        return jsonResponse({
          access_token: "unit-test-jwt",
          username: "reviewer",
          role: "security_admin",
        });
      }
      if (path === "/auth/me") {
        return jsonResponse({ username: "reviewer", role: "security_admin" });
      }
      if (path === "/approvals") return jsonResponse({ pending_approvals: [] });
      if (path === "/approvals/history") return jsonResponse({ approval_history: [] });
      if (path === "/audit-logs") return jsonResponse({ audit_logs: [] });
      if (path === "/security/summary") {
        return jsonResponse({ decisions: {}, recent_anomalies: [] });
      }
      if (path === "/agents") return jsonResponse({ agents: [] });
      if (path === "/security/policies") {
        return jsonResponse({
          default_decision: "BLOCK",
          required_subject_roles: ["agent"],
          version: 1,
          rules: [],
        });
      }
      if (path === "/settings/preferences") return jsonResponse(defaultPreferences);
      throw new Error(`Unexpected API request: ${path}`);
    });
    vi.stubGlobal("fetch", fetchMock);
    render(<App />);

    fireEvent.change(screen.getByLabelText("Account ID"), {
      target: { value: "reviewer" },
    });
    fireEvent.change(screen.getByLabelText("Password"), {
      target: { value: "correct-test-password" },
    });
    fireEvent.click(screen.getByRole("button", { name: /Authenticate/ }));

    expect(await screen.findByRole("heading", { name: /Your agents/ })).toBeTruthy();
    await waitFor(() => {
      expect(sessionStorage.getItem("agentshield-token")).toBe("unit-test-jwt");
    });
    expect(fetchMock).toHaveBeenCalledWith(
      expect.stringMatching(/\/auth\/login$/),
      expect.objectContaining({
        method: "POST",
        credentials: "omit",
        body: JSON.stringify({
          username: "reviewer",
          password: "correct-test-password",
        }),
      }),
    );
    expect(screen.getByText(/Secure session established/)).toBeTruthy();
    expect(screen.getByTestId("risk-telemetry").textContent).toContain("Awaiting telemetry");
    expect(screen.getByTestId("latency-telemetry").textContent).toContain("Awaiting telemetry");
    expect(screen.getByTestId("security-atmosphere").querySelectorAll(".energy-particle")).toHaveLength(42);
    fireEvent.click(screen.getByRole("button", { name: "Sign out" }));
    await waitFor(() => {
      expect(document.body.dataset.securityTheme).toBe("login");
    });
    expect(screen.getByTestId("security-atmosphere").querySelectorAll(".energy-particle")).toHaveLength(8);
  }, 15000);

  it("maps live backend decisions and risk signals to the security theme", async () => {
    let decision = "BLOCK";
    let riskScore: number | null = 0.92;
    let pendingApproval = false;
    const auditEvent = () => ({
      id: 21,
      timestamp: "2026-01-01T10:00:00Z",
      agent: "theme-test-agent",
      user: "theme-test-agent",
      tool: "records.lookup",
      action: "read",
      resource: "records",
      environment: "development",
      records: 1,
      decision,
      reason: `Fixture ${decision} event`,
      approval_id: pendingApproval ? 9 : null,
      risk_score: riskScore,
      anomaly_detected: riskScore !== null && riskScore >= 0.75,
    });
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const path = new URL(String(input)).pathname;
      if (path === "/auth/login") return jsonResponse({
        access_token: "unit-test-jwt",
        username: "reviewer",
        role: "security_admin",
      });
      if (path === "/auth/me") return jsonResponse({ username: "reviewer", role: "security_admin" });
      if (path === "/approvals") {
        return jsonResponse({
          pending_approvals: pendingApproval ? [{
            id: 9, agent: "theme-test-agent", tool: "records.lookup", action: "read",
            resource: "records", environment: "development", records: 1,
            status: "PENDING", reason: "Reviewer required",
          }] : [],
        });
      }
      if (path === "/approvals/history") return jsonResponse({ approval_history: [] });
      if (path === "/audit-logs") return jsonResponse({ audit_logs: [auditEvent()] });
      if (path === "/security/summary") {
        const event = auditEvent();
        return jsonResponse({
          decisions: { [decision]: 1 },
          recent_anomalies: riskScore === null ? [] : [{
            id: event.id,
            timestamp: event.timestamp,
            agent: event.agent,
            action: event.action,
            risk_score: riskScore,
            decision,
          }],
        });
      }
      if (path === "/agents") return jsonResponse({ agents: [] });
      if (path === "/security/policies") {
        return jsonResponse({
          default_decision: "BLOCK",
          required_subject_roles: ["agent"],
          version: 1,
          rules: [],
        });
      }
      if (path === "/settings/preferences") return jsonResponse(defaultPreferences);
      throw new Error(`Unexpected API request: ${path}`);
    });
    vi.stubGlobal("fetch", fetchMock);
    render(<App />);
    fireEvent.change(screen.getByLabelText("Account ID"), { target: { value: "reviewer" } });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "test-password" } });
    fireEvent.click(screen.getByRole("button", { name: /Authenticate/ }));
    expect(await screen.findByRole("heading", { name: /Your agents/ })).toBeTruthy();
    await waitFor(() => expect(document.body.dataset.securityTheme).toBe("blocked"));
    expect(screen.getByTestId("security-state-banner").textContent).toContain("ACTION BLOCKED");
    expect(screen.getByTestId("shield-scene").textContent).toBe("blocked");

    const refresh = () => fireEvent.click(screen.getByRole("button", { name: "Refresh dashboard" }));
    decision = "HUMAN_APPROVAL";
    pendingApproval = true;
    riskScore = 0.25;
    refresh();
    await waitFor(() => expect(document.body.dataset.securityTheme).toBe("approval"));
    expect(screen.getByTestId("security-state-banner").textContent).toContain("HUMAN APPROVAL REQUIRED");
    expect(screen.getByTestId("shield-scene").textContent).toBe("approval");

    decision = "SANDBOX";
    pendingApproval = false;
    refresh();
    await waitFor(() => expect(document.body.dataset.securityTheme).toBe("sandbox"));
    expect(screen.getByTestId("security-state-banner").textContent).toContain("SANDBOX CONTAINMENT");
    expect(screen.getByTestId("shield-scene").textContent).toBe("sandbox");

    decision = "ALLOW";
    riskScore = 0.88;
    refresh();
    await waitFor(() => expect(document.body.dataset.securityTheme).toBe("high-risk"));
    expect(screen.getByTestId("security-state-banner").textContent).toContain("HIGH RISK");
    expect(screen.getByTestId("shield-scene").textContent).toBe("high-risk");

    riskScore = 0.1;
    refresh();
    await waitFor(() => expect(document.body.dataset.securityTheme).toBe("secure"));
    expect(screen.queryByTestId("security-state-banner")).toBeNull();
    expect(screen.getByTestId("shield-scene").textContent).toBe("secure");
  });

  it("allows skipping the one-time awakening and does not replay it in the session", async () => {
    const { unmount } = render(<App />);
    const skip = await screen.findByRole("button", { name: /Skip boot sequence/ });
    fireEvent.click(skip);
    await waitFor(() => {
      expect(screen.queryByRole("button", { name: /Skip boot sequence/ })).toBeNull();
    });

    unmount();
    render(<App />);
    expect(screen.queryByRole("button", { name: /Skip boot sequence/ })).toBeNull();
  });

  it("shows a backend authentication error and exits the connecting state", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => jsonResponse({
        detail: "Authentication database is unavailable. Verify DATABASE_URL and check GET /health.",
      }, 503)),
    );
    render(<App />);

    fireEvent.change(screen.getByLabelText("Account ID"), {
      target: { value: "reviewer" },
    });
    fireEvent.change(screen.getByLabelText("Password"), {
      target: { value: "correct-test-password" },
    });
    fireEvent.click(screen.getByRole("button", { name: /Authenticate/ }));

    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("Authentication database is unavailable");
    expect(
      (screen.getByRole("button", { name: /Authenticate/ }) as HTMLButtonElement)
        .disabled,
    ).toBe(false);
    expect(sessionStorage.getItem("agentshield-token")).toBeNull();
  });

  it("renders reviewer pages and sends a reason with an approval rejection", async () => {
    class FakeWebSocket {
      static latest: FakeWebSocket | null = null;
      onmessage: ((event: MessageEvent) => void) | null = null;
      onopen: ((event: Event) => void) | null = null;
      onclose: ((event: CloseEvent) => void) | null = null;
      onerror: ((event: Event) => void) | null = null;
      readonly protocols: string | string[];

      constructor(readonly url: string, protocols: string | string[]) {
        this.protocols = protocols;
        FakeWebSocket.latest = this;
        queueMicrotask(() => this.onopen?.(new Event("open")));
      }

      close() {}
    }

    const audit = {
      id: 12,
      timestamp: "2026-01-01T10:00:00Z",
      agent: "qa-agent",
      user: "qa-agent",
      tool: "customer.lookup",
      action: "read",
      resource: "customer",
      environment: "development",
      records: 1,
      decision: "BLOCK",
      reason: "Synthetic policy test event",
      approval_id: 4,
      risk_score: 0.81,
      anomaly_detected: true,
    };
    const approval = {
      id: 4,
      agent: "qa-agent",
      user: "qa-agent",
      tool: "customer.lookup",
      action: "read",
      resource: "customer",
      environment: "development",
      records: 1,
      status: "PENDING",
      reason: "Test-only approval fixture",
    };
    const benchmark = {
      summary: {
        scenario_count: 2,
        attack_scenarios: 1,
        legitimate_scenarios: 1,
        attack_requests: 1,
        legitimate_requests: 1,
        attack_success_rate: 0,
        attack_prevention_rate: 1,
        detection_rate: 1,
        false_positive_rate: 0,
        false_negative_rate: 0,
        legitimate_action_acceptance_rate: 1,
        precision: 1,
        recall: 1,
        f1_score: 1,
        average_decision_latency_ms: 2,
        decision_distribution: {
          ALLOW: { count: 1, rate: 0.5 },
          BLOCK: { count: 1, rate: 0.5 },
          SANDBOX: { count: 0, rate: 0 },
          HUMAN_APPROVAL: { count: 0, rate: 0 },
        },
        baseline_comparison: {
          unprotected_agent: {
            attack_requests: 1,
            successful_attack_requests: 1,
            attack_success_rate: 1,
          },
          agentshield_protected: {
            attack_requests: 1,
            successful_attack_requests: 0,
            attack_success_rate: 0,
          },
        },
        category_results: {
          unauthorized_tool_access: {
            scenarios: 1,
            requests: 1,
            successful_attack_requests: 0,
            accepted_legitimate_requests: 0,
          },
          legitimate_action: {
            scenarios: 1,
            requests: 1,
            successful_attack_requests: 0,
            accepted_legitimate_requests: 1,
          },
        },
        expected_scenario_mismatches: 0,
      },
      scenarios: [{
        scenario_id: "TEST-001",
        category: "unauthorized_tool_access",
        is_attack: true,
        agent_identity: "qa-agent",
        tool: "customer.lookup",
        action: "read",
        resource: "customer",
        environment: "production",
        records: 1,
        expected_security_outcome: "BLOCK",
        observed_decisions: ["BLOCK"],
        expected_outcome_met: true,
      }],
      methodology: { executor: "Test fixture; no execution" },
    };
    const requestCalls: Array<{ path: string; init?: RequestInit }> = [];
    let approvalState: typeof approval | null = approval;
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = new URL(String(input)).pathname;
      requestCalls.push({ path, init });
      if (path === "/auth/login") {
        return jsonResponse({
          access_token: "unit-test-jwt",
          username: "reviewer",
          role: "security_admin",
        });
      }
      if (path === "/auth/me") {
        return jsonResponse({ username: "reviewer", role: "security_admin" });
      }
      if (path === "/approvals") {
        return jsonResponse({ pending_approvals: approvalState ? [approvalState] : [] });
      }
      if (path === "/approvals/history") return jsonResponse({ approval_history: [] });
      if (path === "/audit-logs") return jsonResponse({ audit_logs: [audit] });
      if (path === "/audit-logs/integrity") {
        return jsonResponse({
          verified: true,
          records_checked: 1,
          first_invalid_id: null,
          head_hash: "test-hash",
        });
      }
      if (path === "/security/summary") {
        return jsonResponse({
          hours: 24,
          agents: { total: 3, active: 2, inactive: 1 },
          total_events: 8,
          decisions: { BLOCK: 1 },
          severities: { CRITICAL: 1, HIGH: 2, MEDIUM: 3, LOW: 2 },
          blocked_actions: 1,
          pending_approvals: 1,
          events_over_time: [{ date: "2026-01-01", count: 8 }],
          recent_anomalies: [{
            id: audit.id,
            timestamp: audit.timestamp,
            agent: audit.agent,
            action: audit.action,
            risk_score: audit.risk_score,
            decision: audit.decision,
          }],
        });
      }
      if (path === "/agents" && init?.method === "POST") {
        return jsonResponse({
          name: "registered-from-dashboard",
          description: "Dashboard regression identity",
          active: true,
        }, 201);
      }
      if (path === "/agents") {
        return jsonResponse({
          agents: [{
            name: "qa-agent",
            description: "Test-only fixture identity",
            active: true,
            last_seen: audit.timestamp,
            last_decision: "BLOCK",
            usage: { total_actions: 1, blocked_actions: 1, anomalies: 1 },
            permissions: [],
          }],
        });
      }
      if (path === "/security/policies") {
        if (init?.method === "POST") {
          const submitted = JSON.parse(String(init.body)) as {
            expected_version: number;
            default_decision: string;
            required_subject_roles: string[];
            rules: unknown[];
          };
          return jsonResponse({
            version: submitted.expected_version + 1,
            default_decision: submitted.default_decision,
            required_subject_roles: submitted.required_subject_roles,
            rules: submitted.rules,
          });
        }
        return jsonResponse({
          version: 1,
          default_decision: "BLOCK",
          required_subject_roles: ["agent"],
          rules: [{
            id: "qa-rule",
            match: {
              agent: "qa-agent",
              tool: "customer.lookup",
              action: "read",
              resource: "customer",
              environment: ["development"],
              max_records: 10,
            },
            decision: "HUMAN_APPROVAL",
            reason: "Test-only fixture rule",
            rate_limit: 10,
          }],
        });
      }
      if (path === "/agents/qa-agent/status") {
        return jsonResponse({ name: "qa-agent", active: false, status: "suspended" });
      }
      if (path === "/settings/preferences") {
        if (init?.method === "PUT") {
          return jsonResponse(JSON.parse(String(init.body)));
        }
        return jsonResponse(defaultPreferences);
      }
      if (path === "/security/policies/history") return jsonResponse({ versions: [] });
      if (path === "/security/policies/dry-run") {
        return jsonResponse({ decision: "BLOCK", reason: "test policy", dry_run: true, executed: false });
      }
      if (path === "/security/anomaly/evaluation") return jsonResponse({
        available: true,
        evaluation: "deterministic synthetic holdout; advisory signals only",
        training_benign: 20,
        test_attacks: 4,
        test_benign: 5,
        precision: 0.8,
        recall: 0.75,
        f1_score: 0.774,
        false_positive_rate: 0.2,
        mean_detection_latency_ms: 0.15,
        limitations: "Synthetic only",
      });
      if (path === "/security/benchmark/runs") return jsonResponse({ runs: [] });
      if (path.startsWith("/security/benchmark/runs/")) return jsonResponse(benchmark);
      if (path === "/approvals/decision") {
        approvalState = null;
        return jsonResponse({ decision: "REJECTED", reviewer: "reviewer" });
      }
      if (path === "/security/benchmark") return jsonResponse(benchmark);
      throw new Error(`Unexpected API request: ${path}`);
    });
    vi.stubGlobal("fetch", fetchMock);
    vi.stubGlobal("WebSocket", FakeWebSocket);
    render(<App />);

    fireEvent.change(screen.getByLabelText("Account ID"), {
      target: { value: "reviewer" },
    });
    fireEvent.change(screen.getByLabelText("Password"), {
      target: { value: "test-reviewer-password" },
    });
    fireEvent.click(screen.getByRole("button", { name: /Authenticate/ }));
    expect(await screen.findByRole("heading", { name: /Your agents/ })).toBeTruthy();
    expect(screen.getByRole("img", { name: "Persisted security events over time" })).toBeTruthy();
    expect(screen.getByText("Registered agents")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: /Live monitoring/ }));
    expect(await screen.findByText("Live security monitoring")).toBeTruthy();
    expect(screen.getAllByText("qa-agent").length).toBeGreaterThan(0);
    const activeSocket = FakeWebSocket.latest;
    expect(activeSocket).not.toBeNull();
    expect(activeSocket?.url).toMatch(/\/security\/stream$/);
    expect(activeSocket?.protocols).toContain("agentshield.jwt.unit-test-jwt");
    const auditRequestsBeforePush = requestCalls.filter(
      (call) => call.path === "/audit-logs",
    ).length;
    activeSocket?.onmessage?.({
      data: JSON.stringify({ type: "security_event" }),
    } as MessageEvent);
    await waitFor(() => {
      expect(
        requestCalls.filter((call) => call.path === "/audit-logs").length,
      ).toBeGreaterThan(auditRequestsBeforePush);
    });

    fireEvent.click(screen.getByRole("button", { name: /Approval center/ }));
    fireEvent.click(await screen.findByRole("button", { name: "Reject" }));
    const reason = screen.getByLabelText(/Reason for rejection/);
    fireEvent.change(reason, { target: { value: "Test-only reviewer reason" } });
    fireEvent.click(screen.getByRole("button", { name: /Confirm rejection/ }));
    await screen.findByText(/Request rejected by reviewer/);
    const decisionRequest = requestCalls.find((call) => call.path === "/approvals/decision");
    expect(JSON.parse(String(decisionRequest?.init?.body))).toEqual({
      approval_id: 4,
      approved: false,
      rejection_reason: "Test-only reviewer reason",
    });

    fireEvent.click(screen.getByRole("button", { name: /Agent activity/ }));
    expect(await screen.findByText("Test-only fixture identity")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Register agent" }));
    fireEvent.change(screen.getByLabelText("Agent identity"), {
      target: { value: "registered-from-dashboard" },
    });
    fireEvent.change(screen.getByLabelText("Initial agent password"), {
      target: { value: "dashboard-test-password" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Create agent identity" }));
    expect(await screen.findByText(/Agent identity registered/)).toBeTruthy();
    expect(requestCalls.some((call) => call.path === "/agents" && call.init?.method === "POST")).toBe(true);

    fireEvent.click(screen.getByRole("button", { name: /Policy management/ }));
    expect(await screen.findByText("Deterministic by design.")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Dry-run request (no execution)" }));
    expect(await screen.findByText(/"executed": false/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: /Validate and publish new version/ }));
    expect(await screen.findByText(/Policy version 2 saved/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: /Anomaly signals/ }));
    expect(await screen.findByText("Signals, not verdicts.")).toBeTruthy();
    expect(await screen.findByText("Model evaluation available")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: /Attack benchmark/ }));
    fireEvent.click(await screen.findByRole("button", { name: /Run isolated benchmark/ }));
    fireEvent.click(screen.getAllByRole("button", { name: /Run isolated benchmark/ }).at(-1)!);
    expect(await screen.findByText("TEST-001")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: /Audit logs/ }));
    expect(await screen.findByRole("heading", { name: "Audit logs" })).toBeTruthy();
    expect(await screen.findByText("1 audit record verified")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: /Settings/ }));
    expect(await screen.findByText("Account & connection")).toBeTruthy();
    fireEvent.change(screen.getByRole("combobox"), { target: { value: "30" } });
    fireEvent.click(screen.getByRole("switch", { name: "Compact density" }));
    expect(document.querySelector(".app-shell")?.classList.contains("compact-mode")).toBe(true);
    fireEvent.click(screen.getByRole("button", { name: "Save changes" }));
    await waitFor(() => {
      expect(requestCalls.some((call) => call.path === "/settings/preferences" && call.init?.method === "PUT")).toBe(true);
    });
    const savedPreferencesCall = requestCalls.find(
      (call) => call.path === "/settings/preferences" && call.init?.method === "PUT",
    );
    expect(JSON.parse(String(savedPreferencesCall?.init?.body))).toMatchObject({
      refresh_seconds: 30,
      compact_mode: true,
    });
  }, 20000);
});
