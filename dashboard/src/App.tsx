import {
  Component,
  lazy,
  memo,
  Suspense,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type CSSProperties,
  type FormEvent,
  type ReactNode,
} from "react";
import {
  AnimatePresence,
  motion,
  useMotionValue,
  useReducedMotion,
  useSpring,
  useTransform,
} from "framer-motion";
import {
  Activity,
  ArrowRight,
  ArrowUpRight,
  Bell,
  Bot,
  Check,
  CheckCircle2,
  ChevronDown,
  CircleAlert,
  CircleHelp,
  Clock3,
  Database,
  FileCheck2,
  Fingerprint,
  Gauge,
  LockKeyhole,
  LayoutDashboard,
  LogOut,
  Menu,
  MonitorDot,
  Network,
  Radio,
  RefreshCw,
  Search,
  Settings2,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Target,
  Timer,
  TriangleAlert,
  X,
  Zap,
  type LucideIcon,
} from "lucide-react";
import { API_BASE, ApiError, apiRequest } from "./api";
import "./style.css";

const LazyShieldScene = lazy(() => import("./ShieldScene"));

type Decision = "ALLOW" | "BLOCK" | "SANDBOX" | "HUMAN_APPROVAL" | string;
type SecurityTheme = "secure" | "elevated" | "high-risk" | "blocked" | "approval" | "sandbox";
type ShieldMode = SecurityTheme;
type Approval = {
  id: number;
  agent: string;
  user?: string;
  tool: string;
  action: string;
  resource: string;
  environment: string;
  records: number;
  status: string;
  reason: string;
  approved_by?: string | null;
  reviewed_at?: string | null;
};
type Audit = {
  id: number;
  timestamp: string;
  agent: string;
  user: string;
  tool: string;
  action: string;
  resource: string;
  environment: string;
  records: number;
  decision: Decision;
  reason: string;
  approval_id: number | null;
  risk_score: number | null;
  anomaly_detected: boolean;
  event_id?: string | null;
  event_type?: string | null;
  severity?: string | null;
  evidence?: string | null;
  previous_hash?: string | null;
  event_hash?: string | null;
};
type Summary = {
  decisions: Record<string, number>;
  hours?: number;
  agents?: { total: number; active: number; inactive: number };
  total_events?: number;
  severities?: Record<string, number>;
  blocked_actions?: number;
  pending_approvals?: number;
  events_over_time?: Array<{ date: string; count: number }>;
  recent_anomalies: Array<{
    id: number;
    timestamp: string;
    agent: string;
    action: string;
    risk_score: number | null;
    decision: Decision;
  }>;
};
type AuditIntegrity = {
  verified: boolean;
  records_checked: number;
  first_invalid_id: number | null;
  head_hash?: string | null;
};
type Permission = {
  rule_id: string;
  tool: string;
  resource: string;
  action: string;
  environments: string | string[];
  decision: Decision;
  max_records: number | null;
  rate_limit: number | null;
};
type Agent = {
  name: string;
  description: string | null;
  active: boolean;
  last_seen: string | null;
  last_decision: Decision | null;
  usage: { total_actions: number; blocked_actions: number; anomalies: number };
  permissions: Permission[];
};
type PolicyRule = {
  id: string;
  match: Record<string, string | number | string[]>;
  decision: Decision;
  reason: string;
  rate_limit?: number;
};
type Policies = {
  version: number;
  default_decision: string;
  required_subject_roles: string[];
  rules: PolicyRule[];
};
type BenchmarkRunSummary = {
  run_id: number;
  started_at: string;
  actor: string;
  summary: Benchmark["summary"];
};
type AnomalyEvaluation = {
  available: boolean;
  evaluation?: string;
  training_benign?: number;
  test_attacks?: number;
  test_benign?: number;
  precision?: number;
  recall?: number;
  f1_score?: number;
  false_positive_rate?: number;
  mean_detection_latency_ms?: number;
  limitations?: string;
  reason?: string;
};
type BenchmarkScenario = {
  scenario_id: string;
  category: string;
  is_attack: boolean;
  agent_identity: string;
  tool: string;
  action: string;
  resource: string;
  environment: string;
  records: number;
  expected_security_outcome: string;
  observed_decisions: string[];
  expected_outcome_met: boolean;
};
type Benchmark = {
  run_id?: number;
  started_at?: string;
  summary: {
    scenario_count: number;
    attack_scenarios: number;
    legitimate_scenarios: number;
    attack_requests: number;
    legitimate_requests: number;
    attack_success_rate: number;
    attack_prevention_rate: number;
    detection_rate: number;
    false_positive_rate: number;
    false_negative_rate: number;
    legitimate_action_acceptance_rate: number;
    precision: number;
    recall: number;
    f1_score: number;
    average_decision_latency_ms: number;
    decision_distribution: Record<string, { count: number; rate: number }>;
    baseline_comparison: Record<string, {
      attack_requests: number;
      successful_attack_requests: number;
      attack_success_rate: number;
    }>;
    category_results: Record<string, {
      scenarios: number;
      requests: number;
      successful_attack_requests: number;
      accepted_legitimate_requests: number;
    }>;
    expected_scenario_mismatches: number;
  };
  scenarios: BenchmarkScenario[];
  methodology: Record<string, string>;
};
type DashboardPreferences = {
  animations_enabled: boolean;
  refresh_seconds: 15 | 30 | 60;
  auto_refresh: boolean;
  compact_mode: boolean;
  notifications_enabled: boolean;
  critical_notifications_only: boolean;
  desktop_notifications: boolean;
};
const DEFAULT_PREFERENCES: DashboardPreferences = {
  animations_enabled: true,
  refresh_seconds: 15,
  auto_refresh: true,
  compact_mode: false,
  notifications_enabled: true,
  critical_notifications_only: false,
  desktop_notifications: false,
};
function normalizePreferences(
  value: Partial<DashboardPreferences>,
): DashboardPreferences {
  return { ...DEFAULT_PREFERENCES, ...value };
}
type Page =
  | "overview"
  | "monitoring"
  | "approvals"
  | "agents"
  | "policies"
  | "anomalies"
  | "benchmark"
  | "audit"
  | "settings";
type Confirmation =
  | { kind: "approval"; item: Approval; approved: boolean }
  | { kind: "benchmark" };

const PAGE_ITEMS: Array<{ id: Page; label: string; icon: LucideIcon }> = [
  { id: "overview", label: "Security overview", icon: ShieldCheck },
  { id: "monitoring", label: "Live monitoring", icon: Radio },
  { id: "approvals", label: "Approval center", icon: CheckCircle2 },
  { id: "agents", label: "Agent activity", icon: Bot },
  { id: "policies", label: "Policy management", icon: FileCheck2 },
  { id: "anomalies", label: "Anomaly signals", icon: TriangleAlert },
  { id: "benchmark", label: "Attack benchmark", icon: Target },
  { id: "audit", label: "Audit logs", icon: Activity },
  { id: "settings", label: "Settings", icon: Settings2 },
];

const SecurityAtmosphere = memo(function SecurityAtmosphere({
  authenticated,
  theme,
  reducedMotion,
}: {
  authenticated: boolean;
  theme: SecurityTheme;
  reducedMotion: boolean;
}) {
  useEffect(() => {
    const body = document.body;
    body.dataset.securityTheme = authenticated ? theme : "login";
  }, [authenticated, theme]);

  useEffect(() => {
    const body = document.body;
    return () => {
      delete body.dataset.securityTheme;
    };
  }, []);

  useEffect(() => {
    const body = document.body;
    let frame = 0;
    let targetX = window.innerWidth * 0.48;
    let targetY = window.innerHeight * 0.42;
    let currentX = targetX;
    let currentY = targetY;
    const followPointer = () => {
      currentX += (targetX - currentX) * 0.16;
      currentY += (targetY - currentY) * 0.16;
      body.style.setProperty("--pointer-x", `${currentX.toFixed(1)}px`);
      body.style.setProperty("--pointer-y", `${currentY.toFixed(1)}px`);
      if (Math.abs(targetX - currentX) > 0.4 || Math.abs(targetY - currentY) > 0.4) {
        frame = requestAnimationFrame(followPointer);
      } else {
        frame = 0;
      }
    };
    const move = (event: PointerEvent) => {
      if (reducedMotion) return;
      targetX = event.clientX;
      targetY = event.clientY;
      if (!frame) frame = requestAnimationFrame(followPointer);
    };
    window.addEventListener("pointermove", move, { passive: true });
    return () => {
      window.removeEventListener("pointermove", move);
      if (frame) cancelAnimationFrame(frame);
      body.style.removeProperty("--pointer-x");
      body.style.removeProperty("--pointer-y");
    };
  }, [reducedMotion]);

  const particleCount = reducedMotion ? 0 : authenticated ? 42 : 8;
  const particles = Array.from({ length: particleCount }, (_, index) => {
    const seed = index + 1;
    const particleStyle: CSSProperties = {
      left: `${(seed * 47.17) % 100}%`,
      animationDelay: `${-((seed * 1.83) % 11)}s`,
      animationDuration: authenticated
        ? `${7 + ((seed * 2.37) % 9)}s, 1.8s`
        : `${7 + ((seed * 2.37) % 9)}s`,
      width: `${1 + (seed % 3)}px`,
      height: `${7 + (seed % 13)}px`,
      opacity: authenticated ? 0.46 + ((seed % 5) * 0.1) : 0.2,
      filter: `blur(${seed % 4 === 0 ? 0.5 : 0}px)`,
    };
    return (
      <i
        className={`energy-particle energy-particle-${seed % 3}`}
        key={index}
        style={particleStyle}
      />
    );
  });

  return (
    <div
      className={`energy-atmosphere ${authenticated ? "energy-atmosphere-live" : ""} ${reducedMotion ? "energy-atmosphere-static" : ""}`}
      data-testid="security-atmosphere"
      aria-hidden="true"
    >
      <div className="energy-aura" />
      <div className="energy-drift" />
      <div className="energy-rain">{particles}</div>
      <div className="energy-grid" />
    </div>
  );
});

function Awakening({ onSkip }: { onSkip: () => void }) {
  const [phase, setPhase] = useState(0);
  const phases = [
    "INITIALIZING SECURE CORE",
    "ESTABLISHING TRUST BOUNDARIES",
    "POLICY ENGINE ONLINE",
    "AGENTSHIELD ACTIVE",
  ];

  useEffect(() => {
    const interval = window.setInterval(() => {
      setPhase((current) => Math.min(current + 1, phases.length - 1));
    }, 850);
    return () => window.clearInterval(interval);
  }, []);

  return (
    <div className="awakening" role="status" aria-live="polite">
      <div className="awakening-starfield" />
      <div className="awakening-rings" aria-hidden="true"><span /><span /><span /></div>
      <div className="awakening-core" aria-hidden="true"><ShieldCheck size={42} /></div>
      <div className="awakening-brand">AGENT<span>SHIELD</span></div>
      <p className="awakening-phase">{phases[phase]}</p>
      <div className="awakening-progress"><span style={{ width: `${(phase + 1) * 25}%` }} /></div>
      <button className="awakening-skip" type="button" onClick={onSkip}>Skip boot sequence <ArrowRight size={13} /></button>
    </div>
  );
}

class ShieldBoundary extends Component<
  { children: ReactNode; fallback: ReactNode },
  { failed: boolean }
> {
  state = { failed: false };

  static getDerivedStateFromError() {
    return { failed: true };
  }

  render() {
    return this.state.failed ? this.props.fallback : this.props.children;
  }
}

function ShieldVisual({
  mode,
  pulseKey,
  reducedMotion,
  onActivate,
  compact = false,
}: {
  mode: ShieldMode;
  pulseKey: number;
  reducedMotion: boolean;
  onActivate: () => void;
  compact?: boolean;
}) {
  return (
    <div className={`shield-visual ${compact ? "shield-visual-compact" : ""} mode-${mode}`}>
      <div className="shield-fallback" aria-hidden="true">
        <ShieldCheck strokeWidth={1.1} />
      </div>
      <ShieldBoundary fallback={<div className="webgl-note">2D security emblem active</div>}>
        <Suspense fallback={<div className="webgl-note">Preparing secure visualization…</div>}>
          <LazyShieldScene
            mode={mode}
            pulseKey={pulseKey}
            reducedMotion={reducedMotion}
            onActivate={onActivate}
          />
        </Suspense>
      </ShieldBoundary>
      <div className="shield-orbit shield-orbit-one" />
      <div className="shield-orbit shield-orbit-two" />
      <div className="shield-aura" />
      <span className="shield-caption"><span /> POLICY GATEWAY</span>
    </div>
  );
}

export default function App() {
  const [token, setToken] = useState(sessionStorage.getItem("agentshield-token") ?? "");
  const [role, setRole] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [page, setPage] = useState<Page>("overview");
  const [approvals, setApprovals] = useState<Approval[]>([]);
  const [approvalHistory, setApprovalHistory] = useState<Approval[]>([]);
  const [audits, setAudits] = useState<Audit[]>([]);
  const [agents, setAgents] = useState<Agent[]>([]);
  const [summary, setSummary] = useState<Summary>({ decisions: {}, recent_anomalies: [] });
  const [policies, setPolicies] = useState<Policies | null>(null);
  const [benchmark, setBenchmark] = useState<Benchmark | null>(null);
  const [benchmarkRuns, setBenchmarkRuns] = useState<BenchmarkRunSummary[]>([]);
  const [anomalyEvaluation, setAnomalyEvaluation] = useState<AnomalyEvaluation | null>(null);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [loginBusy, setLoginBusy] = useState(false);
  const [busy, setBusy] = useState(false);
  const [initialLoading, setInitialLoading] = useState(Boolean(token));
  const [benchmarkBusy, setBenchmarkBusy] = useState(false);
  const [search, setSearch] = useState("");
  const [filterAgent, setFilterAgent] = useState("");
  const [filterDecision, setFilterDecision] = useState("");
  const [filterAction, setFilterAction] = useState("");
  const [filterDate, setFilterDate] = useState("");
  const [decisionReason, setDecisionReason] = useState("");
  const [confirmation, setConfirmation] = useState<Confirmation | null>(null);
  const [preferences, setPreferences] = useState<DashboardPreferences>(DEFAULT_PREFERENCES);
  const [savedPreferences, setSavedPreferences] = useState<DashboardPreferences>(DEFAULT_PREFERENCES);
  const [preferencesLoaded, setPreferencesLoaded] = useState(false);
  const [preferencesSaving, setPreferencesSaving] = useState(false);
  const [preferencesMessage, setPreferencesMessage] = useState("");
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [notificationOpen, setNotificationOpen] = useState(false);
  const [newEventCount, setNewEventCount] = useState(0);
  const [streamConnected, setStreamConnected] = useState(false);
  const [auditIntegrity, setAuditIntegrity] = useState<AuditIntegrity | null>(null);
  const [integrityBusy, setIntegrityBusy] = useState(false);
  const [overviewHours, setOverviewHours] = useState(24);
  const [agentFormOpen, setAgentFormOpen] = useState(false);
  const [agentName, setAgentName] = useState("");
  const [agentPassword, setAgentPassword] = useState("");
  const [agentDescription, setAgentDescription] = useState("");
  const [agentBusy, setAgentBusy] = useState(false);
  const [policyDraft, setPolicyDraft] = useState("");
  const [policyBusy, setPolicyBusy] = useState(false);
  const [policyHistory, setPolicyHistory] = useState<Array<{ version: number; changed_at: string; changed_by: string }>>([]);
  const [policyTest, setPolicyTest] = useState({ agent: "", tool: "", action: "", resource: "", environment: "development", records: 1 });
  const [policyTestResult, setPolicyTestResult] = useState("");
  const [welcomeOpen, setWelcomeOpen] = useState(false);
  const [statusDetailsOpen, setStatusDetailsOpen] = useState(false);
  const [shieldPulseKey, setShieldPulseKey] = useState(0);
  const [selectedNode, setSelectedNode] = useState("");
  const mainContentRef = useRef<HTMLElement | null>(null);
  const [awakeningVisible, setAwakeningVisible] = useState(() => {
    const reduced = typeof window !== "undefined" &&
      typeof window.matchMedia === "function" &&
      window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    return !reduced && !sessionStorage.getItem("agentshield-awakening-seen");
  });
  const latestAuditId = useRef<number | null>(null);
  const prefersReducedMotion = useReducedMotion();
  const reducedMotion = Boolean(prefersReducedMotion || !preferences.animations_enabled);
  const preferencesDirty = JSON.stringify(preferences) !== JSON.stringify(savedPreferences);

  useEffect(() => {
    const root = mainContentRef.current;
    if (!root || reducedMotion) return;
    const cardSelector = [
      ".panel", ".metric-card", ".telemetry-instrument", ".anomaly-card",
      ".signal-card", ".mini-benchmark", ".flow-node", ".gateway-node",
      ".policy-callout", ".command-hero", ".agent-grid > article",
    ].join(",");
    let activeCard: HTMLElement | null = null;
    let frame = 0;
    let pointerX = 0;
    let pointerY = 0;
    const resetCard = (card: HTMLElement | null) => {
      if (!card) return;
      card.classList.remove("card-pointer-active");
      card.style.removeProperty("--card-x");
      card.style.removeProperty("--card-y");
      card.style.removeProperty("--card-tilt-x");
      card.style.removeProperty("--card-tilt-y");
    };
    const updatePointer = () => {
      if (!activeCard) return;
      const bounds = activeCard.getBoundingClientRect();
      activeCard.style.setProperty("--card-x", `${pointerX - bounds.left}px`);
      activeCard.style.setProperty("--card-y", `${pointerY - bounds.top}px`);
      const tiltX = ((pointerY - bounds.top) / Math.max(bounds.height, 1) - 0.5) * -2.2;
      const tiltY = ((pointerX - bounds.left) / Math.max(bounds.width, 1) - 0.5) * 2.2;
      activeCard.style.setProperty("--card-tilt-x", `${tiltX.toFixed(2)}deg`);
      activeCard.style.setProperty("--card-tilt-y", `${tiltY.toFixed(2)}deg`);
      frame = 0;
    };
    const handlePointerMove = (event: PointerEvent) => {
      const target = event.target instanceof Element
        ? event.target.closest<HTMLElement>(cardSelector)
        : null;
      if (target !== activeCard) {
        resetCard(activeCard);
        activeCard = target;
        activeCard?.classList.add("card-pointer-active");
      }
      if (!activeCard) return;
      pointerX = event.clientX;
      pointerY = event.clientY;
      if (!frame) frame = requestAnimationFrame(updatePointer);
    };
    const handlePointerLeave = (event: PointerEvent) => {
      if (event.relatedTarget instanceof Node && root.contains(event.relatedTarget)) return;
      resetCard(activeCard);
      activeCard = null;
    };
    const handleClick = (event: MouseEvent) => {
      const target = event.target instanceof Element
        ? event.target.closest<HTMLElement>(cardSelector)
        : null;
      if (!target) return;
      target.classList.remove("card-energy-pulse");
      void target.offsetWidth;
      target.classList.add("card-energy-pulse");
      window.setTimeout(() => target.classList.remove("card-energy-pulse"), 650);
    };
    root.addEventListener("pointermove", handlePointerMove, { passive: true });
    root.addEventListener("pointerleave", handlePointerLeave, { passive: true });
    root.addEventListener("click", handleClick);
    return () => {
      root.removeEventListener("pointermove", handlePointerMove);
      root.removeEventListener("pointerleave", handlePointerLeave);
      root.removeEventListener("click", handleClick);
      if (frame) cancelAnimationFrame(frame);
      resetCard(activeCard);
      activeCard?.classList.remove("card-energy-pulse");
    };
  }, [reducedMotion]);

  useEffect(() => {
    if (reducedMotion && awakeningVisible) {
      setAwakeningVisible(false);
      return;
    }
    if (!awakeningVisible) return;
    sessionStorage.setItem("agentshield-awakening-seen", "1");
    const timer = window.setTimeout(() => setAwakeningVisible(false), 4100);
    return () => window.clearTimeout(timer);
  }, [awakeningVisible, reducedMotion]);

  const api = useCallback(async <T,>(
    path: string,
    init: RequestInit = {},
  ): Promise<T> => {
    try {
      return await apiRequest<T>(path, init, token);
    } catch (reason) {
      if (reason instanceof ApiError && reason.status === 401) {
        sessionStorage.removeItem("agentshield-token");
        setToken("");
        setRole("");
        setDisplayName("");
      }
      throw reason;
    }
  }, [token]);

  const refresh = useCallback(async (showSpinner = false) => {
    if (!token || !["reviewer", "security_admin"].includes(role)) return;
    if (showSpinner) setBusy(true);
    setError("");
    try {
      const [
        approvalData,
        historyData,
        auditData,
        summaryData,
        agentData,
        policyData,
      ] = await Promise.all([
        api<{ pending_approvals: Approval[] }>("/approvals"),
        api<{ approval_history: Approval[] }>("/approvals/history"),
        api<{ audit_logs: Audit[] }>("/audit-logs"),
        api<Summary>(`/security/summary?hours=${overviewHours}`),
        api<{ agents: Agent[] }>("/agents"),
        api<Policies>("/security/policies"),
      ]);

      const incomingLatestId = auditData.audit_logs[0]?.id ?? null;
      if (
        latestAuditId.current !== null &&
        incomingLatestId !== null &&
        incomingLatestId !== latestAuditId.current
      ) {
        const latestEvent = auditData.audit_logs[0];
        const notifyForEvent =
          preferences.notifications_enabled &&
          (!preferences.critical_notifications_only || latestEvent?.severity === "CRITICAL");
        if (notifyForEvent) {
          setNewEventCount((count) => count + 1);
        }
        if (
          notifyForEvent &&
          preferences.desktop_notifications &&
          typeof Notification !== "undefined" &&
          Notification.permission === "granted" &&
          latestEvent
        ) {
          new Notification(`AgentShield ${latestEvent.severity ?? "security"} event`, {
            body: `Decision: ${latestEvent.decision}. Open the console to review details.`,
            tag: `agentshield-event-${latestEvent.id}`,
          });
        }
        if (auditData.audit_logs[0]?.decision === "BLOCK") {
          setShieldPulseKey((value) => value + 1);
        }
      }
      latestAuditId.current = incomingLatestId;
      setApprovals(approvalData.pending_approvals);
      setApprovalHistory(historyData.approval_history);
      setAudits(auditData.audit_logs);
      setSummary(summaryData);
      setAgents(agentData.agents);
      setPolicies(policyData);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Unable to load security data");
    } finally {
      if (showSpinner) setBusy(false);
      setInitialLoading(false);
    }
  }, [api, overviewHours, preferences, role, token]);

  const verifyAuditChain = useCallback(async () => {
    setIntegrityBusy(true);
    try {
      setAuditIntegrity(await api<AuditIntegrity>("/audit-logs/integrity"));
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Audit integrity check failed");
    } finally {
      setIntegrityBusy(false);
    }
  }, [api]);

  useEffect(() => {
    if (page === "audit" && token && ["reviewer", "security_admin"].includes(role)) {
      void verifyAuditChain();
    }
  }, [page, role, token, verifyAuditChain]);

  useEffect(() => {
    if (!token) {
      setInitialLoading(false);
      return;
    }
    let active = true;
    setInitialLoading(true);
    void api<{ username: string; role: string }>("/auth/me")
      .then((user) => {
        if (!active) return;
        if (!["reviewer", "security_admin"].includes(user.role)) {
          sessionStorage.removeItem("agentshield-token");
          setToken("");
          setRole("");
          setError("Reviewer or security administrator access is required for this console.");
          return;
        }
        setRole(user.role);
        setDisplayName(user.username);
      })
      .catch((reason: unknown) => {
        if (active) {
          setError(reason instanceof Error ? reason.message : "Authentication failed");
        }
      })
      .finally(() => {
        if (active) setInitialLoading(false);
      });
    return () => {
      active = false;
    };
  }, [api, token]);

  useEffect(() => {
    if (!token || !["reviewer", "security_admin"].includes(role)) return;
    if (!preferences.auto_refresh) return;
    void refresh();
    const timer = window.setInterval(() => void refresh(), preferences.refresh_seconds * 1000);
    return () => window.clearInterval(timer);
  }, [preferences.auto_refresh, preferences.refresh_seconds, refresh, role, token]);

  useEffect(() => {
    if (!token || !role) return;
    let active = true;
    setPreferencesLoaded(false);
    void api<DashboardPreferences>(
      "/settings/preferences",
    ).then((preferences) => {
      if (!active) return;
      const normalized = normalizePreferences(preferences);
      setPreferences(normalized);
      setSavedPreferences(normalized);
      setPreferencesMessage("");
    }).catch((reason: unknown) => {
      if (active) setPreferencesMessage(reason instanceof Error ? reason.message : "Unable to load preferences");
    }).finally(() => {
      if (active) setPreferencesLoaded(true);
    });
    return () => { active = false; };
  }, [api, role, token]);

  useEffect(() => {
    if (!token || !["reviewer", "security_admin"].includes(role) || page !== "benchmark") return;
    let active = true;
    void api<{ runs: BenchmarkRunSummary[] }>("/security/benchmark/runs")
      .then(async ({ runs }) => {
        if (!active) return;
        setBenchmarkRuns(runs);
        if (runs[0]) {
          const latest = await api<Benchmark>(
            `/security/benchmark/runs/${runs[0].run_id}`,
          );
          if (active) setBenchmark(latest);
        } else if (active) {
          setBenchmark(null);
        }
      })
      .catch((reason: unknown) => {
        if (active) setError(reason instanceof Error ? reason.message : "Unable to load benchmark history");
      });
    return () => { active = false; };
  }, [api, page, role, token]);

  useEffect(() => {
    if (!token || !["reviewer", "security_admin"].includes(role) || page !== "anomalies") return;
    let active = true;
    void api<AnomalyEvaluation>("/security/anomaly/evaluation")
      .then((result) => { if (active) setAnomalyEvaluation(result); })
      .catch((reason: unknown) => {
        if (active) setError(reason instanceof Error ? reason.message : "Unable to evaluate anomaly signals");
      });
    return () => { active = false; };
  }, [api, page, role, token]);

  useEffect(() => {
    if (!token || !["reviewer", "security_admin"].includes(role) || page !== "policies") return;
    let active = true;
    void api<{ versions: Array<{ version: number; changed_at: string; changed_by: string }> }>(
      "/security/policies/history",
    ).then(({ versions }) => {
      if (active) setPolicyHistory(versions);
    }).catch((reason: unknown) => {
      if (active) setError(reason instanceof Error ? reason.message : "Unable to load policy history");
    });
    return () => { active = false; };
  }, [api, page, role, token]);

  useEffect(() => {
    if (!policies) return;
    setPolicyDraft(JSON.stringify({
      default_decision: policies.default_decision,
      required_subject_roles: policies.required_subject_roles,
      rules: policies.rules,
    }, null, 2));
    setPolicyTest((current) => ({
      ...current,
      agent: current.agent || agents[0]?.name || "",
      tool: current.tool || String(policies.rules[0]?.match.tool ?? ""),
      action: current.action || String(policies.rules[0]?.match.action ?? ""),
      resource: current.resource || String(policies.rules[0]?.match.resource ?? ""),
    }));
  }, [agents, policies]);

  useEffect(() => {
    if (!token || !["reviewer", "security_admin"].includes(role)) {
      setStreamConnected(false);
      return;
    }

    let active = true;
    let reconnectTimer: number | undefined;
    let socket: WebSocket | undefined;
    const connect = () => {
      if (!active) return;
      socket = new WebSocket(
        `${API_BASE.replace(/^http/, "ws")}/security/stream`,
        ["agentshield.events.v1", `agentshield.jwt.${token}`],
      );
      socket.onopen = () => {
        if (active) setStreamConnected(true);
      };
      socket.onmessage = (message) => {
        if (!active) return;
        try {
          const event: unknown = JSON.parse(String(message.data));
          if (
            typeof event === "object" &&
            event !== null &&
            "type" in event &&
            event.type === "security_event"
          ) {
            void refresh();
          }
        } catch {
          setError("The live security stream returned an invalid event.");
        }
      };
      socket.onclose = () => {
        if (!active) return;
        setStreamConnected(false);
        reconnectTimer = window.setTimeout(connect, 3000);
      };
      socket.onerror = () => socket?.close();
    };

    connect();
    return () => {
      active = false;
      if (reconnectTimer !== undefined) window.clearTimeout(reconnectTimer);
      socket?.close();
      setStreamConnected(false);
    };
  }, [refresh, role, token]);

  async function login(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    setNotice("");
    setLoginBusy(true);
    try {
      const result = await api<{ access_token: string; username: string; role: string }>(
        "/auth/login",
        {
          method: "POST",
          body: JSON.stringify({ username, password }),
        },
      );
      if (
        !result ||
        typeof result !== "object" ||
        typeof result.access_token !== "string" ||
        !result.access_token ||
        typeof result.username !== "string" ||
        typeof result.role !== "string"
      ) {
        throw new Error("The AgentShield API returned an unexpected login response. Check the backend version and /auth/login response.");
      }
      if (!["reviewer", "security_admin"].includes(result.role)) {
        setError("This console requires an authorized reviewer or security administrator.");
        return;
      }
      sessionStorage.setItem("agentshield-token", result.access_token);
      setRole(result.role);
      setDisplayName(result.username);
      setToken(result.access_token);
      setPassword("");
      setWelcomeOpen(true);
      setNotice(`Secure session established for ${result.username}.`);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Sign-in failed. Please try again.");
    } finally {
      setLoginBusy(false);
    }
  }

  async function submitDecision(item: Approval, approved: boolean) {
    const rejectionReason = decisionReason.trim();
    if (!approved && !rejectionReason) {
      setError("A rejection reason is required.");
      return;
    }
    setBusy(true);
    setError("");
    setNotice("");
    try {
      const response = await api<{ decision: string; reviewer?: string }>(
        "/approvals/decision",
        {
          method: "POST",
          body: JSON.stringify({
            approval_id: item.id,
            approved,
            ...(approved ? {} : { rejection_reason: rejectionReason }),
          }),
        },
      );
      setConfirmation(null);
      setDecisionReason("");
      setNotice(
        `Request ${response.decision.toLowerCase()}${response.reviewer ? ` by ${response.reviewer}` : ""}.`,
      );
      await refresh();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Approval decision failed");
    } finally {
      setBusy(false);
    }
  }

  async function runBenchmark() {
    setBenchmarkBusy(true);
    setError("");
    setNotice("");
    try {
      const result = await api<Benchmark>("/security/benchmark", { method: "POST" });
      setBenchmark(result);
      if (result.run_id && result.started_at) {
        setBenchmarkRuns((runs) => [{
          run_id: result.run_id!,
          started_at: result.started_at!,
          actor: displayName,
          summary: result.summary,
        }, ...runs.filter((run) => run.run_id !== result.run_id)].slice(0, 50));
      }
      setNotice("Benchmark completed and saved to persistent run history.");
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Benchmark could not run");
    } finally {
      setBenchmarkBusy(false);
      setConfirmation(null);
    }
  }

  function changePreference<Key extends keyof DashboardPreferences>(
    key: Key,
    value: DashboardPreferences[Key],
  ) {
    setPreferences((current) => ({ ...current, [key]: value }));
    if (
      (key === "notifications_enabled" && value === false) ||
      (key === "critical_notifications_only" && value === true)
    ) {
      setNewEventCount(0);
    }
    setPreferencesMessage("");
  }

  async function savePreferences() {
    setPreferencesSaving(true);
    setPreferencesMessage("");
    try {
      if (preferences.desktop_notifications) {
        if (typeof Notification === "undefined") {
          throw new Error("Desktop notifications are not supported by this browser.");
        }
        if (Notification.permission === "default") {
          const permission = await Notification.requestPermission();
          if (permission !== "granted") {
            throw new Error("Browser notification permission was not granted.");
          }
        } else if (Notification.permission !== "granted") {
          throw new Error("Allow notifications for this site in your browser settings first.");
        }
      }
      const saved = await api<DashboardPreferences>(
        "/settings/preferences",
        {
          method: "PUT",
          body: JSON.stringify(preferences),
        },
      );
      const normalized = normalizePreferences(saved);
      setPreferences(normalized);
      setSavedPreferences(normalized);
      setPreferencesMessage("Your settings are saved to this account.");
    } catch (reason) {
      setPreferencesMessage(reason instanceof Error ? reason.message : "Preferences could not be saved.");
    } finally {
      setPreferencesSaving(false);
    }
  }

  function resetPreferences() {
    setPreferences(DEFAULT_PREFERENCES);
    setPreferencesMessage("Defaults selected. Save to apply them to your account.");
  }

  async function registerAgent(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setAgentBusy(true);
    setError("");
    try {
      await api("/agents", {
        method: "POST",
        body: JSON.stringify({
          name: agentName.trim(),
          password: agentPassword,
          description: agentDescription.trim() || null,
        }),
      });
      setAgentName("");
      setAgentPassword("");
      setAgentDescription("");
      setAgentFormOpen(false);
      setNotice("Agent identity registered. Its password is not displayed again.");
      await refresh();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Agent registration failed");
    } finally {
      setAgentBusy(false);
    }
  }

  async function setAgentActive(agent: Agent, active: boolean) {
    setAgentBusy(true);
    setError("");
    try {
      await api(`/agents/${encodeURIComponent(agent.name)}/status`, {
        method: "PATCH",
        body: JSON.stringify({ active }),
      });
      setNotice(`${agent.name} ${active ? "reactivated" : "suspended"}.`);
      await refresh();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Agent status update failed");
    } finally {
      setAgentBusy(false);
    }
  }

  async function savePolicyDraft() {
    if (!policies) return;
    setPolicyBusy(true);
    setError("");
    try {
      const draft = JSON.parse(policyDraft) as {
        default_decision: string;
        required_subject_roles: string[];
        rules: PolicyRule[];
      };
      const updated = await api<Policies>("/security/policies", {
        method: "POST",
        body: JSON.stringify({ ...draft, expected_version: policies.version }),
      });
      setPolicies(updated);
      setNotice(`Policy version ${updated.version} saved. Changes are effective immediately.`);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Policy update failed");
    } finally {
      setPolicyBusy(false);
    }
  }

  async function testPolicyDraft(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setPolicyTestResult("");
    try {
      const response = await api<Record<string, unknown>>(
        "/security/policies/dry-run",
        {
          method: "POST",
          body: JSON.stringify({
            ...policyTest,
            user: policyTest.agent,
          }),
        },
      );
      setPolicyTestResult(JSON.stringify(response, null, 2));
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Policy dry-run failed");
    }
  }

  function logout() {
    sessionStorage.removeItem("agentshield-token");
    latestAuditId.current = null;
    setToken("");
    setRole("");
    setDisplayName("");
    setApprovals([]);
    setApprovalHistory([]);
    setAudits([]);
    setAuditIntegrity(null);
    setAgents([]);
    setSummary({ decisions: {}, recent_anomalies: [] });
    setPolicies(null);
    setBenchmark(null);
    setBenchmarkRuns([]);
    setAnomalyEvaluation(null);
    setWelcomeOpen(false);
    setPage("overview");
  }

  const filteredAudits = useMemo(() => audits.filter((item) => {
    const searchable = `${item.agent} ${item.action} ${item.resource} ${item.reason} ${item.tool}`.toLowerCase();
    return (
      searchable.includes(search.toLowerCase()) &&
      (!filterAgent || item.agent === filterAgent) &&
      (!filterDecision || item.decision === filterDecision) &&
      (!filterAction || item.action.toLowerCase().includes(filterAction.toLowerCase())) &&
      (!filterDate || item.timestamp.slice(0, 10) === filterDate)
    );
  }), [audits, filterAction, filterAgent, filterDate, filterDecision, search]);
  const notificationAudits = useMemo(() => (
    preferences.critical_notifications_only
      ? audits.filter((item) => item.severity === "CRITICAL")
      : audits
  ), [audits, preferences.critical_notifications_only]);

  const decisionCounts = summary.decisions;
  const totalActions = Object.values(decisionCounts).reduce((total, count) => total + count, 0);
  const blocked = decisionCounts.BLOCK ?? 0;
  const allowed = decisionCounts.ALLOW ?? 0;
  const sandboxed = decisionCounts.SANDBOX ?? 0;
  const latestDecision = audits[0]?.decision;
  const highestObservedRisk = Math.max(
    -1,
    audits[0]?.risk_score ?? -1,
    ...summary.recent_anomalies.map((event) => event.risk_score ?? -1),
  );
  const anomalous = highestObservedRisk >= 0.75;
  const securityTheme: SecurityTheme = latestDecision === "BLOCK"
    ? "blocked"
    : latestDecision === "HUMAN_APPROVAL" || approvals.length > 0
      ? "approval"
      : latestDecision === "SANDBOX"
        ? "sandbox"
        : anomalous
          ? "high-risk"
          : highestObservedRisk >= 0.5
            ? "elevated"
            : "secure";
  const securityLabel: Record<SecurityTheme, string> = {
    secure: "SYSTEM SECURE",
    elevated: "ELEVATED RISK",
    "high-risk": "HIGH RISK",
    blocked: "ACTION BLOCKED",
    approval: "HUMAN APPROVAL REQUIRED",
    sandbox: "SANDBOX CONTAINMENT",
  };
  const securityExplanation = securityTheme === "blocked"
    ? `${audits[0]?.action ?? "Request"} · ${audits[0]?.reason ?? "Blocked by policy"}`
    : securityTheme === "high-risk" || securityTheme === "elevated"
      ? `Behavioral risk signal · ${percent(highestObservedRisk)} · advisory; policy remains authoritative`
      : securityTheme === "approval"
        ? `${approvals.length} pending reviewer request${approvals.length === 1 ? "" : "s"}`
        : securityTheme === "sandbox"
          ? `${audits[0]?.action ?? "Request"} · routed to the configured sandbox`
          : "Deny-by-default policy gateway is active";
  const shieldMode: ShieldMode = securityTheme;
  const statusLabel = error
    ? "API data unavailable"
    : securityLabel[securityTheme];
  const benchmarkStats = benchmark?.summary;
  const anomalyMaximum = Math.max(
    0,
    ...summary.recent_anomalies.map((event) => event.risk_score ?? 0),
  );
  const riskTelemetryValue = summary.recent_anomalies.reduce(
    (maximum, event) => event.risk_score === null
      ? maximum
      : Math.max(maximum, event.risk_score),
    -1,
  );
  const measuredLatency = benchmarkStats &&
      Number.isFinite(benchmarkStats.average_decision_latency_ms)
    ? benchmarkStats.average_decision_latency_ms
    : null;
  const resourceNames = Array.from(new Set(
    (policies?.rules ?? [])
      .map((rule) => rule.match.resource)
      .filter((resource): resource is string =>
        typeof resource === "string" && resource !== "*",
      ),
  )).slice(0, 5);

  if (initialLoading && token) {
    return (
      <>
        <SecurityAtmosphere
          authenticated={Boolean(token)}
          theme={securityTheme}
          reducedMotion={reducedMotion}
        />
        <main className="auth-wait">
          <div className="auth-wait-orb"><ShieldCheck size={26} /></div>
          <p className="eyebrow">VERIFYING SIGNED SESSION</p>
          <h1>Checking your access</h1>
          <p>Confirming your account and reviewer permissions with AgentShield.</p>
          <div className="loading-line"><span /></div>
        </main>
        {awakeningVisible && <Awakening onSkip={() => setAwakeningVisible(false)} />}
      </>
    );
  }

  if (!token) {
    return (
      <>
      <SecurityAtmosphere authenticated={false} theme="secure" reducedMotion={reducedMotion} />
      <main className="login-shell">
        <div className="login-grid" aria-hidden="true" />
        <div className="login-ambient login-ambient-one" aria-hidden="true" />
        <div className="login-ambient login-ambient-two" aria-hidden="true" />
        <section className="login-showcase">
          <div className="brand-lockup">
            <div className="brand-icon"><ShieldCheck size={22} /></div>
            <div><strong>AGENTSHIELD</strong><span>AI RUNTIME SECURITY</span></div>
          </div>
          <div className="login-hero-copy">
            <p className="eyebrow"><span className="eyebrow-dot" /> AUTONOMOUS SYSTEMS. HUMAN GOVERNANCE.</p>
            <h1>Confidence at<br />the <em>speed of AI.</em></h1>
            <p className="muted-copy">One intelligent gateway between autonomous agents and the systems they touch.</p>
          </div>
          <div className="login-shield">
            <ShieldVisual
              mode="secure"
              pulseKey={shieldPulseKey}
              reducedMotion={reducedMotion}
              onActivate={() => setShieldPulseKey((value) => value + 1)}
            />
          </div>
          <div className="login-proof">
            <span><i /> POLICY ENFORCEMENT</span>
            <span><i /> HUMAN OVERSIGHT</span>
            <span><i /> AUDITABLE BY DESIGN</span>
          </div>
          <div className="login-footer">TRUST THE ACTION. VERIFY THE INTENT.</div>
        </section>

        <section className="login-panel-wrap">
          <form className="login-panel" onSubmit={login}>
            <div className="login-panel-top">
              <span className="secure-tag"><LockKeyhole size={13} /> SECURE ACCESS</span>
              <span className="login-version">GATEWAY / 01</span>
            </div>
            <div className="login-heading">
              <div className="login-mobile-mark"><ShieldCheck size={24} /></div>
              <p className="eyebrow">WELCOME BACK</p>
              <h2>Enter the command center</h2>
              <p>Sign in with your authorized reviewer credentials.</p>
            </div>
            <label className="field-label" htmlFor="username">Account ID</label>
            <div className="input-shell">
              <Fingerprint size={17} aria-hidden="true" />
              <input
                autoComplete="username"
                id="username"
                name="username"
                value={username}
                onChange={(event) => setUsername(event.target.value)}
                placeholder="Your reviewer account"
                required
              />
            </div>
            <label className="field-label" htmlFor="password">Password</label>
            <div className="input-shell">
              <LockKeyhole size={16} aria-hidden="true" />
              <input
                autoComplete="current-password"
                id="password"
                name="password"
                type="password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                placeholder="Enter your password"
                required
              />
            </div>
            {error && <div className="login-error" role="alert"><CircleAlert size={16} />{error}</div>}
            <button className="login-submit" type="submit" disabled={loginBusy}>
              <span>{loginBusy ? "Connecting securely…" : "Authenticate"}</span>
              {loginBusy ? <span className="button-spinner" /> : <ArrowRight size={17} />}
            </button>
            <p className="login-timeout-note"><CircleHelp size={13} /> Requests time out with a clear error if the gateway is unavailable.</p>
            <div className="login-divider"><span /> VERIFIED ACCESS ONLY <span /></div>
            <div className="login-security-foot"><LockKeyhole size={13} /> JWT-secured session <b>·</b> Reviewer authorization required</div>
          </form>
          <p className="login-copyright">AGENTSHIELD SECURITY OPERATIONS <span>© 2026</span></p>
        </section>
      </main>
      {awakeningVisible && <Awakening onSkip={() => setAwakeningVisible(false)} />}
      </>
    );
  }

  const activePage = PAGE_ITEMS.find((item) => item.id === page);
  const transition = reducedMotion
    ? { duration: 0 }
    : { duration: 0.24, ease: [0.22, 1, 0.36, 1] as const };

  return (
    <>
    <SecurityAtmosphere authenticated theme={securityTheme} reducedMotion={reducedMotion} />
    <div className={`app-shell ${reducedMotion ? "motion-reduced" : ""} ${preferences.compact_mode ? "compact-mode" : ""}`} data-security-theme={securityTheme}>
      <aside className={`sidebar ${mobileNavOpen ? "sidebar-open" : ""}`}>
        <div className="brand-lockup sidebar-brand">
          <div className="brand-icon"><ShieldCheck size={21} /></div>
          <div><strong>AGENTSHIELD</strong><span>SECURITY OPERATIONS</span></div>
          <button className="mobile-close" onClick={() => setMobileNavOpen(false)} aria-label="Close navigation"><X size={19} /></button>
        </div>
        <div className="side-label">CONTROL PLANE</div>
        <nav className="side-nav" aria-label="Dashboard navigation">
          {PAGE_ITEMS.map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              className={`nav-link ${page === id ? "selected" : ""}`}
              onClick={() => {
                setPage(id);
                setMobileNavOpen(false);
                if (id === "monitoring" || id === "audit") setNewEventCount(0);
              }}
              aria-current={page === id ? "page" : undefined}
            >
              <Icon size={17} strokeWidth={1.8} />
              <span>{label}</span>
              {id === "approvals" && approvals.length > 0 && <b className="nav-count">{approvals.length}</b>}
              {id === "monitoring" && newEventCount > 0 && <b className="nav-count nav-count-blue">{newEventCount}</b>}
              {page === id && <span className="nav-active-mark" />}
            </button>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className={`sidebar-gateway sidebar-gateway-${error ? "error" : securityTheme}`}><span className={`status-pulse ${error ? "status-pulse-error" : ""}`} /><div><strong>{error ? "API connection issue" : securityTheme === "secure" ? "Gateway connected" : securityLabel[securityTheme]}</strong><small>{error ? "See the request error above" : securityTheme === "secure" ? "Live API telemetry" : securityExplanation}</small></div><ChevronDown size={14} /></div>
          <div className="sidebar-user">
            <div className="user-avatar">{displayName.slice(0, 1).toUpperCase()}</div>
            <div className="user-meta"><strong>{displayName}</strong><span>{role.replace("_", " ")}</span></div>
            <button className="logout-button" onClick={logout} aria-label="Sign out"><LogOut size={16} /></button>
          </div>
        </div>
      </aside>
      {mobileNavOpen && <button className="mobile-scrim" onClick={() => setMobileNavOpen(false)} aria-label="Close navigation overlay" />}

      <main className="main-content" ref={mainContentRef}>
        <header className="topbar">
          <div className="topbar-left">
            <button className="mobile-menu" onClick={() => setMobileNavOpen(true)} aria-label="Open navigation"><Menu size={21} /></button>
            <div>
              <div className="breadcrumbs"><span>AGENTSHIELD</span><span className="crumb-slash">/</span><span>COMMAND CENTER</span></div>
              <h1>{activePage?.label}</h1>
            </div>
          </div>
          <div className="topbar-actions">
            <button
              className={`system-status ${error ? "system-status-error" : `system-status-${securityTheme}`}`}
              onClick={() => setStatusDetailsOpen((value) => !value)}
              aria-expanded={statusDetailsOpen}
            >
              <span className={`status-pulse ${error ? "status-pulse-error" : ""}`} /><span>{error ? "API ISSUE" : securityLabel[securityTheme]}</span><ChevronDown size={13} />
            </button>
            <span className="topbar-separator" />
            <button className="notification-button" onClick={() => setNotificationOpen((value) => !value)} aria-label="Recent security notifications" aria-expanded={notificationOpen}>
              <Activity size={18} />
              {newEventCount > 0 && <b>{newEventCount > 9 ? "9+" : newEventCount}</b>}
            </button>
            <button className="refresh-button" onClick={() => void refresh(true)} disabled={busy} aria-label="Refresh dashboard">
              <RefreshCw size={15} className={busy && !reducedMotion ? "spin" : ""} /><span>{busy ? "Syncing" : "Refresh"}</span>
            </button>
          </div>
          {statusDetailsOpen && (
            <div className="status-popover">
              <div className={`status-popover-icon ${securityTheme !== "secure" ? "is-warning" : ""}`}><ShieldCheck size={20} /></div>
              <div><strong>{statusLabel}</strong><p>{error ? "The latest reviewer data request failed. Review the error message and verify API availability." : securityExplanation}</p></div>
              <button onClick={() => setStatusDetailsOpen(false)} aria-label="Close status details"><X size={15} /></button>
            </div>
          )}
          {notificationOpen && (
            <div className="notification-popover">
              <div className="popover-heading"><div><span className="eyebrow">EVENT FEED</span><strong>Security notifications</strong></div><button onClick={() => setNotificationOpen(false)} aria-label="Close notifications"><X size={15} /></button></div>
              {!preferences.notifications_enabled
                ? <EmptyState>In-app event notifications are disabled in Settings.</EmptyState>
                : notificationAudits.length === 0
                  ? <EmptyState>{preferences.critical_notifications_only ? "No critical events in the current audit window." : "No recent audit events were returned by the API."}</EmptyState>
                  : notificationAudits.slice(0, 4).map((item) => (
                  <button className="notification-item" key={item.id} onClick={() => { setPage("monitoring"); setNotificationOpen(false); setNewEventCount(0); }}>
                    <DecisionBadge decision={item.decision} /><span><strong>{item.agent}</strong><small>{item.action} · {item.resource}</small></span><time>{formatTime(item.timestamp)}</time>
                  </button>
                ))}
            </div>
          )}
        </header>

        {securityTheme !== "secure" && (
          <section
            className={`security-state-banner security-state-${securityTheme}`}
            role={securityTheme === "blocked" || securityTheme === "high-risk" ? "alert" : "status"}
            aria-live={securityTheme === "blocked" || securityTheme === "high-risk" ? "assertive" : "polite"}
            data-testid="security-state-banner"
          >
            <span className="security-state-beacon"><ShieldAlert size={18} /></span>
            <div><strong>{securityLabel[securityTheme]}</strong><small>{securityExplanation}</small></div>
            {securityTheme === "approval" && <button className="inline-link" onClick={() => setPage("approvals")}>Review queue <ArrowRight size={14} /></button>}
          </section>
        )}
        {error && <div className="alert-banner error-banner" role="alert"><CircleAlert size={17} /><span>{error}</span><button onClick={() => setError("")} aria-label="Dismiss error"><X size={16} /></button></div>}
        {notice && <div className="alert-banner success-banner" role="status"><CheckCircle2 size={17} /><span>{notice}</span><button onClick={() => setNotice("")} aria-label="Dismiss message"><X size={16} /></button></div>}
        {welcomeOpen && (
          <section className="welcome-strip">
            <span className="welcome-spark"><Sparkles size={17} /></span>
            <div><strong>Welcome to your security command center, {displayName}.</strong><p>Start with live telemetry, review pending approvals, or run the isolated synthetic benchmark.</p></div>
            <button onClick={() => { setPage("monitoring"); setWelcomeOpen(false); }}>Explore live activity <ArrowRight size={15} /></button>
            <button className="strip-close" onClick={() => setWelcomeOpen(false)} aria-label="Dismiss welcome message"><X size={16} /></button>
          </section>
        )}

        <AnimatePresence mode="wait" initial={false}>
          <motion.div
            key={page}
            className="page-content"
            initial={reducedMotion ? false : { opacity: 0, y: 9 }}
            animate={{ opacity: 1, y: 0 }}
            exit={reducedMotion ? undefined : { opacity: 0, y: -5 }}
            transition={transition}
          >
            {page === "overview" && (
              <>
                <Panel
                  title="Security posture"
                  kicker="DATABASE-BACKED · FILTERED WINDOW"
                  aside={<label className="overview-range">Time range
                    <select aria-label="Overview time range" value={overviewHours} onChange={(event) => setOverviewHours(Number(event.target.value))}>
                      <option value={24}>24 hours</option>
                      <option value={168}>7 days</option>
                      <option value={720}>30 days</option>
                    </select>
                  </label>}
                >
                  <section className="metric-grid metric-grid-four" aria-label="Security posture metrics">
                    <Metric label="Registered agents" value={summary.agents?.total ?? 0} caption={`${summary.agents?.active ?? 0} active · ${summary.agents?.inactive ?? 0} inactive`} icon={Bot} tone="cyan" />
                    <Metric label="Security events" value={summary.total_events ?? totalActions} caption={`Last ${summary.hours ?? overviewHours} hours`} icon={Activity} tone="blue" />
                    <Metric label="Blocked actions" value={summary.blocked_actions ?? blocked} caption="Deterministic policy blocks" icon={ShieldAlert} tone="red" />
                    <Metric label="Awaiting approval" value={summary.pending_approvals ?? approvals.length} caption="Pending reviewer decisions" icon={Clock3} tone="amber" />
                  </section>
                  <div className="overview-severity-row" aria-label="Event severity counts">
                    {(["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).map((severity) => (
                      <span key={severity} className={`severity-count severity-${severity.toLowerCase()}`}>
                        <strong>{summary.severities?.[severity] ?? 0}</strong> {severity}
                      </span>
                    ))}
                    <button className="inline-link" onClick={() => setPage("monitoring")}>Investigate events <ArrowRight size={14} /></button>
                  </div>
                  <EventTrendChart events={summary.events_over_time ?? []} />
                </Panel>
                <section className="command-hero">
                  <div className="hero-copy">
                    <div className="hero-overline"><span className="status-pulse" /> LIVE SECURITY POSTURE <span className="hero-overline-line" /></div>
                    <h2>Your agents.<br /><em>Under control.</em></h2>
                    <p>Every action evaluated. Every decision governed. One deterministic security layer between AI and impact.</p>
                    <div className="hero-actions">
                      <button className="button-primary" onClick={() => { setShieldPulseKey((value) => value + 1); setNotice("VISUALIZATION DEMO — shield interaction only; no agent action or API request was performed."); }}>
                        <Zap size={16} /> Test shield response
                      </button>
                      <button className="button-quiet" onClick={() => setPage("monitoring")}>Open event stream <ArrowRight size={15} /></button>
                    </div>
                    <span className="demo-caption"><span /> VISUAL DEMO · NO SECURITY DATA IS GENERATED</span>
                  </div>
                  <div className="hero-emblem">
                    <ShieldVisual
                      mode={shieldMode}
                      pulseKey={shieldPulseKey}
                      reducedMotion={reducedMotion}
                      onActivate={() => setShieldPulseKey((value) => value + 1)}
                    />
                    <div className={`hero-status-pill hero-status-${shieldMode}`}>
                      <span className="status-pulse" /><div>
                        <strong>{securityLabel[shieldMode]}</strong>
                        <small>{securityExplanation}</small>
                      </div>
                    </div>
                  </div>
                  <div className="hero-corner hero-corner-top" /><div className="hero-corner hero-corner-bottom" />
                  <div className="hero-coordinate">AS / SECURE CORE / 01</div>
                </section>

                <section className="telemetry-grid" aria-label="AI risk and measured latency">
                  <TelemetryInstrument
                    label="Behavioral risk signal"
                    value={riskTelemetryValue >= 0 ? riskTelemetryValue : null}
                    caption="Highest recent Isolation Forest score · advisory only"
                    icon={Radio}
                    tone="violet"
                    display={riskTelemetryValue >= 0 ? percent(riskTelemetryValue) : undefined}
                    testId="risk-telemetry"
                  />
                  <TelemetryInstrument
                    label="Decision latency"
                    value={null}
                    caption="Mean measured gateway latency from the latest benchmark"
                    icon={Zap}
                    tone="cyan"
                    display={measuredLatency !== null
                      ? `${measuredLatency.toFixed(2)} ms`
                      : undefined}
                    testId="latency-telemetry"
                  />
                </section>

                <section className="metric-grid" aria-label="Live security metrics">
                  <Metric label="Evaluated" value={totalActions} caption="Persisted audit events" icon={Activity} tone="cyan" />
                  <Metric label="Allowed" value={allowed} caption="Deterministic policy ALLOW" icon={CheckCircle2} tone="green" />
                  <Metric label="Blocked" value={blocked} caption="Policy deny decisions" icon={ShieldAlert} tone="red" />
                  <Metric label="Pending review" value={approvals.length} caption="Awaiting human approval" icon={Clock3} tone="amber" />
                  <Metric label="Sandboxed" value={sandboxed} caption="Isolated policy route" icon={Database} tone="violet" />
                </section>

                <section className="section-block">
                  <SectionTitle kicker="TRUST BOUNDARY" title="Agent-to-resource security flow" aside={<span className="data-origin"><span /> Live identities + YAML policy resources</span>} />
                  <SecurityFlow
                    agents={agents}
                    resources={resourceNames}
                    selectedNode={selectedNode}
                    onSelect={setSelectedNode}
                  />
                </section>

                <section className="overview-lower">
                  <Panel title="Recent security activity" kicker="LIVE AUDIT TELEMETRY" aside={<button className="inline-link" onClick={() => setPage("monitoring")}>View all <ArrowRight size={14} /></button>}>
                    <ActivityTimeline audits={audits.slice(0, 6)} />
                  </Panel>
                  <Panel title="Risk & review signals" kicker="HUMAN + ML OVERSIGHT" aside={<button className="inline-link" onClick={() => setPage("anomalies")}>Signals <ArrowRight size={14} /></button>}>
                    <div className="signal-stack">
                      <div className="signal-card"><div className="signal-icon signal-amber"><Clock3 size={17} /></div><div><span>PENDING APPROVALS</span><strong>{approvals.length}</strong><small>{approvals.length ? "Reviewer action required" : "No requests waiting"}</small></div><button onClick={() => setPage("approvals")} aria-label="Open approvals"><ArrowUpRight size={16} /></button></div>
                      <div className="signal-card"><div className="signal-icon signal-violet"><TriangleAlert size={17} /></div><div><span>ADVISORY ANOMALIES</span><strong>{summary.recent_anomalies.length}</strong><small>Isolation Forest · never final authority</small></div><button onClick={() => setPage("anomalies")} aria-label="Open anomaly signals"><ArrowUpRight size={16} /></button></div>
                    </div>
                    <div className="mini-benchmark">
                      <div className="mini-benchmark-head"><span className="signal-icon signal-cyan"><Target size={16} /></span><div><span>ATTACK BENCHMARK</span><small>{benchmarkStats ? `${benchmarkStats.attack_requests} synthetic attack requests` : "No run loaded in this session"}</small></div><button onClick={() => setPage("benchmark")} aria-label="Open benchmark"><ArrowUpRight size={16} /></button></div>
                      {benchmarkStats ? (
                        <div className="benchmark-mini-values"><div><strong>{percent(benchmarkStats.attack_prevention_rate)}</strong><small>Prevented</small></div><div><strong>{percent(benchmarkStats.false_positive_rate)}</strong><small>False positive</small></div><div><strong>{benchmarkStats.f1_score.toFixed(2)}</strong><small>F1 score</small></div></div>
                      ) : <p className="empty-note">Run the isolated benchmark to calculate current metrics.</p>}
                    </div>
                  </Panel>
                </section>
              </>
            )}

            {page === "monitoring" && (
              <Panel title="Live security monitoring" kicker="AUDIT EVENT STREAM" aside={<span className="refresh-label"><span className={`status-pulse${streamConnected ? "" : " status-pulse-error"}`} /> {streamConnected ? "WebSocket live" : preferences.auto_refresh ? `Polling fallback · ${preferences.refresh_seconds}s` : "Polling paused · refresh manually"}</span>}>
                <AuditFilters
                  agents={agents}
                  search={search}
                  filterAgent={filterAgent}
                  filterDecision={filterDecision}
                  filterAction={filterAction}
                  filterDate={filterDate}
                  onSearch={setSearch}
                  onAgent={setFilterAgent}
                  onDecision={setFilterDecision}
                  onAction={setFilterAction}
                  onDate={setFilterDate}
                  onClear={() => { setSearch(""); setFilterAgent(""); setFilterDecision(""); setFilterAction(""); setFilterDate(""); }}
                />
                <AuditTable rows={filteredAudits} />
              </Panel>
            )}

            {page === "audit" && (
              <>
                <div className="page-intro"><div><span className="eyebrow">TAMPER-EVIDENT SECURITY TRAIL</span><h2>Audit logs</h2><p>Reviewer-protected decisions with SHA-256 chain metadata. Verification detects changes to stored records.</p></div><div className="records-chip"><Activity size={14} /> {filteredAudits.length} / {audits.length} events</div></div>
                <Panel title="Chain integrity" kicker="AUDIT RECORD VERIFICATION" aside={<button className="inline-link" onClick={() => void verifyAuditChain()} disabled={integrityBusy}>{integrityBusy ? "Verifying…" : "Verify chain"} <RefreshCw size={13} /></button>}>
                  {auditIntegrity ? (
                    <div className="integrity-summary" role="status">
                      <DecisionBadge decision={auditIntegrity.verified ? "VERIFIED" : "TAMPERED"} />
                      <span>{auditIntegrity.verified
                        ? `${auditIntegrity.records_checked} audit record${auditIntegrity.records_checked === 1 ? "" : "s"} verified`
                        : `First invalid record: #${auditIntegrity.first_invalid_id ?? "unknown"}`}</span>
                    </div>
                  ) : <EmptyState>Run verification to validate the stored audit chain.</EmptyState>}
                </Panel>
                <Panel title="Decision ledger" kicker="LATEST 100 API RECORDS">
                  <AuditFilters
                    agents={agents}
                    search={search}
                    filterAgent={filterAgent}
                    filterDecision={filterDecision}
                    filterAction={filterAction}
                    filterDate={filterDate}
                    onSearch={setSearch}
                    onAgent={setFilterAgent}
                    onDecision={setFilterDecision}
                    onAction={setFilterAction}
                    onDate={setFilterDate}
                    onClear={() => { setSearch(""); setFilterAgent(""); setFilterDecision(""); setFilterAction(""); setFilterDate(""); }}
                  />
                  <AuditTable rows={filteredAudits} />
                </Panel>
              </>
            )}

            {page === "approvals" && (
              <>
                <div className="page-intro"><div><span className="eyebrow">HUMAN-IN-THE-LOOP GOVERNANCE</span><h2>Review with intent.</h2><p>Approvals are bound to a specific pending request and can only be decided once.</p></div><span className="records-chip amber-chip"><Clock3 size={14} /> {approvals.length} pending</span></div>
                <section className="metric-grid metric-grid-four">
                  <Metric label="Awaiting review" value={approvals.length} caption="Unique pending requests" icon={Clock3} tone="amber" />
                  <Metric label="Reviewed" value={approvalHistory.length} caption="Latest 100 decisions" icon={FileCheck2} tone="cyan" />
                  <Metric label="Approved" value={approvalHistory.filter((item) => ["APPROVED", "EXECUTED"].includes(item.status)).length} caption="Reviewer-authorized" icon={CheckCircle2} tone="green" />
                  <Metric label="Rejected" value={approvalHistory.filter((item) => ["REJECTED", "BLOCKED"].includes(item.status)).length} caption="No tool action performed" icon={ShieldAlert} tone="red" />
                </section>
                <Panel title="Pending requests" kicker="REVIEW QUEUE" aside={<span className="table-count">{approvals.length} OPEN</span>}>
                  {approvals.length === 0 ? <EmptyState>No pending approval requests.</EmptyState> : (
                    <div className="table-wrap"><table className="data-table"><thead><tr><th>Agent / tool</th><th>Requested action</th><th>Environment / reason</th><th>Decision</th></tr></thead>
                      <tbody>{approvals.map((item) => (
                        <tr key={item.id}>
                          <td><strong>{item.agent}</strong><small>{item.tool}</small></td>
                          <td>{item.action} · {item.resource}<small>{item.records.toLocaleString()} records</small></td>
                          <td>{item.environment}<small>{item.reason}</small></td>
                          <td><div className="table-actions"><button className="approve-button" disabled={busy} onClick={() => { setDecisionReason(""); setConfirmation({ kind: "approval", item, approved: true }); }}><Check size={14} /> Approve</button><button className="reject-button" disabled={busy} onClick={() => { setDecisionReason(""); setConfirmation({ kind: "approval", item, approved: false }); }}><X size={14} /> Reject</button></div></td>
                        </tr>
                      ))}</tbody>
                    </table></div>
                  )}
                </Panel>
                <Panel title="Decision history" kicker="REVIEWER ACTIONS" aside={<span className="table-count">LATEST {approvalHistory.length}</span>}>
                  {approvalHistory.length === 0 ? <EmptyState>No completed approval decisions.</EmptyState> : (
                    <div className="table-wrap"><table className="data-table"><thead><tr><th>Request</th><th>Action</th><th>Status</th><th>Reviewer</th><th>Reviewed</th></tr></thead>
                      <tbody>{approvalHistory.map((item) => <tr key={item.id}><td><strong>#{item.id}</strong><small>{item.agent}</small></td><td>{item.action} · {item.resource}<small>{item.reason}</small></td><td><DecisionBadge decision={item.status} /></td><td>{item.approved_by ?? "—"}</td><td>{item.reviewed_at ? formatTime(item.reviewed_at) : "—"}</td></tr>)}</tbody>
                    </table></div>
                  )}
                </Panel>
              </>
            )}

            {page === "agents" && (
              <>
                <div className="page-intro"><div><span className="eyebrow">REGISTERED IDENTITIES</span><h2>Agents under governance</h2><p>Identity state and permissions are resolved from the live agent registry and active policy rules.</p></div><div className="panel-aside"><span className="records-chip"><Bot size={14} /> {agents.length} identities</span>{role === "security_admin" && <button className="button-primary" onClick={() => setAgentFormOpen((open) => !open)}>{agentFormOpen ? "Close form" : "Register agent"}</button>}</div></div>
                {agentFormOpen && role === "security_admin" && (
                  <Panel title="Register controlled agent identity" kicker="ADMINISTRATOR ACTION">
                    <form className="management-form" onSubmit={(event) => void registerAgent(event)}>
                      <label className="field-label" htmlFor="agent-name">Agent identity</label>
                      <input id="agent-name" value={agentName} onChange={(event) => setAgentName(event.target.value)} minLength={3} maxLength={64} required />
                      <label className="field-label" htmlFor="agent-password">Initial agent password</label>
                      <input id="agent-password" type="password" autoComplete="new-password" value={agentPassword} onChange={(event) => setAgentPassword(event.target.value)} minLength={12} required />
                      <label className="field-label" htmlFor="agent-description">Description</label>
                      <input id="agent-description" value={agentDescription} onChange={(event) => setAgentDescription(event.target.value)} maxLength={500} />
                      <button className="button-primary" type="submit" disabled={agentBusy}>{agentBusy ? "Registering…" : "Create agent identity"}</button>
                      <small>The password is sent securely to the API, stored as a hash, and never shown after registration.</small>
                    </form>
                  </Panel>
                )}
                {agents.length === 0 ? <Panel title="Agent inventory" kicker="LIVE REGISTRY"><EmptyState>No registered agents were returned by the API.</EmptyState></Panel> : (
                  <section className="agent-grid">{agents.map((agent) => (
                    <Panel key={agent.name} title={agent.name} kicker="AGENT IDENTITY" aside={<div className="panel-aside"><DecisionBadge decision={agent.active ? "ACTIVE" : "INACTIVE"} />{role === "security_admin" && <button className="button-quiet" disabled={agentBusy} onClick={() => void setAgentActive(agent, !agent.active)}>{agent.active ? "Suspend" : "Reactivate"}</button>}</div>}>
                      <p className="agent-description">{agent.description ?? "No description provided."}</p>
                      <div className="agent-usage"><span><b>{agent.usage.total_actions}</b>evaluated</span><span><b>{agent.usage.blocked_actions}</b>blocked</span><span><b>{agent.usage.anomalies}</b>signals</span></div>
                      <p className="subheading">Policy permissions & constraints</p>
                      {agent.permissions.length === 0 ? <EmptyState>No YAML policy rules match this identity.</EmptyState> : agent.permissions.map((permission) => (
                        <div className="permission-row" key={permission.rule_id}>
                          <div><strong>{permission.action}</strong><small>{permission.tool} · {permission.resource} · {formatEnvironments(permission.environments)}</small></div>
                          <DecisionBadge decision={permission.decision} />
                          <small>{permission.max_records == null ? "No record cap" : `≤ ${permission.max_records.toLocaleString()} records`}{permission.rate_limit == null ? "" : ` · ${permission.rate_limit}/min`}</small>
                        </div>
                      ))}
                      <p className="last-seen">Last activity: {agent.last_seen ? formatTime(agent.last_seen) : "No recorded activity"}</p>
                    </Panel>
                  ))}</section>
                )}
              </>
            )}

            {page === "policies" && (
              <>
                <div className="page-intro"><div><span className="eyebrow">POLICY-AS-CODE · VERSION {policies?.version ?? "—"}</span><h2>Deterministic by design.</h2><p>Policy decides. Anomaly scores advise. No LLM is the final security authority.</p></div><span className="deny-chip"><LockKeyhole size={14} /> DENY BY DEFAULT</span></div>
                <div className="policy-callout"><span className="policy-callout-icon"><ShieldCheck size={19} /></span><div><strong>Unmatched requests are blocked</strong><p>Only configured rules may allow, sandbox, or request human approval. ML signals never override the deterministic decision.</p></div><DecisionBadge decision={policies?.default_decision ?? "BLOCK"} /></div>
                <Panel title="Active rule set" kicker="YAML POLICY CONFIGURATION" aside={<span className="table-count">{policies?.rules.length ?? 0} RULES</span>}>
                  {!policies ? <EmptyState>Policy configuration is unavailable.</EmptyState> : policies.rules.length === 0 ? <EmptyState>No active policy rules were returned.</EmptyState> : (
                    <div className="table-wrap"><table className="data-table"><thead><tr><th>Rule</th><th>Identity / tool</th><th>Action / resource</th><th>Environment</th><th>Constraints</th><th>Decision</th></tr></thead>
                      <tbody>{policies.rules.map((rule) => (
                        <tr key={rule.id}>
                          <td><strong>{rule.id}</strong><small>{rule.reason}</small></td>
                          <td>{formatMatch(rule.match.agent)}<small>{formatMatch(rule.match.tool)}</small></td>
                          <td>{formatMatch(rule.match.action)}<small>{formatMatch(rule.match.resource)}</small></td>
                          <td>{formatEnvironments(rule.match.environment)}</td>
                          <td>{rule.match.max_records != null ? `≤ ${Number(rule.match.max_records).toLocaleString()} records` : "No record cap"}{rule.rate_limit ? <small>{rule.rate_limit} requests/minute</small> : null}</td>
                          <td><DecisionBadge decision={rule.decision} /></td>
                        </tr>
                      ))}</tbody>
                    </table></div>
                  )}
                </Panel>
                {role === "security_admin" && policies && (
                  <Panel title="Policy authoring and dry run" kicker={`OPTIMISTIC VERSION CHECK · CURRENT ${policies.version}`}>
                    <label className="field-label" htmlFor="policy-document">Policy document (JSON)</label>
                    <textarea id="policy-document" className="policy-editor-textarea" value={policyDraft} onChange={(event) => setPolicyDraft(event.target.value)} spellCheck={false} rows={16} />
                    <button className="button-primary" type="button" disabled={policyBusy} onClick={() => void savePolicyDraft()}>{policyBusy ? "Saving…" : "Validate and publish new version"}</button>
                    <p className="muted-footnote">The server validates rule structure and conflicts, rejects stale versions, and records each accepted version. Publishing changes the active deterministic policy.</p>
                    <form className="management-form policy-dry-run" onSubmit={(event) => void testPolicyDraft(event)}>
                      <h3>Test a request against the active policy</h3>
                      <label className="field-label" htmlFor="policy-test-agent">Agent identity</label>
                      <input id="policy-test-agent" value={policyTest.agent} onChange={(event) => setPolicyTest({ ...policyTest, agent: event.target.value })} required />
                      <label className="field-label" htmlFor="policy-test-tool">Tool</label>
                      <input id="policy-test-tool" value={policyTest.tool} onChange={(event) => setPolicyTest({ ...policyTest, tool: event.target.value })} required />
                      <label className="field-label" htmlFor="policy-test-action">Action</label>
                      <input id="policy-test-action" value={policyTest.action} onChange={(event) => setPolicyTest({ ...policyTest, action: event.target.value })} required />
                      <label className="field-label" htmlFor="policy-test-resource">Resource</label>
                      <input id="policy-test-resource" value={policyTest.resource} onChange={(event) => setPolicyTest({ ...policyTest, resource: event.target.value })} required />
                      <button className="button-quiet" type="submit">Dry-run request (no execution)</button>
                    </form>
                    {policyTestResult && <pre className="policy-test-result">{policyTestResult}</pre>}
                  </Panel>
                )}
                <Panel title="Version history" kicker="PERSISTED POLICY CHANGES" aside={<span className="table-count">{policyHistory.length} VERSIONS</span>}>
                  {policyHistory.length === 0 ? <EmptyState>No persisted policy versions were returned.</EmptyState> : (
                    <div className="table-wrap"><table className="data-table"><thead><tr><th>Version</th><th>Changed by</th><th>Timestamp</th></tr></thead>
                      <tbody>{policyHistory.map((version) => <tr key={version.version}><td><strong>v{version.version}</strong></td><td>{version.changed_by}</td><td>{formatTime(version.changed_at)}</td></tr>)}</tbody>
                    </table></div>
                  )}
                </Panel>
              </>
            )}

            {page === "anomalies" && (
              <>
                <div className="page-intro"><div><span className="eyebrow">BEHAVIORAL RISK OBSERVABILITY</span><h2>Signals, not verdicts.</h2><p>Isolation Forest observations provide context to reviewers; they do not authorize or deny any action.</p></div><span className="advisory-tag"><TriangleAlert size={14} /> ADVISORY ONLY</span></div>
                <div className="advisory-banner"><CircleHelp size={19} /><div><strong>Deterministic policy remains the final authority.</strong><small>An unusual behavior score is a prompt for investigation—not proof that an action is malicious.</small></div></div>
                <Panel title="Recent anomaly signals" kicker="ISOLATION FOREST · ADVISORY" aside={<span className="records-chip violet-chip">{summary.recent_anomalies.length} signals</span>}>
                  {anomalyEvaluation && (
                    <section className="anomaly-evaluation" aria-label="Anomaly model evaluation">
                      <div><span className="eyebrow">REPRODUCIBLE SYNTHETIC HOLDOUT</span><strong>{anomalyEvaluation.available ? "Model evaluation available" : "Evaluation unavailable"}</strong><small>{anomalyEvaluation.available ? `${anomalyEvaluation.training_benign} training samples · ${anomalyEvaluation.test_attacks} attack / ${anomalyEvaluation.test_benign} benign holdout samples` : anomalyEvaluation.reason}</small></div>
                      {anomalyEvaluation.available && <div className="anomaly-evaluation-metrics">
                        <span><b>{percent(anomalyEvaluation.precision ?? 0)}</b>Precision</span>
                        <span><b>{percent(anomalyEvaluation.recall ?? 0)}</b>Recall</span>
                        <span><b>{(anomalyEvaluation.f1_score ?? 0).toFixed(3)}</b>F1</span>
                        <span><b>{percent(anomalyEvaluation.false_positive_rate ?? 0)}</b>False positive</span>
                        <span><b>{(anomalyEvaluation.mean_detection_latency_ms ?? 0).toFixed(3)} ms</b>Mean scoring latency</span>
                      </div>}
                      {anomalyEvaluation.limitations && <small className="muted-footnote">{anomalyEvaluation.limitations}</small>}
                    </section>
                  )}
                  {summary.recent_anomalies.length === 0 ? <EmptyState>No anomaly events were reported in the available audit window.</EmptyState> : (
                    <div className="anomaly-grid">{summary.recent_anomalies.map((item) => {
                      const score = item.risk_score;
                      return <article className="anomaly-card" key={item.id}>
                        <div className="anomaly-card-top"><span className="signal-icon signal-violet"><TriangleAlert size={17} /></span><DecisionBadge decision={item.decision} /><time>{formatTime(item.timestamp)}</time></div>
                        <h3>{item.agent}</h3><p>{item.action} · deterministic outcome shown separately</p>
                        <div className="risk-row"><div className="risk-track"><motion.span initial={false} animate={{ width: `${Math.min((score ?? 0) * 100, 100)}%` }} transition={transition} /></div><b>{score === null ? "Awaiting telemetry" : percent(score)}</b></div>
                        <small>Behavioral risk score · not an enforcement decision</small>
                      </article>;
                    })}</div>
                  )}
                  {anomalyMaximum > 0 && <p className="muted-footnote">Highest recent advisory risk signal: {percent(anomalyMaximum)}</p>}
                </Panel>
              </>
            )}

            {page === "benchmark" && (
              <>
                <div className="page-intro benchmark-page-heading"><div><span className="eyebrow">CONTROLLED ADVERSARIAL EVALUATION</span><h2>Measure the boundary.</h2><p>Runs the deterministic gateway against synthetic scenarios; action executors are mocked and external systems are not called.</p></div><button className="button-primary" disabled={benchmarkBusy} onClick={() => setConfirmation({ kind: "benchmark" })}>{benchmarkBusy ? <span className="button-spinner" /> : <Target size={16} />}{benchmarkBusy ? "Running benchmark…" : "Run isolated benchmark"}</button></div>
                {!benchmark ? <Panel title="No benchmark loaded" kicker="ATTACK SIMULATION"><EmptyState>Run the benchmark to calculate current attack prevention, false-positive, and decision metrics. No sample statistics are displayed.</EmptyState></Panel> : (
                  <>
                    <section className="metric-grid metric-grid-four">
                      <Metric label="Attack prevention" value={percent(benchmarkStats?.attack_prevention_rate ?? 0)} caption="Attack requests not ALLOWed" icon={ShieldCheck} tone="green" />
                      <Metric label="Attack success" value={percent(benchmarkStats?.attack_success_rate ?? 0)} caption="Requests receiving ALLOW" icon={ShieldAlert} tone="red" />
                      <Metric label="False-positive rate" value={percent(benchmarkStats?.false_positive_rate ?? 0)} caption="Legitimate requests blocked" icon={CircleAlert} tone="amber" />
                      <Metric label="Legitimate acceptance" value={percent(benchmarkStats?.legitimate_action_acceptance_rate ?? 0)} caption="Allowed, sandboxed, or approval" icon={CheckCircle2} tone="cyan" />
                    </section>
                    <section className="metric-grid metric-grid-four">
                      <Metric label="Precision" value={percent(benchmarkStats?.precision ?? 0)} caption="Blocked requests that were attacks" icon={CrosshairIcon} tone="cyan" />
                      <Metric label="Recall" value={percent(benchmarkStats?.recall ?? 0)} caption="Attacks detected as BLOCK" icon={Target} tone="violet" />
                      <Metric label="F1 score" value={(benchmarkStats?.f1_score ?? 0).toFixed(3)} caption="Precision / recall balance" icon={Gauge} tone="amber" />
                      <Metric label="Decision latency" value={measuredLatency === null ? "Awaiting telemetry" : `${measuredLatency.toFixed(2)} ms`} caption="Mean measured gateway latency" icon={Zap} tone="blue" />
                    </section>
                    <section className="overview-lower">
                      <Panel title="Decision distribution" kicker={`${benchmarkStats?.attack_requests} ATTACK + ${benchmarkStats?.legitimate_requests} LEGITIMATE REQUESTS`}>
                        <DecisionBars decisions={Object.fromEntries(Object.entries(benchmarkStats?.decision_distribution ?? {}).map(([key, value]) => [key, value.count]))} />
                      </Panel>
                      <Panel title="Baseline comparison" kicker="SIMULATED BASELINE VS PROTECTED GATEWAY"><BaselineChart baseline={benchmarkStats?.baseline_comparison ?? {}} /></Panel>
                    </section>
                    <Panel title="Scenario categories" kicker={`${benchmarkStats?.scenario_count} DETERMINISTIC SCENARIOS`} aside={<span className="records-chip">{benchmarkStats?.expected_scenario_mismatches} mismatches</span>}>
                      <div className="table-wrap"><table className="data-table"><thead><tr><th>Category</th><th>Scenarios</th><th>Requests</th><th>Attack ALLOW outcomes</th><th>Legitimate accepted</th></tr></thead>
                        <tbody>{Object.entries(benchmarkStats?.category_results ?? {}).map(([category, result]) => <tr key={category}><td><strong>{category.replaceAll("_", " ")}</strong></td><td>{result.scenarios}</td><td>{result.requests}</td><td>{result.successful_attack_requests}</td><td>{result.accepted_legitimate_requests}</td></tr>)}</tbody>
                      </table></div>
                    </Panel>
                    <Panel title="Scenario details" kicker="OBSERVED GATEWAY OUTCOMES">
                      <div className="table-wrap"><table className="data-table"><thead><tr><th>Scenario</th><th>Type</th><th>Agent / tool</th><th>Requested operation</th><th>Expected</th><th>Observed</th></tr></thead>
                        <tbody>{benchmark.scenarios.map((scenario) => <tr key={scenario.scenario_id}><td><strong>{scenario.scenario_id}</strong><small>{scenario.category.replaceAll("_", " ")}</small></td><td>{scenario.is_attack ? "Attack" : "Legitimate"}</td><td>{scenario.agent_identity}<small>{scenario.tool}</small></td><td>{scenario.action} · {scenario.resource}<small>{scenario.environment} · {scenario.records} records</small></td><td><DecisionBadge decision={scenario.expected_security_outcome} /></td><td>{scenario.observed_decisions.map((decision, index) => <DecisionBadge key={`${scenario.scenario_id}-${index}`} decision={decision} />)}</td></tr>)}</tbody>
                      </table></div>
                    </Panel>
                    <details className="methodology"><summary>Benchmark methodology and assumptions</summary><dl>{Object.entries(benchmark.methodology).map(([key, value]) => <div key={key}><dt>{key.replaceAll("_", " ")}</dt><dd>{value}</dd></div>)}</dl></details>
                  </>
                )}
                <Panel title="Persisted benchmark runs" kicker="DATABASE HISTORY" aside={<span className="table-count">{benchmarkRuns.length} RUNS</span>}>
                  {benchmarkRuns.length === 0 ? <EmptyState>No benchmark runs have been saved for this project.</EmptyState> : (
                    <div className="table-wrap"><table className="data-table"><thead><tr><th>Run</th><th>Started</th><th>Started by</th><th>Prevention</th><th>F1 score</th><th>Scenarios</th></tr></thead>
                      <tbody>{benchmarkRuns.map((run) => <tr key={run.run_id}><td><button className="inline-link" onClick={() => void api<Benchmark>(`/security/benchmark/runs/${run.run_id}`).then(setBenchmark).catch((reason: unknown) => setError(reason instanceof Error ? reason.message : "Could not load benchmark run"))}>#{run.run_id}</button></td><td>{formatTime(run.started_at)}</td><td>{run.actor}</td><td>{percent(run.summary.attack_prevention_rate)}</td><td>{run.summary.f1_score.toFixed(3)}</td><td>{run.summary.scenario_count}</td></tr>)}</tbody>
                    </table></div>
                  )}
                </Panel>
              </>
            )}

            {page === "settings" && (
              <>
                <div className="settings-hero">
                  <div className="settings-hero-orb"><Settings2 size={24} /></div>
                  <div><span className="eyebrow">PERSONALIZE YOUR CONSOLE</span><h2>Settings that stick.</h2><p>Preferences sync to your signed-in account and apply across the live dashboard.</p></div>
                  <div className={`settings-save-indicator ${preferencesDirty ? "is-dirty" : "is-saved"}`}><span />{preferencesSaving ? "SAVING" : !preferencesLoaded ? "LOADING" : preferencesDirty ? "UNSAVED CHANGES" : "ALL CHANGES SAVED"}</div>
                </div>
                <div className="settings-grid">
                  <Panel title="Display & motion" kicker="ACCESSIBILITY">
                    <SettingRow icon={Sparkles} title="Interface motion" description="Turn dashboard animations on or off. Your system's reduced-motion preference is always respected." control={<button className={`toggle ${preferences.animations_enabled ? "toggle-on" : ""}`} role="switch" aria-label="Interface motion" aria-checked={preferences.animations_enabled} disabled={!preferencesLoaded || preferencesSaving} onClick={() => changePreference("animations_enabled", !preferences.animations_enabled)}><span /></button>} />
                    <SettingRow icon={LayoutDashboard} title="Compact density" description="Reduce card and table spacing to fit more security data on screen." control={<button className={`toggle ${preferences.compact_mode ? "toggle-on" : ""}`} role="switch" aria-label="Compact density" aria-checked={preferences.compact_mode} disabled={!preferencesLoaded || preferencesSaving} onClick={() => changePreference("compact_mode", !preferences.compact_mode)}><span /></button>} />
                  </Panel>
                  <Panel title="Monitoring behavior" kicker="LIVE DATA">
                    <SettingRow icon={RefreshCw} title="Automatic refresh" description="Poll the gateway in the background. Live WebSocket events remain enabled independently." control={<button className={`toggle ${preferences.auto_refresh ? "toggle-on" : ""}`} role="switch" aria-label="Automatic refresh" aria-checked={preferences.auto_refresh} disabled={!preferencesLoaded || preferencesSaving} onClick={() => changePreference("auto_refresh", !preferences.auto_refresh)}><span /></button>} />
                    <SettingRow icon={Timer} title="Refresh interval" description="How frequently the dashboard requests a full data refresh when automatic refresh is enabled." control={<select aria-label="Telemetry refresh" className="setting-select" value={preferences.refresh_seconds} disabled={!preferencesLoaded || preferencesSaving || !preferences.auto_refresh} onChange={(event) => changePreference("refresh_seconds", Number(event.target.value) as DashboardPreferences["refresh_seconds"])}><option value={15}>15 seconds</option><option value={30}>30 seconds</option><option value={60}>60 seconds</option></select>} />
                  </Panel>
                  <Panel title="Security notifications" kicker="ALERT DELIVERY">
                    <SettingRow icon={Bell} title="In-app event notifications" description="Show incoming audit events in the notification menu and update the unread counter." control={<button className={`toggle ${preferences.notifications_enabled ? "toggle-on" : ""}`} role="switch" aria-label="In-app event notifications" aria-checked={preferences.notifications_enabled} disabled={!preferencesLoaded || preferencesSaving} onClick={() => changePreference("notifications_enabled", !preferences.notifications_enabled)}><span /></button>} />
                    <SettingRow icon={ShieldAlert} title="Critical events only" description="Filter the notification menu and unread counter to critical severity events." control={<button className={`toggle ${preferences.critical_notifications_only ? "toggle-on" : ""}`} role="switch" aria-label="Critical events only" aria-checked={preferences.critical_notifications_only} disabled={!preferencesLoaded || preferencesSaving || !preferences.notifications_enabled} onClick={() => changePreference("critical_notifications_only", !preferences.critical_notifications_only)}><span /></button>} />
                    <SettingRow icon={MonitorDot} title="Desktop notifications" description="Show browser notifications for new security events while this console is open. Browser permission is required." control={<button className={`toggle ${preferences.desktop_notifications ? "toggle-on" : ""}`} role="switch" aria-label="Desktop notifications" aria-checked={preferences.desktop_notifications} disabled={!preferencesLoaded || preferencesSaving || !preferences.notifications_enabled || typeof Notification === "undefined"} onClick={() => changePreference("desktop_notifications", !preferences.desktop_notifications)}><span /></button>} />
                    {typeof Notification !== "undefined" && preferences.desktop_notifications && Notification.permission === "denied" && <p className="settings-inline-warning">Notifications are blocked by the browser. Enable them in the site permissions before saving this preference.</p>}
                  </Panel>
                  <Panel title="Account & connection" kicker="SECURE CLIENT">
                    <SettingRow icon={Fingerprint} title="Authenticated account" description="Current identity and authorization role from the signed session." control={<span className="settings-value">{displayName} · {role.replace("_", " ")}</span>} />
                    <SettingRow icon={Network} title="API endpoint" description="Configured dashboard API base URL. Tokens and credentials are never displayed here." control={<code className="api-endpoint">{API_BASE}</code>} />
                    <SettingRow icon={LockKeyhole} title="Authentication" description="Bearer JWT, short-lived server-side validation, reviewer role required." control={<span className="connected-label"><span className="status-pulse" /> ACTIVE</span>} />
                  </Panel>
                </div>
                <div className="settings-actions">
                  <div className={preferencesMessage && !preferencesMessage.startsWith("Your") && !preferencesMessage.startsWith("Defaults selected") ? "settings-error" : "settings-feedback"} role="status">{preferencesMessage || (preferencesDirty ? "Your edits are not saved yet." : "Your preferences are synchronized with the server.")}</div>
                  <button className="button-quiet" disabled={!preferencesLoaded || preferencesSaving || !preferencesDirty} onClick={resetPreferences}>Reset defaults</button>
                  <button className="button-primary" disabled={!preferencesLoaded || preferencesSaving || !preferencesDirty} onClick={() => void savePreferences()}>{preferencesSaving ? <span className="button-spinner" /> : <Check size={16} />}{preferencesSaving ? "Saving settings…" : "Save changes"}</button>
                </div>
                <div className="settings-footnote"><CircleHelp size={15} /> These settings change your dashboard experience only. Policy enforcement, authentication, and security decisions remain server-side.</div>
              </>
            )}
          </motion.div>
        </AnimatePresence>

        <footer className="app-footer"><span>AGENTSHIELD <b>·</b> DETERMINISTIC POLICY IS AUTHORITATIVE <b>·</b> ML SIGNALS ARE ADVISORY</span><span>Last event: {audits[0] ? formatTime(audits[0].timestamp) : "No audit data returned"}</span></footer>
      </main>

      {confirmation && (
        <div className="modal-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget && !busy && !benchmarkBusy) setConfirmation(null); }}>
          {confirmation.kind === "approval" ? (
            <form className="confirm-modal" role="dialog" aria-modal="true" aria-labelledby="confirm-title" onSubmit={(event) => { event.preventDefault(); void submitDecision(confirmation.item, confirmation.approved); }}>
              <div className={`modal-icon ${confirmation.approved ? "modal-icon-green" : "modal-icon-red"}`}>{confirmation.approved ? <CheckCircle2 size={21} /> : <ShieldAlert size={21} />}</div>
              <button className="modal-close" type="button" onClick={() => setConfirmation(null)} aria-label="Close dialog"><X size={17} /></button>
              <span className="eyebrow">HUMAN APPROVAL · REQUEST #{confirmation.item.id}</span>
              <h2 id="confirm-title">{confirmation.approved ? "Approve this action?" : "Reject this action?"}</h2>
              <p className="modal-summary"><strong>{confirmation.item.agent}</strong> requested <strong>{confirmation.item.action}</strong> on <strong>{confirmation.item.resource}</strong> in {confirmation.item.environment}.</p>
              <div className="modal-request"><span>{confirmation.item.tool}</span><span>{confirmation.item.records.toLocaleString()} records</span></div>
              {!confirmation.approved && (
                <label className="field-label modal-reason" htmlFor="rejection-reason">Reason for rejection <span>REQUIRED</span>
                  <textarea id="rejection-reason" value={decisionReason} onChange={(event) => setDecisionReason(event.target.value)} maxLength={500} required placeholder="Explain why this request is rejected…" rows={3} />
                </label>
              )}
              <div className="modal-actions"><button type="button" className="button-quiet" onClick={() => setConfirmation(null)} disabled={busy}>Cancel</button><button type="submit" className={confirmation.approved ? "approve-button" : "reject-button"} disabled={busy || (!confirmation.approved && !decisionReason.trim())}>{busy ? "Submitting…" : confirmation.approved ? <><Check size={15} /> Confirm approval</> : <><X size={15} /> Confirm rejection</>}</button></div>
            </form>
          ) : (
            <div className="confirm-modal" role="dialog" aria-modal="true" aria-labelledby="benchmark-confirm-title">
              <div className="modal-icon modal-icon-cyan"><Target size={21} /></div>
              <button className="modal-close" onClick={() => setConfirmation(null)} aria-label="Close dialog"><X size={17} /></button>
              <span className="eyebrow">ISOLATED SYNTHETIC RUN</span>
              <h2 id="benchmark-confirm-title">Run the security benchmark?</h2>
              <p className="modal-summary">Scenarios execute against the actual AgentShield policy gateway using synthetic SQLite identities. Tool and sandbox executors are mocked; no production systems are called.</p>
              <div className="modal-actions"><button className="button-quiet" onClick={() => setConfirmation(null)}>Cancel</button><button className="button-primary" disabled={benchmarkBusy} onClick={() => void runBenchmark()}><Target size={15} /> Run isolated benchmark</button></div>
            </div>
          )}
        </div>
      )}
    </div>
    {awakeningVisible && <Awakening onSkip={() => setAwakeningVisible(false)} />}
    </>
  );
}

const CrosshairIcon = Target;

function TelemetryInstrument({
  label,
  value,
  display,
  caption,
  icon: Icon,
  tone,
  testId,
}: {
  label: string;
  value: number | null;
  display?: string;
  caption: string;
  icon: LucideIcon;
  tone: "cyan" | "violet";
  testId: string;
}) {
  const circumference = 163.36;
  const progress = value === null ? 0 : Math.min(Math.max(value, 0), 1);
  return (
    <article className={`telemetry-instrument telemetry-${tone}`} data-testid={testId}>
      <div className="telemetry-instrument-copy">
        <div className="metric-card-top"><span>{label}</span><Icon size={16} /></div>
        <p>{caption}</p>
        <small>{value === null ? "Awaiting telemetry" : "LIVE BACKEND TELEMETRY"}</small>
      </div>
      <div className={`telemetry-dial ${value === null ? "telemetry-dial-idle" : ""}`} aria-label={`${label}: ${display ?? "Awaiting telemetry"}`}>
        <svg viewBox="0 0 64 64" aria-hidden="true">
          <circle className="telemetry-dial-track" cx="32" cy="32" r="26" />
          {value !== null && (
            <motion.circle
              className="telemetry-dial-value"
              cx="32"
              cy="32"
              r="26"
              initial={{ strokeDashoffset: circumference }}
              animate={{ strokeDashoffset: circumference * (1 - progress) }}
              transition={{ duration: 0.8, ease: "easeOut" }}
              style={{ strokeDasharray: circumference }}
            />
          )}
          <circle className="telemetry-dial-inner" cx="32" cy="32" r="19" />
        </svg>
        <strong>{display ?? "—"}</strong>
      </div>
    </article>
  );
}

function Metric({
  label,
  value,
  caption,
  icon: Icon,
  tone,
}: {
  label: string;
  value: number | string;
  caption: string;
  icon: LucideIcon;
  tone: string;
}) {
  return (
    <motion.article className={`metric-card tone-${tone}`} whileHover={{ y: -3 }} transition={{ duration: 0.18 }}>
      <div className="metric-card-top"><span>{label}</span><Icon size={17} strokeWidth={1.7} /></div>
      <strong>{typeof value === "number" ? <AnimatedValue value={value} /> : value}</strong>
      <small>{caption}</small>
      <span className="metric-card-glow" />
    </motion.article>
  );
}

function EventTrendChart({ events }: { events: Array<{ date: string; count: number }> }) {
  const maximum = Math.max(0, ...events.map((event) => event.count));
  if (events.length === 0) {
    return <p className="muted-footnote">No persisted events in this selected time window.</p>;
  }
  return (
    <div className="event-trend" role="img" aria-label="Persisted security events over time">
      <span className="eyebrow">EVENTS OVER TIME</span>
      <div className="event-trend-bars">
        {events.map((event) => (
          <div className="event-trend-day" key={event.date} title={`${event.date}: ${event.count} events`}>
            <span className="event-trend-count">{event.count}</span>
            <span
              className="event-trend-bar"
              style={{ height: `${maximum ? Math.max(4, (event.count / maximum) * 100) : 0}%` }}
            />
            <small>{event.date.slice(5)}</small>
          </div>
        ))}
      </div>
    </div>
  );
}

function AnimatedValue({ value }: { value: number }) {
  const valueMotion = useMotionValue(value);
  const spring = useSpring(valueMotion, { stiffness: 120, damping: 24, mass: 0.7 });
  const formatted = useTransform(spring, (current) => Math.round(current).toLocaleString());
  useEffect(() => valueMotion.set(value), [value, valueMotion]);
  return <motion.span>{formatted}</motion.span>;
}

function Panel({
  title,
  kicker,
  aside,
  children,
}: {
  title: string;
  kicker: string;
  aside?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section className="panel">
      <div className="section-heading">
        <div><span className="eyebrow">{kicker}</span><h2>{title}</h2></div>
        {aside && <div className="panel-aside">{aside}</div>}
      </div>
      {children}
    </section>
  );
}

function SectionTitle({ kicker, title, aside }: { kicker: string; title: string; aside?: ReactNode }) {
  return <div className="section-title"><div><span className="eyebrow">{kicker}</span><h2>{title}</h2></div>{aside}</div>;
}

function SecurityFlow({
  agents,
  resources,
  selectedNode,
  onSelect,
}: {
  agents: Agent[];
  resources: string[];
  selectedNode: string;
  onSelect: (node: string) => void;
}) {
  const agentNodes = agents.slice(0, 4);
  const resourceNodes = resources.slice(0, 4);
  return (
    <div className="flow-panel">
      <div className="flow-column">
        <span className="flow-label">IDENTITIES <b>{agents.length}</b></span>
        <div className="flow-node-list">
          {agentNodes.length === 0 ? <span className="flow-empty">No registered agents returned</span> : agentNodes.map((agent) => (
            <button className={`flow-node agent-node ${selectedNode === agent.name ? "node-selected" : ""}`} key={agent.name} title={agent.description ?? agent.name} onClick={() => onSelect(agent.name)}>
              <span className="node-icon"><Bot size={16} /></span><span><strong>{agent.name}</strong><small>{agent.active ? "Active identity" : "Inactive identity"}</small></span><i className={agent.active ? "node-dot" : "node-dot node-dot-off"} />
            </button>
          ))}
        </div>
      </div>
      <div className="flow-connector" aria-hidden="true"><span /><i /><i /><i /></div>
      <button className={`gateway-node ${selectedNode === "gateway" ? "node-selected" : ""}`} onClick={() => onSelect("gateway")} title="Every action passes through deterministic, deny-by-default policy evaluation.">
        <span className="gateway-halo"><ShieldCheck size={23} /></span><strong>AgentShield</strong><small>POLICY GATEWAY</small><span className="gateway-state"><i /> ENFORCING</span>
      </button>
      <div className="flow-connector flow-connector-right" aria-hidden="true"><span /><i /><i /><i /></div>
      <div className="flow-column">
        <span className="flow-label">POLICY RESOURCES <b>{resources.length}</b></span>
        <div className="flow-node-list">
          {resourceNodes.length === 0 ? <span className="flow-empty">No named resources in active policy</span> : resourceNodes.map((resource) => (
            <button className={`flow-node resource-node ${selectedNode === resource ? "node-selected" : ""}`} key={resource} title="Configured resource from active policy rules" onClick={() => onSelect(resource)}>
              <span className="node-icon"><Database size={16} /></span><span><strong>{resource}</strong><small>Policy-protected resource</small></span><LockKeyhole size={14} className="resource-lock" />
            </button>
          ))}
        </div>
      </div>
      {selectedNode && <div className="flow-selection"><span className="selection-mark" /><span>Selected node: <strong>{selectedNode}</strong></span><button onClick={() => onSelect("")} aria-label="Clear selected node"><X size={14} /></button></div>}
      <div className="flow-disclaimer">Illustrative trust-boundary visualization · node labels come from API data</div>
    </div>
  );
}

function ActivityTimeline({ audits }: { audits: Audit[] }) {
  if (audits.length === 0) return <EmptyState>No audit events were returned by the security API.</EmptyState>;
  return (
    <div className="timeline">
      {audits.map((item, index) => (
        <article className="timeline-item" key={item.id}>
          <span className={`timeline-marker decision-dot-${item.decision.toLowerCase()}`}><i /></span>
          <div className="timeline-content"><div className="timeline-top"><strong>{item.agent}</strong><time>{formatTime(item.timestamp)}</time></div><p>{item.action} <span>on</span> {item.resource}<small>{item.tool} · {item.environment}</small></p></div>
          <DecisionBadge decision={item.decision} />
          {index < audits.length - 1 && <span className="timeline-line" />}
        </article>
      ))}
    </div>
  );
}

function AuditFilters({
  agents,
  search,
  filterAgent,
  filterDecision,
  filterAction,
  filterDate,
  onSearch,
  onAgent,
  onDecision,
  onAction,
  onDate,
  onClear,
}: {
  agents: Agent[];
  search: string;
  filterAgent: string;
  filterDecision: string;
  filterAction: string;
  filterDate: string;
  onSearch: (value: string) => void;
  onAgent: (value: string) => void;
  onDecision: (value: string) => void;
  onAction: (value: string) => void;
  onDate: (value: string) => void;
  onClear: () => void;
}) {
  return (
    <div className="filter-toolbar">
      <label className="filter-search"><Search size={16} /><input aria-label="Search audit events" placeholder="Search events…" value={search} onChange={(event) => onSearch(event.target.value)} /></label>
      <select aria-label="Filter by agent" value={filterAgent} onChange={(event) => onAgent(event.target.value)}><option value="">All agents</option>{agents.map((agent) => <option key={agent.name}>{agent.name}</option>)}</select>
      <select aria-label="Filter by decision" value={filterDecision} onChange={(event) => onDecision(event.target.value)}><option value="">All decisions</option>{["ALLOW", "BLOCK", "SANDBOX", "HUMAN_APPROVAL", "REJECTED"].map((item) => <option key={item}>{item}</option>)}</select>
      <input aria-label="Filter by action" placeholder="Action" value={filterAction} onChange={(event) => onAction(event.target.value)} />
      <input aria-label="Filter by date" type="date" value={filterDate} onChange={(event) => onDate(event.target.value)} />
      <button className="clear-filters" onClick={onClear}>Clear</button>
    </div>
  );
}

function AuditTable({ rows }: { rows: Audit[] }) {
  if (rows.length === 0) return <EmptyState>No audit events match the current view.</EmptyState>;
  return (
    <div className="table-wrap"><table className="data-table"><thead><tr><th>Decision</th><th>Agent / tool</th><th>Action / resource</th><th>Environment</th><th>Risk signal</th><th>Timestamp</th></tr></thead>
      <tbody>{rows.map((item) => (
        <tr key={item.id}>
          <td><DecisionBadge decision={item.decision} />{item.severity && <small className={`event-severity severity-${item.severity.toLowerCase()}`}>{item.severity}</small>}</td><td><strong>{item.agent}</strong><small>{item.tool}</small></td>
          <td>{item.action} · {item.resource}<small>{item.event_type ? `${item.event_type} · ` : ""}{item.reason}</small>{item.evidence && <small>Evidence: {item.evidence}</small>}</td><td>{item.environment}<small>{item.records.toLocaleString()} records</small>{item.event_hash && <small title={item.event_hash}>Audit hash linked</small>}</td>
          <td>{item.risk_score == null ? <span className="muted">Unavailable</span> : <span className="risk-value">{percent(item.risk_score)} · advisory</span>}{item.anomaly_detected && <span className="warning-icon"><TriangleAlert size={13} /></span>}</td>
          <td>{formatTime(item.timestamp)}</td>
        </tr>
      ))}</tbody>
    </table><span className="table-footnote">Anomaly values are advisory and do not determine policy outcomes.</span></div>
  );
}

function DecisionBadge({ decision }: { decision: string }) {
  return <span className={`decision-badge decision-${decision.toLowerCase()}`}><i />{decision.replaceAll("_", " ")}</span>;
}

function DecisionBars({ decisions }: { decisions: Record<string, number> }) {
  const entries = ["ALLOW", "BLOCK", "SANDBOX", "HUMAN_APPROVAL"].map((name) => [name, decisions[name] ?? 0] as const);
  const max = Math.max(1, ...entries.map(([, count]) => count));
  return <div className="decision-chart">{entries.map(([name, count]) => (
    <div className="decision-chart-row" key={name}><span className={`chart-label chart-label-${name.toLowerCase()}`}>{name.replace("_", " ")}</span><div className="chart-track"><motion.i initial={{ width: 0 }} animate={{ width: `${(count / max) * 100}%` }} transition={{ duration: 0.75, ease: "easeOut" }} className={`chart-fill fill-${name.toLowerCase()}`} /></div><b>{count.toLocaleString()}</b></div>
  ))}</div>;
}

function BaselineChart({
  baseline,
}: {
  baseline: Record<string, { attack_requests: number; successful_attack_requests: number; attack_success_rate: number }>;
}) {
  const rows = [
    ["Simulated unprotected agent", baseline.unprotected_agent],
    ["AgentShield protected", baseline.agentshield_protected],
  ] as const;
  if (!rows[0][1] || !rows[1][1]) return <EmptyState>Baseline comparison is not available.</EmptyState>;
  return <div className="baseline-chart">{rows.map(([label, data]) => (
    <div className="baseline-row" key={label}><div><strong>{label}</strong><span>{data.successful_attack_requests} / {data.attack_requests} successful attack requests</span></div><div className="chart-track"><motion.i initial={{ width: 0 }} animate={{ width: `${data.attack_success_rate * 100}%` }} transition={{ duration: 0.7 }} className={`chart-fill ${label.startsWith("Simulated") ? "fill-block" : "fill-allow"}`} /></div><b>{percent(data.attack_success_rate)}</b></div>
  ))}<p className="table-footnote">Unprotected baseline is a stated simulation assumption, not a separately executed agent.</p></div>;
}

function SettingRow({
  icon: Icon,
  title,
  description,
  control,
}: {
  icon: LucideIcon;
  title: string;
  description: string;
  control: ReactNode;
}) {
  return <div className="setting-row"><span className="setting-icon"><Icon size={17} /></span><div className="setting-copy"><strong>{title}</strong><small>{description}</small></div><div className="setting-control">{control}</div></div>;
}

function EmptyState({ children }: { children: ReactNode }) {
  return <div className="empty-state"><span className="empty-state-mark"><Activity size={17} /></span><p>{children}</p></div>;
}

function formatTime(value: string) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function formatEnvironments(environments: unknown) {
  if (Array.isArray(environments)) return environments.map(String).join(", ");
  return typeof environments === "string" ? environments : "*";
}

function formatMatch(value: unknown) {
  if (Array.isArray(value)) return value.map(String).join(", ");
  return typeof value === "string" || typeof value === "number" ? String(value) : "*";
}

function percent(value: number) {
  return `${(value * 100).toFixed(1)}%`;
}
