from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    model_validator,
)
from typing import Annotated, Any, Literal


class ActionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    user: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    tool: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    action: Annotated[str, StringConstraints(min_length=1, max_length=64)]
    resource: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    environment: Annotated[str, StringConstraints(min_length=1, max_length=64)]
    records: int = Field(default=0, ge=0)


class ApprovalDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    approval_id: int
    approved: bool
    rejection_reason: str | None = Field(default=None, max_length=500)

    @model_validator(mode="after")
    def require_rejection_reason(self) -> "ApprovalDecision":
        if not self.approved and not (self.rejection_reason or "").strip():
            raise ValueError("A rejection reason is required")
        return self


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    password: Annotated[str, StringConstraints(min_length=1, max_length=72)]


class AgentSimulationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    actions: list[ActionRequest] = Field(min_length=1, max_length=20)


class SecurityEventSubmission(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_type: Literal[
        "agent_action",
        "unauthorized_tool_invocation",
        "unusual_api_request",
        "privilege_escalation_attempt",
        "prompt_injection_indicator",
        "suspicious_agent_behavior",
        "excessive_action_frequency",
        "sensitive_data_access_attempt",
        "policy_violation",
        "repeated_authentication_failure",
        "unexpected_identity_or_permissions",
    ]
    tool: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    action: Annotated[str, StringConstraints(min_length=1, max_length=64)]
    resource: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    environment: Annotated[str, StringConstraints(min_length=1, max_length=64)]
    records: int = Field(default=0, ge=0)
    evidence: str | None = Field(default=None, max_length=2000)


class AgentRegistration(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: Annotated[
        str,
        StringConstraints(
            min_length=2,
            max_length=64,
            pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$",
        ),
    ]
    password: Annotated[str, StringConstraints(min_length=12, max_length=72)]
    description: str | None = Field(default=None, max_length=500)


class AgentStatusUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    active: bool


class PolicyDocumentUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_version: int = Field(ge=1)
    default_decision: Literal["BLOCK"]
    required_subject_roles: list[
        Annotated[str, StringConstraints(min_length=1, max_length=64)]
    ] = Field(min_length=1, max_length=20)
    rules: list[dict[str, Any]] = Field(max_length=200)


class DashboardPreferences(BaseModel):
    model_config = ConfigDict(extra="forbid")

    animations_enabled: bool = True
    refresh_seconds: Literal[15, 30, 60] = 15
    auto_refresh: bool = True
    compact_mode: bool = False
    notifications_enabled: bool = True
    critical_notifications_only: bool = False
    desktop_notifications: bool = False