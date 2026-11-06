from security.policy_engine import check_action_policy
from database.database import SessionLocal
from database.models import ApprovalRequest


_SIMULATED_TOOLS = {
    ("customer", "read"): "Customer read was simulated; no customer system was contacted.",
    ("customer", "update"): "Customer update was simulated; no customer data was changed.",
    ("customer", "export"): "Customer export was simulated; no customer data was exported.",
    ("customer", "delete"): "Customer deletion was simulated; no customer data was deleted.",
    ("demo", "preview"): "Demo preview was simulated.",
}


def execute_action(request, approval_id=None):
    authorization = check_action_policy(
        request.agent,
        request.resource,
        request.action,
        request.environment,
        request.records,
        tool=request.tool,
    )
    if authorization["decision"] == "HUMAN_APPROVAL" and approval_id is not None:
        db = SessionLocal()
        try:
            approval = db.query(ApprovalRequest).filter(
                ApprovalRequest.id == approval_id,
                ApprovalRequest.status == "EXECUTING",
                ApprovalRequest.agent == request.agent,
                ApprovalRequest.user == request.user,
                ApprovalRequest.tool == request.tool,
                ApprovalRequest.action == request.action,
                ApprovalRequest.resource == request.resource,
                ApprovalRequest.environment == request.environment,
                ApprovalRequest.records == request.records,
            ).first()
            if not approval or not approval.approved_by:
                raise PermissionError("Approval is not valid for this action")
        finally:
            db.close()
        authorization = check_action_policy(
            request.agent,
            request.resource,
            request.action,
            request.environment,
            request.records,
            ignore_approval=True,
            tool=request.tool,
        )
    if authorization["decision"] != "ALLOW":
        raise PermissionError(
            "Tool dispatch requires a matching deterministic ALLOW policy"
        )

    message = _SIMULATED_TOOLS.get(
        (request.resource, request.action.lower())
    )
    if message is None:
        raise PermissionError("No tool is registered for this action")

    return {
        "status": "SIMULATED",
        "message": message,
        "executed": False
    }