from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from app.core.auth import verify_admin_api_key
from app.policy.engine import policy_engine
from app.storage.repository import AuditRepository

router = APIRouter(prefix="/admin", tags=["Admin & Telemetry API"])


class TestInspectionRequest(BaseModel):
    prompt: str


@router.get("/metrics")
async def get_metrics(admin_key: str = Depends(verify_admin_api_key)):
    """Retrieve aggregate security gateway statistics and threat breakdown."""
    return await AuditRepository.get_metrics_summary()


@router.get("/logs")
async def get_audit_logs(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    action: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    admin_key: str = Depends(verify_admin_api_key),
):
    """Retrieve paginated audit logs with action filters and search."""
    logs = await AuditRepository.get_recent_logs(
        limit=limit,
        offset=offset,
        action=action,
        search=search,
    )
    return {"logs": logs, "count": len(logs), "limit": limit, "offset": offset}


@router.get("/logs/{incident_id}")
async def get_log_detail(incident_id: str, admin_key: str = Depends(verify_admin_api_key)):
    """Retrieve full forensic trace and raw payload for a specific incident."""
    log = await AuditRepository.get_log_by_id(incident_id)
    if not log:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident ID not found.")
    return log


@router.get("/policy")
async def get_active_policy(admin_key: str = Depends(verify_admin_api_key)):
    """View active policy schema and runtime inspector configurations."""
    return {
        "policy_file": str(policy_engine.policy_path),
        "policy": policy_engine.policy.model_dump(),
        "active_inspectors": list(policy_engine.inspectors.keys()),
    }


@router.post("/policy/reload")
async def reload_policy(admin_key: str = Depends(verify_admin_api_key)):
    """Hot-reload policy YAML file into memory."""
    policy_engine.reload_policy()
    return {
        "status": "success",
        "message": "Policy reloaded successfully.",
        "inspectors": list(policy_engine.inspectors.keys()),
    }


@router.post("/test-inspect")
async def test_inspect_prompt(
    payload: TestInspectionRequest,
    admin_key: str = Depends(verify_admin_api_key),
):
    """Live interactive testing endpoint for security playground in dashboard."""
    decision = await policy_engine.evaluate_request(payload.prompt)
    return {
        "action": decision.action,
        "passed": decision.passed,
        "risk_score": round(decision.risk_score, 3),
        "sanitized_text": decision.sanitized_text,
        "violations": [v.model_dump() for v in decision.violations],
        "inspector_results": decision.inspector_results,
        "execution_time_ms": round(decision.execution_time_ms, 2),
    }
