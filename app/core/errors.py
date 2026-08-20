from typing import Any, Dict, List, Optional
from fastapi import Request, status
from fastapi.responses import JSONResponse


class SecurityPolicyViolationException(Exception):
    """Raised when an incoming or outgoing request violates security policies."""

    def __init__(
        self,
        detail: str,
        incident_id: str,
        risk_score: float,
        violations: List[Dict[str, Any]],
        status_code: int = status.HTTP_400_BAD_REQUEST,
    ):
        self.detail = detail
        self.incident_id = incident_id
        self.risk_score = risk_score
        self.violations = violations
        self.status_code = status_code
        super().__init__(detail)


class RateLimitExceededException(Exception):
    """Raised when a client exceeds the sliding window request rate limit."""

    def __init__(self, detail: str = "Rate limit exceeded. Please retry later.", retry_after: int = 60):
        self.detail = detail
        self.retry_after = retry_after
        self.status_code = status.HTTP_429_TOO_MANY_REQUESTS
        super().__init__(detail)


class UnauthorizedException(Exception):
    """Raised when missing or invalid API key is provided."""

    def __init__(self, detail: str = "Invalid or missing Gateway API key."):
        self.detail = detail
        self.status_code = status.HTTP_401_UNAUTHORIZED
        super().__init__(detail)


class UpstreamProviderException(Exception):
    """Raised when upstream LLM fails, times out, or returns error."""

    def __init__(self, detail: str, upstream_status_code: Optional[int] = None):
        self.detail = detail
        self.upstream_status_code = upstream_status_code
        self.status_code = status.HTTP_502_BAD_GATEWAY
        super().__init__(detail)


async def security_policy_violation_handler(request: Request, exc: SecurityPolicyViolationException):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": {
                "type": "security_policy_violation",
                "message": exc.detail,
                "incident_id": exc.incident_id,
                "risk_score": round(exc.risk_score, 3),
                "violations": exc.violations,
            }
        },
    )


async def rate_limit_handler(request: Request, exc: RateLimitExceededException):
    return JSONResponse(
        status_code=exc.status_code,
        headers={"Retry-After": str(exc.retry_after)},
        content={
            "error": {
                "type": "rate_limit_exceeded",
                "message": exc.detail,
                "retry_after_seconds": exc.retry_after,
            }
        },
    )


async def unauthorized_handler(request: Request, exc: UnauthorizedException):
    return JSONResponse(
        status_code=exc.status_code,
        headers={"WWW-Authenticate": "Bearer"},
        content={
            "error": {
                "type": "authentication_error",
                "message": exc.detail,
            }
        },
    )


async def upstream_provider_handler(request: Request, exc: UpstreamProviderException):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": {
                "type": "upstream_provider_error",
                "message": exc.detail,
                "upstream_status_code": exc.upstream_status_code,
            }
        },
    )
