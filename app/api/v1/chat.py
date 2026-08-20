import asyncio
import time
import uuid
from typing import Any, Dict, List, Optional, Union
from fastapi import APIRouter, Depends, Header, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from app.core.auth import verify_client_api_key
from app.core.errors import SecurityPolicyViolationException
from app.core.rate_limit import rate_limit_dependency
from app.policy.engine import policy_engine
from app.storage.repository import AuditRepository
from app.upstream.client import upstream_client

router = APIRouter(tags=["Gateway Chat API"])


class ChatMessage(BaseModel):
    role: str = "user"
    content: str


class ChatCompletionRequest(BaseModel):
    model: Optional[str] = "gpt-4o-mini"
    messages: List[ChatMessage]
    temperature: Optional[float] = 0.7
    max_tokens: Optional[int] = None
    stream: Optional[bool] = False
    # Allow extra fields for full OpenAI compatibility
    extra: Dict[str, Any] = Field(default_factory=dict)


class ChatRequestSimple(BaseModel):
    prompt: str
    model: Optional[str] = "gpt-4o-mini"
    temperature: Optional[float] = 0.7


@router.post("/chat/completions")
@router.post("/chat")
async def chat_gateway(
    request: Request,
    payload: Union[ChatCompletionRequest, ChatRequestSimple],
    client_key: str = Depends(verify_client_api_key),
):
    """
    Main Gateway Endpoint (OpenAI format & simple prompt format compatible).
    Inspects request -> Evaluates Policy -> Proxies to Upstream LLM -> Inspects Response -> Logs Audit.
    """
    start_time = time.perf_counter()
    incident_id = f"argus-inc-{uuid.uuid4().hex[:12]}"
    client_ip = request.client.host if request.client else "127.0.0.1"

    # Apply rate limiting
    await rate_limit_dependency(request, client_key=client_key)

    # Normalize messages & extract user input text
    if isinstance(payload, ChatRequestSimple):
        raw_user_prompt = payload.prompt
        normalized_messages = [{"role": "user", "content": payload.prompt}]
        target_model = payload.model or "gpt-4o-mini"
        temperature = payload.temperature or 0.7
        max_tokens = None
    else:
        normalized_messages = [{"role": m.role, "content": m.content} for m in payload.messages]
        # Combine all user/system messages for inspection
        raw_user_prompt = "\n".join(m.content for m in payload.messages)
        target_model = payload.model or "gpt-4o-mini"
        temperature = payload.temperature or 0.7
        max_tokens = payload.max_tokens

    # Step 1: Request Security Inspection
    request_decision = await policy_engine.evaluate_request(raw_user_prompt)

    # If policy blocks request -> short-circuit and log
    if not request_decision.passed or request_decision.action == "BLOCKED":
        total_latency_ms = (time.perf_counter() - start_time) * 1000.0

        # Persist incident asynchronously
        asyncio.create_task(
            AuditRepository.create_log(
                log_id=incident_id,
                client_id=client_key[:12] + "...",
                model=target_model,
                action="BLOCKED",
                risk_score=request_decision.risk_score,
                latency_ms=total_latency_ms,
                prompt_tokens=len(raw_user_prompt.split()),
                completion_tokens=0,
                request_prompt=raw_user_prompt,
                sanitized_prompt=request_decision.sanitized_text,
                violations=[v.model_dump() for v in request_decision.violations],
                inspector_details=request_decision.inspector_results,
                client_ip=client_ip,
            )
        )

        raise SecurityPolicyViolationException(
            detail="Request blocked by ARGUS Security Policy.",
            incident_id=incident_id,
            risk_score=request_decision.risk_score,
            violations=[v.model_dump() for v in request_decision.violations],
        )

    # Prepare sanitized messages for upstream proxy
    sanitized_messages = []
    if request_decision.action == "REDACTED":
        # If input was redacted, replace the user content in messages
        for msg in normalized_messages:
            if msg["role"] == "user":
                sanitized_content = (await policy_engine.inspectors["pii"].inspect(msg["content"])).sanitized_text
                sanitized_messages.append({"role": msg["role"], "content": sanitized_content or msg["content"]})
            else:
                sanitized_messages.append(msg)
    else:
        sanitized_messages = normalized_messages

    # Step 2: Forward to Upstream LLM
    upstream_response = await upstream_client.forward_chat(
        messages=sanitized_messages,
        model=target_model,
        temperature=temperature,
        max_tokens=max_tokens,
    )

    # Step 3: Response Inspection & Sanitization
    raw_completion_text = ""
    choices = upstream_response.get("choices", [])
    if choices and "message" in choices[0]:
        raw_completion_text = choices[0]["message"].get("content", "")

    response_decision = await policy_engine.evaluate_response(raw_completion_text)

    # If response violates policy (e.g. secret leak) -> replace or block
    if not response_decision.passed:
        if choices and "message" in choices[0]:
            choices[0]["message"]["content"] = "[SECURITY ALERT: Upstream model response blocked due to confidential credential leakage.]"
    elif response_decision.sanitized_text != raw_completion_text:
        if choices and "message" in choices[0]:
            choices[0]["message"]["content"] = response_decision.sanitized_text

    total_latency_ms = (time.perf_counter() - start_time) * 1000.0
    final_action = "REDACTED" if (request_decision.action == "REDACTED" or response_decision.action == "REDACTED") else request_decision.action

    usage = upstream_response.get("usage", {})
    prompt_tokens = usage.get("prompt_tokens", len(raw_user_prompt.split()))
    completion_tokens = usage.get("completion_tokens", len(raw_completion_text.split()))

    combined_violations = [v.model_dump() for v in request_decision.violations + response_decision.violations]
    combined_inspectors = {
        "request": request_decision.inspector_results,
        "response": response_decision.inspector_results,
    }

    # Step 4: Asynchronous Audit Logging
    asyncio.create_task(
        AuditRepository.create_log(
            log_id=incident_id,
            client_id=client_key[:12] + "...",
            model=target_model,
            action=final_action,
            risk_score=max(request_decision.risk_score, response_decision.risk_score),
            latency_ms=total_latency_ms,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            request_prompt=raw_user_prompt,
            sanitized_prompt=request_decision.sanitized_text,
            raw_response=raw_completion_text,
            sanitized_response=response_decision.sanitized_text,
            violations=combined_violations,
            inspector_details=combined_inspectors,
            client_ip=client_ip,
        )
    )

    # Build response with security headers
    response_payload = upstream_response
    headers = {
        "X-Argus-Incident-Id": incident_id,
        "X-Argus-Action": final_action,
        "X-Argus-Risk-Score": str(round(max(request_decision.risk_score, response_decision.risk_score), 3)),
        "X-Argus-Latency-Ms": str(round(total_latency_ms, 2)),
    }

    return JSONResponse(content=response_payload, headers=headers)
