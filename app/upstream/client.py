import logging
from typing import Any, Dict, List, Optional
import httpx
from app.config import settings
from app.core.errors import UpstreamProviderException
from app.upstream.mock_provider import MockLLMProvider

logger = logging.getLogger("argus.upstream.client")


class UpstreamClient:
    """Dispatches sanitized chat completions to configured upstream LLMs (OpenAI/Gemini/Mock)."""

    def __init__(self):
        self.provider = settings.ARGUS_UPSTREAM_PROVIDER.lower()
        self.base_url = settings.ARGUS_UPSTREAM_BASE_URL.rstrip("/")
        self.api_key = settings.ARGUS_UPSTREAM_API_KEY
        self.default_model = settings.ARGUS_UPSTREAM_MODEL
        self.timeout = settings.ARGUS_UPSTREAM_TIMEOUT_SECONDS

    async def forward_chat(
        self,
        messages: List[Dict[str, str]],
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: Optional[int] = None,
        extra_params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        target_model = model or self.default_model

        # If configured for mock mode or if no API key is set for live provider
        if self.provider == "mock" or not self.api_key:
            if self.provider != "mock" and not self.api_key:
                logger.warning("No upstream API key configured. Falling back to MockLLMProvider.")
            return await MockLLMProvider.generate_chat_completion(
                messages=messages,
                model=target_model,
                temperature=temperature,
                max_tokens=max_tokens or 512,
            )

        # Live upstream HTTP dispatch
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        payload: Dict[str, Any] = {
            "model": target_model,
            "messages": messages,
            "temperature": temperature,
        }
        if max_tokens:
            payload["max_tokens"] = max_tokens
        if extra_params:
            payload.update(extra_params)

        url = f"{self.base_url}/chat/completions"

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                response = await client.post(url, headers=headers, json=payload)
            except httpx.TimeoutException:
                raise UpstreamProviderException("Upstream LLM provider request timed out.")
            except httpx.RequestError as e:
                raise UpstreamProviderException(f"Failed to connect to upstream provider: {str(e)}")

            if response.status_code != 200:
                error_detail = response.text
                try:
                    error_json = response.json()
                    error_detail = error_json.get("error", {}).get("message", error_detail)
                except Exception:
                    pass
                raise UpstreamProviderException(
                    detail=f"Upstream provider error: {error_detail}",
                    upstream_status_code=response.status_code,
                )

            return response.json()


upstream_client = UpstreamClient()
