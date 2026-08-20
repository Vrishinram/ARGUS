import time
import uuid
from typing import Any, Dict, List


class MockLLMProvider:
    """High-speed local mock provider for zero-cost, offline testing and CI/CD validation."""

    @staticmethod
    async def generate_chat_completion(
        messages: List[Dict[str, str]],
        model: str = "mock-gpt-4o",
        temperature: float = 0.7,
        max_tokens: int = 512,
    ) -> Dict[str, Any]:
        last_message = messages[-1]["content"] if messages else "Hello"

        # Generate contextual mock response
        if "weather" in last_message.lower():
            content = "The current weather is sunny and 72°F (22°C) with light breeze."
        elif "code" in last_message.lower() or "python" in last_message.lower():
            content = "Here is a safe Python snippet:\n\n```python\ndef greet(name: str) -> str:\n    return f'Hello, {name}!'\n```"
        elif "leak_test_secret" in last_message.lower():
            content = "Here is an accidental secret leak: AKIAIOSFODNN7EXAMPLE for testing."
        else:
            content = f"Argus Gateway Mock Response: Your sanitized input was successfully processed. Model: {model}."

        prompt_tokens = max(1, sum(len(m.get("content", "").split()) for m in messages))
        completion_tokens = max(1, len(content.split()))

        return {
            "id": f"chatcmpl-mock-{uuid.uuid4().hex[:10]}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": model,
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": content,
                    },
                    "finish_reason": "stop",
                }
            ],
            "usage": {
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": prompt_tokens + completion_tokens,
            },
        }
