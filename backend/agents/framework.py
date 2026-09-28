"""Small agent framework base class used by the Acme Loan Processor agents."""

import os
from abc import ABC, abstractmethod
from copy import deepcopy
from typing import Any

from llm.openai_compatible import OpenAICompatibleClient


class AcmeLoanAgentFramework(ABC):
    """Base class that makes agent metadata and model usage obvious."""

    FRAMEWORK_NAME = "AcmeLoanAgentFramework"
    AGENT_ID = ""
    AGENT_NAME = ""
    VERSION = "1.0.0"
    MODEL_NAME = ""
    BEDROCK_MODEL_ID = ""
    BEDROCK_FALLBACK_MODEL_ID = ""
    DESCRIPTION = ""
    MCP_SERVERS: list[str] = []
    GUARDRAILS: dict[str, Any] = {}
    SYSTEM_PROMPT = ""
    IS_ROUTABLE = True
    IS_SCAN_ONLY = False

    OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"

    def __init__(self):
        # Runtime LLM calls use OpenRouter credentials from .env:
        # OPENROUTER_API_KEY and OPENROUTER_MODEL.
        self.model_client = OpenAICompatibleClient(
            base_url=self.OPENROUTER_BASE_URL,
            api_key=os.getenv("OPENROUTER_API_KEY"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.AGENT_ID,
            "name": self.AGENT_NAME,
            "version": self.VERSION,
            "framework": self.FRAMEWORK_NAME,
            "model": self.MODEL_NAME,
            "provider": "OpenRouter",
            "model_approval_notice": "Replace the configured model with an organization-approved LLM from the allow list before production use.",
            "openrouter_model": os.getenv("OPENROUTER_MODEL"),
            "bedrock_model_id": self.BEDROCK_MODEL_ID,
            "bedrock_fallback_model_id": self.BEDROCK_FALLBACK_MODEL_ID,
            "description": self.DESCRIPTION,
            "mcp_servers": list(self.MCP_SERVERS),
            "guardrails": deepcopy(self.GUARDRAILS),
            "system_prompt": self.SYSTEM_PROMPT,
            "is_routable": self.IS_ROUTABLE,
            "is_scan_only": self.IS_SCAN_ONLY,
        }

    async def call_bedrock_model(
        self,
        messages: list[dict[str, Any]],
        temperature: float = 0.2,
        max_tokens: int = 350,
    ) -> str:
        """Call OpenRouter using OPENROUTER_API_KEY + OPENROUTER_MODEL.

        Method name is kept for compatibility with existing agents.
        """
        api_key = (os.getenv("OPENROUTER_API_KEY") or "").strip()
        model = (os.getenv("OPENROUTER_MODEL") or "").strip()
        if not api_key:
            return "LLM service not configured. Please set OPENROUTER_API_KEY."
        if not model:
            return "LLM service not configured. Please set OPENROUTER_MODEL."

        return await self.model_client.chat(
            model=model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
        )

    @abstractmethod
    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        """Handle a request for this agent."""
