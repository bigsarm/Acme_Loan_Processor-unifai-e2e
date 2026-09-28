"""Rate Check Agent class with explicit OpenRouter + DeepSeek invocation."""

import logging
import os
import re
from typing import Any

from llm.openai_compatible import OpenAICompatibleClient

from .framework import AcmeLoanAgentFramework

logger = logging.getLogger(__name__)


def _mask_ui_pii(text: str) -> str:
    masked = text or ""
    pii_patterns = [
        re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        re.compile(r"\b\d{9}\b"),
        re.compile(r"\b(?:19|20)\d{2}\b"),
        re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE),
        re.compile(r"\b(?:\+?1[-.\s]*)?(?:\(?\d{3}\)?[-.\s]*)\d{3}[-.\s]*\d{4}\b"),
        re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
        re.compile(r"\b[A-Z]{1,2}\d{6,9}\b", re.IGNORECASE),
        re.compile(r"\b[A-Z0-9]{1,9}\d{4,9}[A-Z0-9]*\b", re.IGNORECASE),
        re.compile(r"\b\d{2}-\d{7}\b"),
        re.compile(r"\b\d{8,17}\b"),
        re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"),
        re.compile(r"\b(?:[0-9A-F]{2}:){5}[0-9A-F]{2}\b", re.IGNORECASE),
        re.compile(r"\b(?:employee|school)\s*id\s*[:#]?\s*[A-Z0-9-]+\b", re.IGNORECASE),
        re.compile(r"\b[A-HJ-NPR-Z0-9]{17}\b", re.IGNORECASE),
    ]
    for pattern in pii_patterns:
        masked = pattern.sub("<masked_pii>", masked)
    return masked


class RateCheckAgent(AcmeLoanAgentFramework):
    AGENT_ID = "rate_check_agent"
    AGENT_NAME = "Rate_Check Agent"
    VERSION = "1.0.0"
    MODEL_NAME = "configured-via-OPENROUTER_MODEL"
    BEDROCK_MODEL_ID = ""
    DESCRIPTION = "Checks lending-rate questions using an OpenRouter model configured at runtime; replace with an organization-approved model via OPENROUTER_MODEL."
    MCP_SERVERS: list[str] = []
    GUARDRAILS = {
        "mask_pii": True,
        "base64_prompt_detection": True,
        "credential_minimization": True,
        "inter_agent_authentication": True,
    }
    SYSTEM_PROMPT = "Answer rate-check questions with short, practical lending-rate guidance."
    IS_ROUTABLE = False

    OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"

    def __init__(self):
        super().__init__()
        self.openrouter_client = OpenAICompatibleClient(
            base_url=self.OPENROUTER_BASE_URL,
            api_key=os.getenv("OPENROUTER_API_KEY"),
        )

    def to_dict(self) -> dict[str, Any]:
        metadata = super().to_dict()
        metadata["provider"] = "OpenRouter"
        metadata["openrouter_base_url"] = self.OPENROUTER_BASE_URL
        metadata["openrouter_model"] = os.getenv("OPENROUTER_MODEL")
        return metadata

    def sanitize_user_message(self, user_message: str) -> tuple[str, bool]:
        sanitized = (user_message or "").strip() or "No rate request provided."
        suspicious_patterns = [
            (re.compile(r"\b(?:ignore|disregard|bypass|override|forget)\b.{0,80}\b(?:previous|above|system|prior)\b.{0,80}\binstructions?\b", re.IGNORECASE | re.DOTALL), "<prompt_injection_removed: instruction_override>"),
            (re.compile(r"\b(?:you are now|act as|pretend to be|roleplay as)\b.{0,80}\b(?:dan|developer mode|unrestricted|system|assistant)\b", re.IGNORECASE | re.DOTALL), "<prompt_injection_removed: role_hijack>"),
            (re.compile(r"</?(?:system|assistant|user|tool)>|```+|---+|===+", re.IGNORECASE), "<prompt_injection_removed: delimiter_escape>"),
            (re.compile(r"(?:^|\b)(?:[A-Fa-f0-9]{2}){12,}(?:\b|$)|%(?:[0-9A-Fa-f]{2}){6,}|\b[a-zA-Z0-9+/]{24,}={0,2}\b|\\u[0-9A-Fa-f]{4}", re.IGNORECASE), "<prompt_injection_removed: encoded_payload>"),
            (re.compile(r"<!--.*?-->|[\u200B-\u200F\u2060\uFEFF]|display\s*:\s*none|visibility\s*:\s*hidden", re.IGNORECASE | re.DOTALL), "<prompt_injection_removed: hidden_text>"),
            (re.compile(r"\b(?:system|assistant|tool)\s*:\s*", re.IGNORECASE), "<prompt_injection_removed: fake_system_message>"),
            (re.compile(r"!\[[^\]]*\]\([^\)]*https?://[^\)]*\)|\b(?:send|post|upload|exfiltrate|leak|reveal)\b.{0,80}\b(?:system prompt|credentials|secrets?|data)\b", re.IGNORECASE | re.DOTALL), "<prompt_injection_removed: exfiltration_attempt>"),
            (re.compile(r"\b(?:in the next message|from now on|for the rest of this chat|remember this|store this instruction)\b", re.IGNORECASE), "<prompt_injection_removed: context_poisoning>"),
            (re.compile(r"\b(?:metadata|frontmatter|yaml|json|csv|comment|code comment|file content)\b.{0,80}\b(?:ignore|override|follow these instructions)\b", re.IGNORECASE | re.DOTALL), "<prompt_injection_removed: indirect_injection>"),
            (re.compile(r"\b(?:curl|wget|bash|sh|zsh|powershell|cmd\.exe|rm|chmod|python\s+-c|exec|eval|subprocess|os\.system)\b", re.IGNORECASE), "<prompt_injection_removed: command_injection>"),
            (re.compile(r"\bc[\W_]*u[\W_]*r[\W_]*l\b|\bi[\W_]*g[\W_]*n[\W_]*o[\W_]*r[\W_]*e\b|\bd[\W_]*a[\W_]*n\b", re.IGNORECASE), "<prompt_injection_removed: split_payload>"),
            (re.compile(r"\b(?:DAN|developer mode|jailbreak|do anything now|fictional scenario|hypothetical bypass|unfiltered response)\b", re.IGNORECASE), "<prompt_injection_removed: jailbreak_attempt>"),
        ]

        blocked = False
        for pattern, replacement in suspicious_patterns:
            if pattern.search(sanitized):
                blocked = True
                sanitized = pattern.sub(replacement, sanitized)

        return sanitized, blocked

    def sanitize_model_output(self, model_output: str) -> str:
        safe_lines: list[str] = []
        for line in (model_output or "").splitlines():
            if re.search(r"\b(?:eval|exec|subprocess|shell\s*=\s*True|os\.system)\b", line, re.IGNORECASE):
                continue
            safe_lines.append(line)
        return "\n".join(safe_lines).strip() or "Rate summary unavailable."

    async def call_agent_model(self, user_message: str) -> str:
        model = os.getenv("OPENROUTER_MODEL")
        if not os.getenv("OPENROUTER_API_KEY"):
            return "LLM service not configured. Please set OPENROUTER_API_KEY."
        if not model:
            return "LLM service not configured. Please set OPENROUTER_MODEL."

        logger.info(
            "Rate check LLM request",
            extra={
                "agent": self.AGENT_ID,
                "model": model,
                "prompt_length": len(user_message or ""),
            },
        )
        model_output = await self.openrouter_client.chat(
            model=model,
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"Rate check request:\n{user_message or 'No rate request provided.'}\n\n"
                        "Provide a concise rate check summary."
                    ),
                },
            ],
            temperature=0.2,
            max_tokens=220,
        )
        logger.info(
            "Rate check LLM response",
            extra={
                "agent": self.AGENT_ID,
                "model": model,
                "response_length": len(model_output or ""),
            },
        )
        return model_output

    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        user_message = context.get("user_message", "")
        safe_user_message, blocked_unsafe_content = self.sanitize_user_message(user_message)
        prompt_message = safe_user_message
        if blocked_unsafe_content:
            prompt_message = (
                "A rate-check request contained blocked unsafe prompt content. "
                "Use only the remaining safe request details."
            )

        model_output = self.sanitize_model_output(await self.call_agent_model(prompt_message))

        masked_user_message = _mask_ui_pii(safe_user_message)
        response = (
            f"Rate check request: {masked_user_message}\n\n"
            f"Rate summary:\n{model_output}"
        )

        return {
            "response": response,
            "agent": self.AGENT_NAME,
            "model": os.getenv("OPENROUTER_MODEL") or "Replace with an organization-approved model via OPENROUTER_MODEL",
            "framework": self.FRAMEWORK_NAME,
            "provider": "OpenRouter",
        }


rate_check_agent = RateCheckAgent()
