"""Rate Check Agent class with explicit OpenRouter + DeepSeek invocation."""

import logging
import os
import re
from typing import Any
from urllib.parse import unquote

from llm.openai_compatible import OpenAICompatibleClient

from .framework import AcmeLoanAgentFramework

logger = logging.getLogger(__name__)


def neutralize_prompt_injection(text: str) -> tuple[str, bool]:
    sanitized = text or ""
    blocked = False

    def _replace(pattern: re.Pattern[str], replacement: str, value: str) -> str:
        nonlocal blocked
        updated, count = pattern.subn(replacement, value)
        if count:
            blocked = True
        return updated

    hidden_text_pattern = re.compile(r"<!--.*?-->|[\u200B-\u200F\u2060\uFEFF]", re.IGNORECASE | re.DOTALL)
    instruction_override_pattern = re.compile(
        r"\b(?:ignore|disregard|forget|override|bypass)\b.{0,40}\b(?:previous|prior|above|earlier|system|developer|all)\b.{0,40}\b(?:instructions?|prompts?|messages?|rules?)\b",
        re.IGNORECASE | re.DOTALL,
    )
    role_hijack_pattern = re.compile(
        r"\b(?:you are now|act as|pretend to be|assume the role of|behave as)\b.{0,60}\b(?:dan|unrestricted|root|system|developer|assistant)\b",
        re.IGNORECASE | re.DOTALL,
    )
    delimiter_escape_pattern = re.compile(r"</?(?:system|assistant|developer|tool|user)>|(?:^|\n)\s*(?:---+|===+|```+)", re.IGNORECASE)
    fake_system_message_pattern = re.compile(
        r"\b(?:system|developer|tool)\s*:\s*|\[(?:system|developer|tool)\]",
        re.IGNORECASE,
    )
    exfiltration_pattern = re.compile(
        r"!\[[^\]]*\]\([^)]*\)|\b(?:send|post|upload|exfiltrate|leak|reveal|expose)\b.{0,80}\b(?:https?://|www\.|system prompt|prompt|secrets?|credentials?|data)\b",
        re.IGNORECASE | re.DOTALL,
    )
    context_poisoning_pattern = re.compile(
        r"\b(?:in (?:the )?next message|on your next turn|for the rest of this chat|from now on|remember this instruction|store this|persist this)\b",
        re.IGNORECASE,
    )
    indirect_injection_pattern = re.compile(
        r"\b(?:metadata|file contents?|document|comment|code comment|hidden field|front matter)\b.{0,60}\b(?:ignore|override|follow these instructions|execute)\b",
        re.IGNORECASE | re.DOTALL,
    )
    command_injection_pattern = re.compile(
        r"\b(?:curl|wget|bash|sh|zsh|powershell|cmd\.exe|python\s+-c|node\s+-e|exec|eval|subprocess|os\.system|rm\s+-rf|chmod\s+\+x)\b",
        re.IGNORECASE,
    )
    jailbreak_pattern = re.compile(
        r"\b(?:jailbreak|developer mode|do anything now|dan|bypass safety|disable safety|fictional scenario|hypothetical bypass)\b",
        re.IGNORECASE,
    )
    split_payload_pattern = re.compile(
        r"\b(?:i\s*g\s*n\s*o\s*r\s*e|b\s*y\s*p\s*a\s*s|d\s*a\s*n)\b",
        re.IGNORECASE,
    )
    encoded_payload_pattern = re.compile(
        r"(?:\b[A-Fa-f0-9]{32,}\b|\b(?:[A-Za-z0-9+/]{20,}={0,2})\b|%(?:[0-9A-Fa-f]{2}){6,}|\\x[0-9A-Fa-f]{2}(?:\\x[0-9A-Fa-f]{2}){3,}|\\u[0-9A-Fa-f]{4}(?:\\u[0-9A-Fa-f]{4}){1,})",
        re.IGNORECASE,
    )

    sanitized = _replace(hidden_text_pattern, "<prompt_injection_removed: hidden_text>", sanitized)
    sanitized = _replace(instruction_override_pattern, "<prompt_injection_removed: instruction_override>", sanitized)
    sanitized = _replace(role_hijack_pattern, "<prompt_injection_removed: role_hijack>", sanitized)
    sanitized = _replace(delimiter_escape_pattern, "<prompt_injection_removed: delimiter_escape>", sanitized)
    sanitized = _replace(fake_system_message_pattern, "<prompt_injection_removed: fake_system_message>", sanitized)
    sanitized = _replace(exfiltration_pattern, "<prompt_injection_removed: exfiltration_attempt>", sanitized)
    sanitized = _replace(context_poisoning_pattern, "<prompt_injection_removed: context_poisoning>", sanitized)
    sanitized = _replace(indirect_injection_pattern, "<prompt_injection_removed: indirect_injection>", sanitized)
    sanitized = _replace(command_injection_pattern, "<prompt_injection_removed: command_injection>", sanitized)
    sanitized = _replace(jailbreak_pattern, "<prompt_injection_removed: jailbreak_attempt>", sanitized)
    sanitized = _replace(split_payload_pattern, "<prompt_injection_removed: split_payload>", sanitized)

    decoded = unquote(sanitized)
    if decoded != sanitized and decoded != text:
        blocked = True
        sanitized = encoded_payload_pattern.sub("<prompt_injection_removed: encoded_payload>", decoded)
    else:
        sanitized = _replace(encoded_payload_pattern, "<prompt_injection_removed: encoded_payload>", sanitized)

    sanitized = re.sub(r"\n{3,}", "\n\n", sanitized)
    return sanitized, blocked


class RateCheckAgent(AcmeLoanAgentFramework):
    AGENT_ID = "rate_check_agent"
    AGENT_NAME = "Rate_Check Agent"
    VERSION = "1.0.0"
    MODEL_NAME = os.getenv("OPENROUTER_MODEL", "deepseek/deepseek-chat")
    BEDROCK_MODEL_ID = ""
    DESCRIPTION = "Checks lending-rate questions using an OpenRouter-configured model. Configure OPENROUTER_MODEL to an organization-approved LLM."
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
        metadata["provider"] = "OpenRouter (configure with an approved organizational model)"
        metadata["openrouter_base_url"] = self.OPENROUTER_BASE_URL
        metadata["openrouter_model"] = os.getenv("OPENROUTER_MODEL")
        metadata["model_configuration_notice"] = "Replace any unapproved model with an organization-approved LLM via OPENROUTER_MODEL."
        return metadata

    def sanitize_user_message(self, user_message: str) -> tuple[str, bool]:
        sanitized = (user_message or "").strip() or "No rate request provided."
        sanitized, prompt_injection_blocked = neutralize_prompt_injection(sanitized)
        suspicious_patterns = [
            re.compile(r"<!--.*?-->", re.DOTALL),
            re.compile(r"[A-Za-z0-9+/=]{24,}"),
            re.compile(r"\b(?:curl|wget|bash|sh|zsh|powershell|cmd\.exe|rm|chmod|python\s+-c|exec|eval|subprocess)\b", re.IGNORECASE),
            re.compile(r"\bc[\W_]*u[\W_]*r[\W_]*l\b", re.IGNORECASE),
            re.compile(r"\bc[4@]rl\b|\bw[6g]et\b|\br[mn]\b", re.IGNORECASE),
        ]

        blocked = prompt_injection_blocked
        for pattern in suspicious_patterns:
            if pattern.search(sanitized):
                blocked = True
                sanitized = pattern.sub("<blocked_unsafe_content>", sanitized)

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
            return "LLM service not configured. Please set OPENROUTER_MODEL to an organization-approved LLM."

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
        if not os.getenv("OPENROUTER_MODEL"):
            return {
                "response": "Configuration required: replace the current model with an organization-approved LLM via OPENROUTER_MODEL.",
                "agent": self.AGENT_NAME,
                "model": self.MODEL_NAME,
                "framework": self.FRAMEWORK_NAME,
                "provider": "OpenRouter",
            }
        safe_user_message, blocked_unsafe_content = self.sanitize_user_message(user_message)
        prompt_message = safe_user_message
        if blocked_unsafe_content:
            prompt_message = (
                "A rate-check request contained blocked unsafe prompt content. "
                "Use only the remaining safe request details."
            )

        model_output = self.sanitize_model_output(await self.call_agent_model(prompt_message))

        response = (
            f"Rate check request: {safe_user_message}\n\n"
            f"Rate summary:\n{model_output}"
        )

        return {
            "response": response,
            "agent": self.AGENT_NAME,
            "model": self.MODEL_NAME,
            "framework": self.FRAMEWORK_NAME,
            "provider": "OpenRouter",
        }


rate_check_agent = RateCheckAgent()
