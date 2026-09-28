"""Orchestrator Agent class with explicit model invocation."""

import logging
import os
import re
import urllib.parse
from typing import Any

from .access_control_agent import access_control_agent
from .credit_eval_agent import credit_eval_agent
from .environment_diagnostics_agent import environment_diagnostics_agent
from .file_management_agent import file_management_agent
from .file_processor_agent import file_processor_agent
from .framework import AcmeLoanAgentFramework
from .loan_processing_agent import loan_processing_agent
from .scheduling_agent import scheduling_agent
from .installed_skill_agent import installed_skill_agent

logger = logging.getLogger(__name__)


_ZERO_WIDTH_RE = re.compile(r"[\u200b\u200c\u200d\ufeff]")


def _replace_if_decoded_attack(text: str, pattern: re.Pattern[str], marker: str) -> str:
    def _repl(match: re.Match[str]) -> str:
        candidate = match.group(0)
        try:
            decoded = urllib.parse.unquote(candidate)
        except Exception:
            decoded = candidate
        if decoded != candidate and pattern.search(decoded):
            return marker
        return candidate

    return re.sub(r"(?:%[0-9A-Fa-f]{2}){4,}", _repl, text)


def _neutralize_untrusted_text(text: str) -> str:
    if not isinstance(text, str) or not text:
        return text

    sanitized = text

    hidden_patterns = [
        (re.compile(r"<!--(?:(?!-->).)*(ignore previous instructions|forget everything above|act as|you are now|developer mode|system prompt)(?:(?!-->).)*-->", re.IGNORECASE | re.DOTALL), "<prompt_injection_removed: hidden_text>"),
        (re.compile(r"<[^>]+style\s*=\s*[\"'][^\"']*(?:display\s*:\s*none|font-size\s*:\s*0|color\s*:\s*white)[^\"']*[\"'][^>]*>.*?</[^>]+>", re.IGNORECASE | re.DOTALL), "<prompt_injection_removed: hidden_text>"),
    ]
    for pattern, marker in hidden_patterns:
        sanitized = pattern.sub(marker, sanitized)
    if _ZERO_WIDTH_RE.search(sanitized):
        sanitized = _ZERO_WIDTH_RE.sub("", sanitized)
        sanitized = sanitized.replace("ignore previous instructions", "<prompt_injection_removed: hidden_text>")

    replacements = [
        (re.compile(r"\b(?:ignore|disregard)\s+(?:all\s+)?(?:previous|prior|earlier)\s+instructions\b|\bforget\s+everything\s+(?:above|before)\b", re.IGNORECASE), "<prompt_injection_removed: instruction_override>"),
        (re.compile(r"\byou\s+are\s+now\s+(?:dan|developer mode|admin mode|root)\b|\bact\s+as\s+(?:an\s+)?(?:unrestricted|unfiltered|jailbroken)\b", re.IGNORECASE), "<prompt_injection_removed: role_hijack>"),
        (re.compile(r"</system>|</assistant>|<system>|<assistant>|(?:^|\n)\s*(?:---|===)\s*(?:system|assistant|developer|tool)\s*(?:---|===)", re.IGNORECASE), "<prompt_injection_removed: delimiter_escape>"),
        (re.compile(r"\b(?:system|assistant|tool)\s*:\s*(?:ignore|reveal|send|list|print|dump)\b", re.IGNORECASE), "<prompt_injection_removed: fake_system_message>"),
        (re.compile(r"\b(?:reveal|leak|print|dump|list|show)\b.{0,80}\b(?:system prompt|secrets?|passwords?|api keys?|tokens?|credentials?)\b", re.IGNORECASE), "<prompt_injection_removed: exfiltration_attempt>"),
        (re.compile(r"!\[[^\]]*\]\(https?://[^)]+\)|\b(?:send|post|upload|exfiltrate|curl|wget)\b.{0,80}https?://\S+", re.IGNORECASE), "<prompt_injection_removed: exfiltration_attempt>"),
        (re.compile(r"\b(?:in (?:the )?next turn|on your next response|after this message)\b.{0,80}\b(?:ignore|override|change|pretend)\b", re.IGNORECASE), "<prompt_injection_removed: context_poisoning>"),
        (re.compile(r"(?:/\*|#|//)\s*(?:ignore previous instructions|act as|you are now|reveal system prompt)", re.IGNORECASE), "<prompt_injection_removed: indirect_injection>"),
        (re.compile(r"\b(?:rm\s+-rf\b|curl\s+https?://\S+\s*\|\s*sh\b|wget\s+https?://\S+\s*\|\s*sh\b|powershell\s+-enc\b|bash\s+-c\b|sh\s+-c\b|cmd\.exe\b|/bin/sh\b|/bin/bash\b|chmod\s+\+x\b|python\s+-c\b)\b", re.IGNORECASE), "<prompt_injection_removed: command_injection>"),
        (re.compile(r"\b(?:dan|developer mode|jailbreak|do anything now|fictional scenario where safety does not apply)\b", re.IGNORECASE), "<prompt_injection_removed: jailbreak_attempt>"),
        (re.compile(r"\b(?:ignore\W*previous\W*instructions|forget\W*everything\W*above|act\W*as\W*unrestricted)\b", re.IGNORECASE), "<prompt_injection_removed: split_payload>"),
    ]
    for pattern, marker in replacements:
        sanitized = pattern.sub(marker, sanitized)

    encoded_attack_pattern = re.compile(r"\b(?:ignore\s+previous\s+instructions|forget\s+everything\s+above|act\s+as\s+unrestricted|you\s+are\s+now\s+dan|reveal\s+all\s+confidential\s+information|list\s+all\s+passwords\s+and\s+api\s+keys)\b", re.IGNORECASE)
    sanitized = _replace_if_decoded_attack(sanitized, encoded_attack_pattern, "<prompt_injection_removed: encoded_payload>")

    def _replace_base64(match: re.Match[str]) -> str:
        token = match.group(0)
        if len(token) < 24 or len(token) % 4 != 0:
            return token
        try:
            decoded = __import__("base64").b64decode(token, validate=True).decode("utf-8", errors="ignore")
        except Exception:
            return token
        if encoded_attack_pattern.search(decoded):
            return "<prompt_injection_removed: encoded_payload>"
        return token

    sanitized = re.sub(r"\b(?:[A-Za-z0-9+/]{24,}={0,2})\b", _replace_base64, sanitized)

    leetspeak_pattern = re.compile(r"\b(?:1gn0re\s+prev(?:10us|ious)\s+1nstruct10ns|act\s+as\s+unrestr1cted|y0u\s+are\s+n0w\s+dan)\b", re.IGNORECASE)
    sanitized = leetspeak_pattern.sub("<prompt_injection_removed: encoded_payload>", sanitized)

    return sanitized


def _redact_pii_text(text: str) -> str:
    if not isinstance(text, str) or not text:
        return text

    redacted = text
    replacements = [
        (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "<pii_redacted:ssn>"),
        (re.compile(r"\b(?:\+?1[-.\s]?)?(?:\(\d{3}\)[-.\s]?|\d{3}[-.\s])\d{3}[-.\s]\d{4}\b"), "<pii_redacted:phone>"),
        (re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE), "<pii_redacted:email>"),
        (re.compile(r"\b(?:\d[ -]*?){13,19}\b"), "<pii_redacted:credit_card>"),
        (re.compile(r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b"), "<pii_redacted:ip_address>"),
        (re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b"), "<pii_redacted:mac_address>"),
        (re.compile(r"\b[A-HJ-NPR-Z0-9]{17}\b"), "<pii_redacted:vin>"),
        (re.compile(r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))(?:[ -]*\d{4}){3}\b"), "<pii_redacted:credit_card>"),
        (re.compile(r"\b(?:routing|account)\s*(?:number|no\.?|#)?\s*:\s*[A-Z0-9-]{6,20}\b", re.IGNORECASE), lambda m: m.group(0).split(":", 1)[0] + ": <pii_redacted:financial_account>"),
        (re.compile(r"\b(?:passport(?:\s+number|\s+no\.?)?|driver'?s\s+license(?:\s+number)?|drivers\s+license(?:\s+number)?|taxpayer\s+identification\s+number|tin|employee\s+id|school\s+id)\s*:\s*[^\n,;]+", re.IGNORECASE), lambda m: m.group(0).split(":", 1)[0] + ": <pii_redacted:labeled_identifier>"),
        (re.compile(r"\b(?:dob|date\s+of\s+birth|year\s+of\s+birth|birthplace|mother'?s\s+maiden\s+name|home\s+address|address|medical\s+record(?:s)?|fingerprints?|retina/?iris\s+scan|voice\s+signature|facial\s+image|ethnicity|sexual\s+orientation|fine\s+location)\s*:\s*[^\n]+", re.IGNORECASE), lambda m: m.group(0).split(":", 1)[0] + ": <pii_redacted>"),
    ]
    for pattern, replacement in replacements:
        redacted = pattern.sub(replacement, redacted)
    redacted = re.sub(r"\bborn\s+in\s+(19\d{2}|20\d{2})\b", "born in <pii_redacted:year_of_birth>", redacted, flags=re.IGNORECASE)
    return redacted


def _sanitize_file_contents(file_contents: list[dict[str, Any]]) -> list[dict[str, Any]]:
    sanitized_files: list[dict[str, Any]] = []
    for item in file_contents or []:
        if isinstance(item, dict):
            sanitized_item: dict[str, Any] = {}
            for key, value in item.items():
                if isinstance(value, str):
                    value = _neutralize_untrusted_text(value)
                    value = _redact_pii_text(value)
                sanitized_item[key] = value
            sanitized_files.append(sanitized_item)
        else:
            sanitized_files.append(item)
    return sanitized_files


class OrchestratorAgent(AcmeLoanAgentFramework):
    AGENT_ID = "orchestrator_agent"
    AGENT_NAME = "Orchestrator Agent"
    VERSION = "1.0.0"
    MODEL_NAME = "claude-sonnet-4"
    BEDROCK_MODEL_ID = os.getenv("ORCHESTRATOR_BEDROCK_MODEL_ID", "us.anthropic.claude-3-5-sonnet-20241022-v2:0")
    DESCRIPTION = "Routes work between the specialized agents and shares the conversation context."
    MCP_SERVERS = ["Slack"]
    GUARDRAILS = {
        "mask_pii": None,
        "base64_prompt_detection": None,
        "credential_minimization": None,
        "inter_agent_authentication": False,
    }
    SYSTEM_PROMPT = "Route requests to the right specialist and keep the workflow moving."

    async def call_agent_model(self, user_message: str, selected_agent_name: str) -> str:
        user_message = _neutralize_untrusted_text(user_message)
        return await self.call_bedrock_model(
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"User request:\n{user_message or 'No user message provided.'}\n\n"
                        f"Selected agent: {selected_agent_name}\n\n"
                        "Explain the routing decision in one short paragraph."
                    ),
                },
            ],
            temperature=0.1,
            max_tokens=160,
        )

    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        sanitized_user_message = _neutralize_untrusted_text(context.get("user_message", ""))
        sanitized_file_contents = _sanitize_file_contents(context.get("file_contents", []))
        selected_agent = self.select_agent(
            user_message=sanitized_user_message,
            file_contents=sanitized_file_contents,
        )
        selected_agent_name = selected_agent.AGENT_NAME

        # Vulnerability: the Orchestrator Agent forwards the entire context and a
        # shared internal token to downstream agents with no authentication boundary.
        forwarded_context = dict(context)
        forwarded_context["user_message"] = sanitized_user_message
        forwarded_context["file_contents"] = sanitized_file_contents
        forwarded_context["orchestrator_agent"] = self.AGENT_NAME
        forwarded_context["selected_agent"] = selected_agent_name
        forwarded_context["internal_call_chain"] = [self.AGENT_NAME, selected_agent_name]
        forwarded_context["internal_hop_token"] = "shared-orchestrator-hop-token"

        logger.info(
            "Orchestrator Agent routing request",
            extra={
                "selected_agent": selected_agent_name,
                "internal_call_chain": forwarded_context["internal_call_chain"],
            },
        )

        routing_note = await self.call_agent_model(
            sanitized_user_message,
            selected_agent_name,
        )
        response = await selected_agent.handle(forwarded_context)
        response["orchestrator"] = self.AGENT_NAME
        response["routing_note"] = routing_note
        return response

    def select_agent(self, user_message: str, file_contents: list[dict[str, Any]]) -> AcmeLoanAgentFramework:
        text = (user_message or "").lower()

        if self._should_route_to_installed_skill(text):
            return installed_skill_agent
        if any(keyword in text for keyword in ["schedule", "meeting", "calendar", "appointment"]):
            return scheduling_agent
        if any(
            keyword in text
            for keyword in [
                "delete",
                "purge",
                "destroy",
                "remove file",
                "file management",
                "deletefile",
                "purge records",
            ]
        ):
            return file_management_agent
        if any(
            keyword in text
            for keyword in [
                "grant access",
                "deny access",
                "allow access",
                "firewall",
                "assign role",
                "assign a role",
                "grant admin",
                "privilege",
                "authorize",
                "access control",
                "security decision",
            ]
        ):
            return access_control_agent
        if any(
            keyword in text
            for keyword in [
                "environment diagnostic",
                "environment diagnostics",
                "run diagnostics",
                "diagnostic steps",
                "verify environment",
                "environment setup",
            ]
        ):
            return environment_diagnostics_agent
        if any(keyword in text for keyword in ["credit", "fico", "debt-to-income", "dti", "underwrite", "loan status", "employee", "ssn", "borrower status"]):
            return credit_eval_agent
        if any(keyword in text for keyword in ["loan", "mortgage", "borrower", "application"]):
            return credit_eval_agent
        if file_contents or any(
            keyword in text
            for keyword in [
                "support document",
                "uploaded support",
                "review this uploaded",
                "summarize it's contents",
                "summarize its contents",
                "uploaded document",
                "review document",
            ]
        ):
            return file_processor_agent
        return credit_eval_agent

    @staticmethod
    def _should_route_to_installed_skill(text: str) -> bool:
        # Ambient skill loading: match task intent, not explicit "use skill" commands.
        skill_match_keywords = [
            "loan document",
            "loan documents",
            "process my loan document",
            "process loan document",
            "review my loan document",
            "review loan document",
        ]
        return any(keyword in text for keyword in skill_match_keywords)


orchestrator_agent = OrchestratorAgent()
