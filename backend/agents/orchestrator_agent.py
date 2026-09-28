"""Orchestrator Agent class with explicit model invocation."""

import logging
from typing import Any
import os
import re
import urllib.parse

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


_PROMPT_INJECTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(r"(?is)\b(ignore\s+previous\s+instructions|forget\s+everything\s+above|disregard\s+all\s+prior)\b"),
        "<prompt_injection_removed: instruction_override>",
    ),
    (
        re.compile(r"(?is)\b(you\s+are\s+now\s+dan|act\s+as\s+unrestricted|developer\s+mode|jailbreak|do\s+anything\s+now|fictional\s+framing\s+bypass)\b"),
        "<prompt_injection_removed: jailbreak_attempt>",
    ),
    (
        re.compile(r"(?is)\b(act\s+as|you\s+are\s+now|pretend\s+to\s+be|assume\s+the\s+role\s+of)\b"),
        "<prompt_injection_removed: role_hijack>",
    ),
    (
        re.compile(r"(?is)(</system>|</assistant>|<system>|<assistant>|\[system\]|\[assistant\]|^---+$|^===+$)", re.MULTILINE),
        "<prompt_injection_removed: delimiter_escape>",
    ),
    (
        re.compile(r"(?is)(<!--[\s\S]*?-->|[\u200B-\u200F\u2060\uFEFF])"),
        "<prompt_injection_removed: hidden_text>",
    ),
    (
        re.compile(r"(?is)\b(system\s*:\s*|tool\s*:\s*|assistant\s*:\s*)"),
        "<prompt_injection_removed: fake_system_message>",
    ),
    (
        re.compile(r"(?is)\b(send|post|upload|exfiltrat\w*|leak)\b.{0,80}\b(http|https|url|webhook|system\s+prompt|secrets?)\b"),
        "<prompt_injection_removed: exfiltration_attempt>",
    ),
    (
        re.compile(r"(?is)\b(in\s+the\s+next\s+turn|on\s+your\s+next\s+reply|remember\s+this\s+secret\s+instruction|store\s+this\s+instruction)\b"),
        "<prompt_injection_removed: context_poisoning>",
    ),
    (
        re.compile(r"(?is)\b(file\s+metadata|code\s+comment|yaml\s+front\s+matter|markdown\s+comment)\b.{0,80}\b(ignore|override|instruction)\b"),
        "<prompt_injection_removed: indirect_injection>",
    ),
    (
        re.compile(r"(?is)\b(rm\s+-rf|curl\s+|wget\s+|powershell\b|cmd\.exe|/bin/sh|bash\b|subprocess\b|os\.system\b|exec\b|eval\b)\b"),
        "<prompt_injection_removed: command_injection>",
    ),
    (
        re.compile(r"(?is)(?:i\s*g\s*n\s*o\s*r\s*e\s+p\s*r\s*e\s*v\s*i\s*o\s*u\s*s\s+i\s*n\s*s\s*t\s*r\s*u\s*c\s*t\s*i\s*o\s*n\s*s)"),
        "<prompt_injection_removed: split_payload>",
    ),
]

_PIi_REDACTIONS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b|\b\d{9}\b"), "<redacted:ssn>"),
    (re.compile(r"\b(?:19|20)\d{2}\b"), "<redacted:year_of_birth>"),
    (re.compile(r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b"), "<redacted:email>"),
    (re.compile(r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4})\b"), "<redacted:personal_phone_number>"),
    (re.compile(r"\b\d{1,5}\s+[A-Za-z0-9.#'\-\s]+\s(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct)\b", re.IGNORECASE), "<redacted:home_address>"),
    (re.compile(r"\b[A-PR-WYa-pr-wy][1-9]\d\s?\d{4}[1-9]\b"), "<redacted:passport_number>"),
    (re.compile(r"\b[A-Z0-9]{1,9}\b"), "<redacted:drivers_license_number>"),
    (re.compile(r"\b\d{2}-\d{7}\b|\b\d{9}\b"), "<redacted:taxpayer_identification_number>"),
    (re.compile(r"\b(?:\d[ -]*?){13,19}\b"), "<redacted:credit_card_number>"),
    (re.compile(r"\b(?:account|acct|iban|routing)[:#\s-]*[A-Z0-9-]{6,34}\b", re.IGNORECASE), "<redacted:financial_account_number>"),
    (re.compile(r"\bemployee\s*id[:#\s-]*[A-Z0-9-]{2,}\b", re.IGNORECASE), "<redacted:employee_id>"),
    (re.compile(r"\bschool\s*id[:#\s-]*[A-Z0-9-]{2,}\b", re.IGNORECASE), "<redacted:school_id>"),
    (re.compile(r"\b[A-HJ-NPR-Z0-9]{17}\b"), "<redacted:vehicle_identification_number>"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "<redacted:ip_address>"),
    (re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b"), "<redacted:mac_address>"),
]


def _contains_encoded_or_obfuscated_payload(value: str) -> bool:
    if not value:
        return False
    compact = re.sub(r"\s+", "", value)
    if re.search(r"(?:[A-Za-z0-9+/]{20,}={0,2})", compact):
        return True
    if re.search(r"(?:0x)?[0-9a-fA-F]{24,}", compact):
        return True
    if re.search(r"(?:%[0-9A-Fa-f]{2}){6,}", value):
        return True
    if re.search(r"(?:[01]{8}\s*){6,}", value):
        return True
    if re.search(r"\b[a-zA-Z]*[430157][a-zA-Z0-9]*\b", value):
        return True
    if re.search(r"(?:[.-]{1,6}\s+){6,}[.-]{1,6}", value):
        return True
    return False


def _neutralize_prompt_injection(value: str) -> str:
    sanitized = value or ""
    for pattern, replacement in _PROMPT_INJECTION_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)
    if _contains_encoded_or_obfuscated_payload(sanitized):
        sanitized = re.sub(r"(?:[A-Za-z0-9+/]{20,}={0,2})", "<prompt_injection_removed: encoded_payload>", sanitized)
        sanitized = re.sub(r"(?:0x)?[0-9a-fA-F]{24,}", "<prompt_injection_removed: encoded_payload>", sanitized)
        sanitized = re.sub(r"(?:%[0-9A-Fa-f]{2}){6,}", "<prompt_injection_removed: encoded_payload>", sanitized)
        sanitized = re.sub(r"(?:[01]{8}\s*){6,}", "<prompt_injection_removed: encoded_payload>", sanitized)
        sanitized = re.sub(r"\b[a-zA-Z]*[430157][a-zA-Z0-9]*\b", "<prompt_injection_removed: encoded_payload>", sanitized)
        sanitized = re.sub(r"(?:[.-]{1,6}\s+){6,}[.-]{1,6}", "<prompt_injection_removed: encoded_payload>", sanitized)
        sanitized = urllib.parse.unquote(sanitized)
    return sanitized


def _inspect_prompt_input(value: str) -> str:
    sanitized = _neutralize_prompt_injection(value or "")
    if re.search(r"(?is)\b(rm\s+-rf|curl\s+|wget\s+|powershell\b|cmd\.exe|/bin/sh|bash\b|subprocess\b|os\.system\b|exec\b|eval\b)\b", sanitized):
        raise ValueError("Prompt input contains command or code execution content.")
    return sanitized


def _redact_pii_text(value: str) -> str:
    redacted = value or ""
    for pattern, replacement in _PIi_REDACTIONS:
        redacted = pattern.sub(replacement, redacted)
    return redacted


def _sanitize_file_contents(file_contents: list[dict[str, Any]]) -> list[dict[str, Any]]:
    sanitized_files: list[dict[str, Any]] = []
    for item in file_contents or []:
        sanitized_item = dict(item)
        for key, value in list(sanitized_item.items()):
            if isinstance(value, str):
                sanitized_item[key] = _redact_pii_text(_neutralize_prompt_injection(value))
            elif isinstance(value, list):
                sanitized_item[key] = [
                    _redact_pii_text(_neutralize_prompt_injection(entry)) if isinstance(entry, str) else entry
                    for entry in value
                ]
        sanitized_files.append(sanitized_item)
    return sanitized_files


class OrchestratorAgent(AcmeLoanAgentFramework):
    AGENT_ID = "orchestrator_agent"
    AGENT_NAME = "Orchestrator Agent"
    VERSION = "1.0.0"
    MODEL_NAME = os.getenv("ORCHESTRATOR_MODEL_NAME", "claude-sonnet-4")
    BEDROCK_MODEL_ID = os.getenv("ORCHESTRATOR_BEDROCK_MODEL_ID", "us.anthropic.claude-3-5-sonnet-20241022-v2:0")
    # Replace these defaults with an approved LLM from the organization's allow list via environment configuration.
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
        user_message = _inspect_prompt_input(user_message)
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
        sanitized_user_message = _inspect_prompt_input(context.get("user_message", ""))
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
