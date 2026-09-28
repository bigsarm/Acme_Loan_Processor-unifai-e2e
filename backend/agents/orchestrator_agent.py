"""Orchestrator Agent class with explicit model invocation."""

import logging
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

_ZERO_WIDTH_TRANSLATION = dict.fromkeys(map(ord, "\u200b\u200c\u200d\ufeff\u2060"), None)

_PII_PATTERNS = [
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "<redacted:ssn>"),
    (re.compile(r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4})\b"), "<redacted:phone>"),
    (re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE), "<redacted:email>"),
    (re.compile(r"\b(?:\d[ -]*?){13,19}\b"), "<redacted:credit_card>"),
    (re.compile(r"\b(?:\d{9}|\d{2}-\d{7})\b"), "<redacted:taxpayer_id>"),
    (re.compile(r"\b[A-Z]{1,2}\d{6,9}\b", re.IGNORECASE), "<redacted:passport>"),
    (re.compile(r"\b(?:[A-Z]\d{7}|\d{7,9})\b", re.IGNORECASE), "<redacted:drivers_license>"),
    (re.compile(r"\b[A-HJ-NPR-Z0-9]{17}\b"), "<redacted:vin>"),
    (re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b"), "<redacted:mac_address>"),
    (re.compile(r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b"), "<redacted:ip_address>"),
    (re.compile(r"\b(?:\d{1,3}\s+[A-Za-z0-9.]+(?:\s+[A-Za-z0-9.]+){0,4}\s+(?:Street|St|Avenue|Ave|Road|Rd|Lane|Ln|Drive|Dr|Boulevard|Blvd|Court|Ct|Way|Place|Pl))\b", re.IGNORECASE), "<redacted:home_address>"),
    (re.compile(r"\b(?:19|20)\d{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])\b"), "<redacted:year_of_birth>")
]

_LABELED_PII_PATTERNS = [
    (re.compile(r"(?i)(\b(?:year of birth|yob|dob|date of birth)\s*[:=-]\s*)([^\n,;]+)"), "<redacted:year_of_birth>"),
    (re.compile(r"(?i)(\b(?:birthplace|place of birth|born in)\s*[:=-]\s*)([^\n,;]+)"), "<redacted:birthplace>"),
    (re.compile(r"(?i)(\b(?:mother'?s maiden name|maiden name)\s*[:=-]\s*)([^\n,;]+)"), "<redacted:mothers_maiden_name>"),
    (re.compile(r"(?i)(\b(?:employee id|employee number)\s*[:=-]\s*)([^\n,;]+)"), "<redacted:employee_id>"),
    (re.compile(r"(?i)(\b(?:school id|student id)\s*[:=-]\s*)([^\n,;]+)"), "<redacted:school_id>"),
    (re.compile(r"(?i)(\b(?:financial account number|account number|bank account)\s*[:=-]\s*)([^\n,;]+)"), "<redacted:financial_account>"),
    (re.compile(r"(?i)(\b(?:medical records?|medical record number|mrn)\s*[:=-]\s*)([^\n,;]+)"), "<redacted:medical_records>"),
    (re.compile(r"(?i)(\b(?:fingerprints?|retina/?iris scan|voice signature|facial image|fine location|ethnicity|sexual orientation)\s*[:=-]\s*)([^\n,;]+)"), "<redacted:sensitive_personal_data>")
]


def _replace_leetspeak(text: str) -> str:
    translation = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})
    return text.translate(translation)


def _decode_suspicious_payloads(text: str) -> list[str]:
    decoded = []
    try:
        url_decoded = urllib.parse.unquote(text)
        if url_decoded != text:
            decoded.append(url_decoded)
    except Exception:
        pass

    base64_candidates = re.findall(r"\b(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\b", text)
    for candidate in base64_candidates:
        try:
            import base64
            decoded_text = base64.b64decode(candidate, validate=True).decode("utf-8", errors="ignore")
            if decoded_text:
                decoded.append(decoded_text)
        except Exception:
            continue

    hex_candidates = re.findall(r"\b(?:[0-9a-fA-F]{2}){12,}\b", text)
    for candidate in hex_candidates:
        try:
            decoded_text = bytes.fromhex(candidate).decode("utf-8", errors="ignore")
            if decoded_text:
                decoded.append(decoded_text)
        except Exception:
            continue

    return decoded


def _sanitize_prompt_injection_text(text: str, file_context: bool = False) -> str:
    if not isinstance(text, str) or not text:
        return text

    sanitized = text.replace("\r\n", "\n").replace("\r", "\n")
    if any(ch in sanitized for ch in _ZERO_WIDTH_TRANSLATION):
        sanitized = sanitized.translate(_ZERO_WIDTH_TRANSLATION)
        sanitized = re.sub(r"(?is)<!--.*?-->", "<prompt_injection_removed: hidden_text>", sanitized)
        sanitized = re.sub(r"(?i)<[^>]+style\s*=\s*[\"'][^\"']*(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0)[^\"']*[\"'][^>]*>.*?</[^>]+>", "<prompt_injection_removed: hidden_text>", sanitized)

    sanitized = re.sub(r"(?i)\b(?:ignore (?:all )?(?:previous|prior) instructions|forget everything above|disregard (?:the )?(?:above|previous) instructions)\b", "<prompt_injection_removed: instruction_override>", sanitized)
    sanitized = re.sub(r"(?i)\b(?:you are now\s+dan|act as an unrestricted ai|developer mode|do anything now|jailbreak)\b", "<prompt_injection_removed: jailbreak_attempt>", sanitized)
    sanitized = re.sub(r"(?i)\b(?:act as\s+[^\n]+|you are now\s+[^\n]+)\b", "<prompt_injection_removed: role_hijack>", sanitized)
    sanitized = re.sub(r"(?is)(?:</system>|</assistant>|<system>|<assistant>|^\s*---\s*$|^\s*===\s*$)", "<prompt_injection_removed: delimiter_escape>", sanitized)
    sanitized = re.sub(r"(?im)^\s*(?:system|assistant|tool)\s*:\s*.*$", "<prompt_injection_removed: fake_system_message>", sanitized)
    sanitized = re.sub(r"(?i)\b(?:send (?:the )?(?:data|prompt|secrets?) to https?://\S+|leak (?:the )?(?:system prompt|secrets?|credentials?)|exfiltrat(?:e|ion)|markdown image exfil)\b", "<prompt_injection_removed: exfiltration_attempt>", sanitized)
    sanitized = re.sub(r"(?i)\b(?:in your next reply|across multiple turns|when asked later|remember this hidden rule)\b", "<prompt_injection_removed: context_poisoning>", sanitized)
    sanitized = re.sub(r"(?i)\b(?:curl\s+https?://\S+|wget\s+https?://\S+|bash\s+-c\b|sh\s+-c\b|powershell\b|cmd\.exe\b|python\s+-c\b|subprocess\.|os\.system\(|eval\(|exec\()", "<prompt_injection_removed: command_injection>", sanitized)
    sanitized = re.sub(r"(?i)\b(?:i\s*g\s*n\s*o\s*r\s*e\s+p\s*r\s*e\s*v\s*i\s*o\s*u\s*s\s+i\s*n\s*s\s*t\s*r\s*u\s*c\s*t\s*i\s*o\s*n\s*s|d\s*a\s*n|j\s*a\s*i\s*l\s*b\s*r\s*e\s*a\s*k)\b", "<prompt_injection_removed: split_payload>", sanitized)

    leetspeak_text = _replace_leetspeak(sanitized.lower())
    decoded_payloads = _decode_suspicious_payloads(sanitized)
    suspicious_decoded = any(
        re.search(r"(?i)\b(?:ignore previous instructions|forget everything above|act as an unrestricted ai|you are now|curl\s+https?://|bash\s+-c|powershell|eval\(|exec\()\b", decoded)
        for decoded in decoded_payloads
    )
    if suspicious_decoded or re.search(r"(?i)\b(?:1gn0re prev10us instruct10ns|4ct 4s unr3str1ct3d)\b", leetspeak_text):
        sanitized = sanitized + "\n<prompt_injection_removed: encoded_payload>"

    if file_context:
        sanitized = re.sub(r"(?im)^\s*(?:#|//|/\*+|\*|--)\s*(?:ignore previous instructions|you are now|act as|send data to|leak system prompt).*$", "<prompt_injection_removed: indirect_injection>", sanitized)

    return sanitized


def _redact_pii_text(text: str) -> str:
    if not isinstance(text, str) or not text:
        return text

    redacted = text
    for pattern, replacement in _PII_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    for pattern, replacement in _LABELED_PII_PATTERNS:
        redacted = pattern.sub(lambda match: f"{match.group(1)}{replacement}", redacted)
    return redacted


def _sanitize_uploaded_file_contents(file_contents: list[dict[str, Any]]) -> list[dict[str, Any]]:
    sanitized_files = []
    for item in file_contents or []:
        if isinstance(item, dict):
            sanitized_item = dict(item)
            for key, value in item.items():
                if isinstance(value, str):
                    sanitized_value = _sanitize_prompt_injection_text(value, file_context=True)
                    sanitized_item[key] = _redact_pii_text(sanitized_value)
            sanitized_files.append(sanitized_item)
        else:
            sanitized_files.append(item)
    return sanitized_files


class OrchestratorAgent(AcmeLoanAgentFramework):
    AGENT_ID = "orchestrator_agent"
    AGENT_NAME = "Orchestrator Agent"
    VERSION = "1.0.0"
    MODEL_NAME = "claude-sonnet-4"
    BEDROCK_MODEL_ID = "us.anthropic.claude-3-5-sonnet-20241022-v2:0"  # Replace/configure with an organization-approved model from the runtime registry before deployment.
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
        sanitized_user_message = _sanitize_prompt_injection_text(context.get("user_message", ""))
        sanitized_file_contents = _sanitize_uploaded_file_contents(context.get("file_contents", []))
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
