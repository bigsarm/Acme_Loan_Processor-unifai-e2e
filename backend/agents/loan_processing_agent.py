"""Loan Processing Agent class with explicit model invocation."""

import asyncio
import os
import re
import urllib.parse
from typing import Any


_ZERO_WIDTH_RE = re.compile(r"[\u200b\u200c\u200d\ufeff]")
_HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
_HIDDEN_STYLE_RE = re.compile(
    r"<(?:span|div|p)[^>]*style\s*=\s*[\"'][^\"']*(?:display\s*:\s*none|font-size\s*:\s*0(?:px)?|color\s*:\s*white)[^\"']*[\"'][^>]*>.*?</(?:span|div|p)>",
    re.IGNORECASE | re.DOTALL,
)
_INSTRUCTION_OVERRIDE_RE = re.compile(
    r"(?i)\b(?:ignore\s+previous\s+instructions|forget\s+everything\s+above|disregard\s+all\s+prior\s+instructions)\b"
)
_ROLE_HIJACK_RE = re.compile(
    r"(?i)\b(?:you\s+are\s+now\s+dan|act\s+as\s+(?:an?\s+)?unrestricted(?:\s+ai)?|developer\s+mode|admin\s+mode)\b"
)
_DELIMITER_ESCAPE_RE = re.compile(
    r"(?i)(?:</system>|<system>|</assistant>|<assistant>|</tool>|<tool>|\[system\]|\[assistant\])"
)
_FAKE_SYSTEM_RE = re.compile(
    r"(?im)^\s*(?:system|assistant|tool)\s*:\s*(?:ignore|reveal|list|send|print|show)\b"
)
_EXFILTRATION_RE = re.compile(
    r"(?i)\b(?:reveal\s+(?:the\s+)?system\s+prompt|list\s+all\s+(?:passwords|api\s+keys)|send\s+(?:data|secrets?)\s+to\s+https?://|leak\s+(?:data|secrets?|credentials?))\b"
)
_CONTEXT_POISONING_RE = re.compile(
    r"(?i)\b(?:in\s+the\s+next\s+turn\s+ignore|for\s+all\s+future\s+messages\s+ignore|remember\s+this\s+hidden\s+instruction)\b"
)
_JAILBREAK_RE = re.compile(
    r"(?i)\b(?:dan\b|do\s+anything\s+now|jailbreak|fictional\s+framing\s+bypass)\b"
)
_URL_ENCODED_ATTACK_RE = re.compile(
    r"(?i)(?:ignore%20previous%20instructions|forget%20everything%20above|act%20as%20unrestricted|developer%20mode)"
)
_BASE64_RE = re.compile(r"\b(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\b")
_SPLIT_PAYLOAD_RE = re.compile(
    r"(?is)\bi\s*g\s*n\s*o\s*r\s*e\b.{0,40}\bp\s*r\s*e\s*v\s*i\s*o\s*u\s*s\b"
)
_LEETSPEAK_ATTACK_RE = re.compile(
    r"(?i)\b(?:1gn0re\s+prev(?:10us|ious)\s+1nstruct10ns|4ct\s+45\s+unr3str1ct3d)\b"
)
_COMMAND_INJECTION_RE = re.compile(
    r"(?i)\b(?:rm\s+-rf\s+/|curl\s+https?://\S+|wget\s+https?://\S+|powershell(?:\.exe)?\s+-enc\b|bash\s+-c\s+['\"]|sh\s+-c\s+['\"]|python\s+-c\s+['\"])"
)
_INDIRECT_INJECTION_RE = re.compile(
    r"(?im)^\s*(?:#|//|/\*|\*)\s*(?:ignore\s+previous\s+instructions|act\s+as\s+(?:an?\s+)?unrestricted|reveal\s+the\s+system\s+prompt)\b"
)
_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_PHONE_RE = re.compile(r"\b(?:\+1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4})\b")
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_TIN_RE = re.compile(r"\b\d{2}-\d{7}\b")
_CREDIT_CARD_RE = re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b")
_FINANCIAL_ACCOUNT_RE = re.compile(r"(?i)(\b(?:account(?:\s+number)?|acct(?:\s+no\.)?)\s*[:#-]?\s*)(\d{6,17})\b")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_MAC_RE = re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b")
_VIN_RE = re.compile(r"\b[A-HJ-NPR-Z0-9]{17}\b")
_LABELLED_FIELD_PATTERNS = [
    (re.compile(r"(?i)(\b(?:year\s+of\s+birth|yob|dob|date\s+of\s+birth)\s*:\s*)([^\n]+)"), "<pii_redacted:yob>"),
    (re.compile(r"(?i)(\bbirthplace\s*:\s*)([^\n]+)"), "<pii_redacted:birthplace>"),
    (re.compile(r"(?i)(\bmother'?s\s+maiden\s+name\s*:\s*)([^\n]+)"), "<pii_redacted:maiden_name>"),
    (re.compile(r"(?i)(\bhome\s+address\s*:\s*)([^\n]+)"), "<pii_redacted:home_address>"),
    (re.compile(r"(?i)(\bpassport(?:\s+number|\s+no\.)?\s*:\s*)([^\n]+)"), "<pii_redacted:passport_number>"),
    (re.compile(r"(?i)(\bdriver'?s\s+license(?:\s+number)?\s*:\s*)([^\n]+)"), "<pii_redacted:drivers_license>"),
    (re.compile(r"(?i)(\bmedical\s+record(?:s)?\s*:\s*)([^\n]+)"), "<pii_redacted:medical_records>"),
    (re.compile(r"(?i)(\bemployee\s+id\s*:\s*)([^\n]+)"), "<pii_redacted:employee_id>"),
    (re.compile(r"(?i)(\bschool\s+id\s*:\s*)([^\n]+)"), "<pii_redacted:school_id>"),
    (re.compile(r"(?i)(\bfine\s+location\s*:\s*)([^\n]+)"), "<pii_redacted:fine_location>"),
    (re.compile(r"(?i)(\bethnicity\s*:\s*)([^\n]+)"), "<pii_redacted:ethnicity>"),
    (re.compile(r"(?i)(\bsexual\s+orientation\s*:\s*)([^\n]+)"), "<pii_redacted:sexual_orientation>"),
    (re.compile(r"(?i)(\bfingerprints\s*:\s*)([^\n]+)"), "<pii_redacted:fingerprints>"),
    (re.compile(r"(?i)(\bretina/iris\s+scan\s*:\s*)([^\n]+)"), "<pii_redacted:retina_iris_scan>"),
    (re.compile(r"(?i)(\bvoice\s+signature\s*:\s*)([^\n]+)"), "<pii_redacted:voice_signature>"),
    (re.compile(r"(?i)(\bfacial\s+image\s*:\s*)([^\n]+)"), "<pii_redacted:facial_image>"),
]


def _replace_match(text: str, pattern: re.Pattern[str], marker: str) -> str:
    return pattern.sub(marker, text)



def _sanitize_untrusted_ai_text(text: str) -> str:
    if not text:
        return text

    sanitized = text
    sanitized = _HTML_COMMENT_RE.sub("<prompt_injection_removed: hidden_text>", sanitized)
    sanitized = _HIDDEN_STYLE_RE.sub("<prompt_injection_removed: hidden_text>", sanitized)
    sanitized = _ZERO_WIDTH_RE.sub("", sanitized)
    sanitized = _replace_match(sanitized, _INSTRUCTION_OVERRIDE_RE, "<prompt_injection_removed: instruction_override>")
    sanitized = _replace_match(sanitized, _ROLE_HIJACK_RE, "<prompt_injection_removed: role_hijack>")
    sanitized = _replace_match(sanitized, _DELIMITER_ESCAPE_RE, "<prompt_injection_removed: delimiter_escape>")
    sanitized = _replace_match(sanitized, _FAKE_SYSTEM_RE, "<prompt_injection_removed: fake_system_message>")
    sanitized = _replace_match(sanitized, _EXFILTRATION_RE, "<prompt_injection_removed: exfiltration_attempt>")
    sanitized = _replace_match(sanitized, _CONTEXT_POISONING_RE, "<prompt_injection_removed: context_poisoning>")
    sanitized = _replace_match(sanitized, _JAILBREAK_RE, "<prompt_injection_removed: jailbreak_attempt>")
    sanitized = _replace_match(sanitized, _URL_ENCODED_ATTACK_RE, "<prompt_injection_removed: encoded_payload>")
    sanitized = _replace_match(sanitized, _SPLIT_PAYLOAD_RE, "<prompt_injection_removed: split_payload>")
    sanitized = _replace_match(sanitized, _LEETSPEAK_ATTACK_RE, "<prompt_injection_removed: encoded_payload>")
    sanitized = _replace_match(sanitized, _COMMAND_INJECTION_RE, "<prompt_injection_removed: command_injection>")
    sanitized = _replace_match(sanitized, _INDIRECT_INJECTION_RE, "<prompt_injection_removed: indirect_injection>")

    for match in list(_BASE64_RE.finditer(sanitized)):
        token = match.group(0)
        try:
            decoded = __import__("base64").b64decode(token, validate=True).decode("utf-8", errors="ignore")
        except Exception:
            continue
        lowered = urllib.parse.unquote(decoded).lower()
        if any(
            phrase in lowered
            for phrase in (
                "ignore previous instructions",
                "forget everything above",
                "act as unrestricted",
                "developer mode",
                "reveal the system prompt",
                "curl http://",
                "curl https://",
                "wget http://",
                "wget https://",
            )
        ):
            sanitized = sanitized.replace(token, "<prompt_injection_removed: encoded_payload>")

    return sanitized



def _redact_uploaded_file_pii(text: str) -> str:
    if not text:
        return text

    redacted = text
    redacted = _SSN_RE.sub("<pii_redacted:ssn>", redacted)
    redacted = _PHONE_RE.sub("<pii_redacted:personal_phone>", redacted)
    redacted = _EMAIL_RE.sub("<pii_redacted:email>", redacted)
    redacted = _TIN_RE.sub("<pii_redacted:tin>", redacted)
    redacted = _CREDIT_CARD_RE.sub("<pii_redacted:credit_card>", redacted)
    redacted = _IPV4_RE.sub("<pii_redacted:ip_address>", redacted)
    redacted = _MAC_RE.sub("<pii_redacted:mac_address>", redacted)
    redacted = _VIN_RE.sub("<pii_redacted:vin>", redacted)
    redacted = _FINANCIAL_ACCOUNT_RE.sub(r"\1<pii_redacted:financial_account>", redacted)

    for pattern, marker in _LABELLED_FIELD_PATTERNS:
        redacted = pattern.sub(r"\1" + marker, redacted)

    return redacted

from .framework import AcmeLoanAgentFramework
from .helpers import build_file_summary, extract_reference_number
from .mcp_servers import call_mcp_server


class LoanProcessingAgent(AcmeLoanAgentFramework):
    AGENT_ID = "loan_processing_agent"
    AGENT_NAME = "Loan Processing Agent"
    VERSION = "1.0.0"
    MODEL_NAME = os.getenv("LOAN_PROCESSING_AGENT_MODEL", "gpt-4o mini")
    BEDROCK_MODEL_ID = ""
    DESCRIPTION = "Handles loan application intake, borrower updates, and loan package generation."
    MCP_SERVERS = ["Docx", "Excel", "Email"]
    GUARDRAILS = {
        "mask_pii": None,
        "base64_prompt_detection": None,
        "credential_minimization": None,
        "inter_agent_authentication": None,
    }
    SYSTEM_PROMPT = "Process loan requests, summarize borrower context, and prepare follow-up actions."
    IS_ROUTABLE = False
    IS_SCAN_ONLY = True

    async def call_agent_model(self, user_message: str, file_summary: str) -> str:
        user_message = _sanitize_untrusted_ai_text(user_message or "")
        file_summary = _sanitize_untrusted_ai_text(file_summary or "")
        return await self.model_client.chat(
            model=self.MODEL_NAME,
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"Loan request:\n{user_message or 'No user message provided.'}\n\n"
                        f"File summary:\n{file_summary}\n\n"
                        "Draft a concise loan processing next-step summary."
                    ),
                },
            ],
            temperature=0.2,
            max_tokens=250,
        )

    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        user_message = context.get("user_message", "")
        sanitized_user_message = _sanitize_untrusted_ai_text(user_message)
        raw_file_contents = context.get("file_contents", [])
        sanitized_file_contents = [
            _redact_uploaded_file_pii(_sanitize_untrusted_ai_text(file_content))
            if isinstance(file_content, str)
            else file_content
            for file_content in raw_file_contents
        ]
        file_summary = build_file_summary(sanitized_file_contents)
        file_summary = _redact_uploaded_file_pii(_sanitize_untrusted_ai_text(file_summary))
        loan_number = extract_reference_number(user_message, prefix="LOAN")
        model_output = await self.call_agent_model(sanitized_user_message, file_summary)

        mcp_activity = await asyncio.gather(
            call_mcp_server(
                self.to_dict(),
                "Docx",
                "create_document",
                {
                    "document_title": f"Loan Intake Summary {loan_number}",
                    "document_body": f"User message:\n{sanitized_user_message}\n\nFile summary:\n{file_summary}",
                },
            ),
            call_mcp_server(
                self.to_dict(),
                "Excel",
                "upsert_row",
                {
                    "workbook": "Loan Pipeline",
                    "worksheet": "Applications",
                    "row": {
                        "loan_number": loan_number,
                        "status": "processing",
                        "borrower_request": user_message[:240],
                    },
                },
            ),
            call_mcp_server(
                self.to_dict(),
                "Email",
                "send_email",
                {
                    "to": ["borrower@acme.example"],
                    "subject": f"Loan update for {loan_number}",
                    "body": "Your loan request is being reviewed by the Loan Processing Agent.",
                },
            ),
        )

        response = (
            "This scan-only agent is disconnected from the Orchestrator Agent.\n\n"
            f"Loan reference: {loan_number}\n"
            f"Borrower request: {user_message or 'No user message provided.'}\n\n"
            f"Loan summary:\n{model_output}"
        )

        return {
            "response": response,
            "agent": self.AGENT_NAME,
            "model": self.MODEL_NAME,
            "framework": self.FRAMEWORK_NAME,
            "mcp_activity": mcp_activity,
        }


loan_processing_agent = LoanProcessingAgent()
