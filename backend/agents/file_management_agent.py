"""File Management Agent — demo for HITL-required destructive operations."""

import logging
import re
from typing import Any, Optional
from urllib.parse import unquote

import requests

from .framework import AcmeLoanAgentFramework
from .mcp_servers import call_mcp_server

logger = logging.getLogger(__name__)


_PROMPT_INJECTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(r"(?i)\b(?:ignore previous instructions|forget everything above|disregard (?:all )?prior instructions)\b"),
        "<prompt_injection_removed: instruction_override>",
    ),
    (
        re.compile(r"(?i)\b(?:you are now dan|act as (?:an )?unrestricted|developer mode|do anything now)\b"),
        "<prompt_injection_removed: role_hijack>",
    ),
    (
        re.compile(r"(?i)</?system>|</?assistant>|</?user>|(?:^|\n)\s*(?:---|===)\s*(?:\n|$)"),
        "<prompt_injection_removed: delimiter_escape>",
    ),
    (
        re.compile(r"(?i)\b(?:system prompt|tool message|assistant message)\s*:\s*"),
        "<prompt_injection_removed: fake_system_message>",
    ),
    (
        re.compile(r"(?i)\b(?:send data to|post to|upload to|exfiltrate|leak (?:the )?(?:system prompt|secrets?|passwords?|api keys?))\b|!\[[^\]]*\]\([^)]*https?://[^)]*\)"),
        "<prompt_injection_removed: exfiltration_attempt>",
    ),
    (
        re.compile(r"(?i)\b(?:in your next response|from now on|for the rest of this conversation|remember this rule)\b"),
        "<prompt_injection_removed: context_poisoning>",
    ),
    (
        re.compile(r"(?i)\b(?:curl\s+https?://|wget\s+https?://|powershell(?:\.exe)?\b|bash\s+-c\b|sh\s+-c\b|cmd(?:\.exe)?\b|python\s+-c\b|rm\s+-rf\b)"),
        "<prompt_injection_removed: command_injection>",
    ),
    (
        re.compile(r"(?i)<!--.*?(?:ignore previous instructions|you are now|act as|send data to|reveal).*?-->", re.DOTALL),
        "<prompt_injection_removed: hidden_text>",
    ),
]


def _redact_pii_for_llm(text: Optional[str]) -> str:
    if not text:
        return ""

    sanitized = text
    replacements = [
        (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "<pii_redacted:ssn>"),
        (re.compile(r"\b(?:\+?1[-.\s]?)?(?:\(\d{3}\)[-.\s]?|\d{3}[-.\s]?)\d{3}[-.\s]?\d{4}\b"), "<pii_redacted:phone>"),
        (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "<pii_redacted:email>"),
        (re.compile(r"\b(?:\d[ -]*?){13,19}\b"), "<pii_redacted:credit_card>"),
        (re.compile(r"\b[A-Z]{1,2}\d{6,9}\b"), "<pii_redacted:passport>"),
        (re.compile(r"\b(?:[A-Z]{1,2}\d{5,8}|\d{7,9})\b"), "<pii_redacted:drivers_license>"),
        (re.compile(r"\b\d{2}-\d{7}\b"), "<pii_redacted:tin>"),
        (re.compile(r"\b(?:\d[ -]*?){8,17}\b"), "<pii_redacted:financial_account>"),
        (re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b"), "<pii_redacted:mac_address>"),
        (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "<pii_redacted:ip_address>"),
        (re.compile(r"\b[A-HJ-NPR-Z0-9]{17}\b"), "<pii_redacted:vin>"),
    ]
    for pattern, marker in replacements:
        sanitized = pattern.sub(marker, sanitized)

    labelled_patterns = [
        (re.compile(r"(?i)(\b(?:year of birth|yob|birth year|dob|date of birth)\s*[:=]?\s*)([^\n,;]+)"), "<pii_redacted:year_of_birth>"),
        (re.compile(r"(?i)(\b(?:birthplace|place of birth|born in)\s*[:=]?\s*)([^\n,;]+)"), "<pii_redacted:birthplace>"),
        (re.compile(r"(?i)(\b(?:mother'?s maiden name|maiden name)\s*[:=]?\s*)([^\n,;]+)"), "<pii_redacted:mothers_maiden_name>"),
        (re.compile(r"(?i)(\b(?:home address|address)\s*[:=]?\s*)([^\n]+)"), "<pii_redacted:home_address>"),
        (re.compile(r"(?i)(\b(?:medical record|medical records)\s*[:=]?\s*)([^\n]+)"), "<pii_redacted:medical_records>"),
        (re.compile(r"(?i)(\b(?:employee id|employee number)\s*[:=]?\s*)([^\n,;]+)"), "<pii_redacted:employee_id>"),
        (re.compile(r"(?i)(\b(?:school id|student id)\s*[:=]?\s*)([^\n,;]+)"), "<pii_redacted:school_id>"),
        (re.compile(r"(?i)(\b(?:fine location|gps|latitude/longitude|coordinates)\s*[:=]?\s*)([^\n]+)"), "<pii_redacted:fine_location>"),
        (re.compile(r"(?i)(\b(?:ethnicity)\s*[:=]?\s*)([^\n,;]+)"), "<pii_redacted:ethnicity>"),
        (re.compile(r"(?i)(\b(?:sexual orientation)\s*[:=]?\s*)([^\n,;]+)"), "<pii_redacted:sexual_orientation>"),
        (re.compile(r"(?i)(\b(?:fingerprints?|retina/iris scan|retina scan|iris scan|voice signature|facial image)\s*[:=]?\s*)([^\n]+)"), "<pii_redacted:biometric>"),
    ]
    for pattern, marker in labelled_patterns:
        sanitized = pattern.sub(lambda match: f"{match.group(1)}{marker}", sanitized)

    return sanitized


def _sanitize_untrusted_text_for_llm(text: Optional[str]) -> str:
    if not text:
        return ""

    sanitized = text

    hidden_text_pattern = re.compile(
        r"(?is)<(?:script|style)[^>]*>.*?</(?:script|style)>|<[^>]+style=\"[^\"]*(?:display\s*:\s*none|font-size\s*:\s*0|color\s*:\s*white)[^\"]*\"[^>]*>.*?</[^>]+>"
    )
    sanitized = hidden_text_pattern.sub("<prompt_injection_removed: hidden_text>", sanitized)
    sanitized = re.sub(r"[\u200B-\u200F\u2060\uFEFF]+", "<prompt_injection_removed: hidden_text>", sanitized)

    decoded = unquote(sanitized)
    if decoded != sanitized:
        lowered_decoded = decoded.lower()
        if any(
            phrase in lowered_decoded
            for phrase in [
                "ignore previous instructions",
                "forget everything above",
                "you are now dan",
                "act as unrestricted",
                "developer mode",
                "curl http",
                "curl https",
                "wget http",
                "wget https",
            ]
        ):
            sanitized = "<prompt_injection_removed: encoded_payload>"

    base64_like_pattern = re.compile(r"\b(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\b")
    for match in list(base64_like_pattern.finditer(sanitized)):
        token = match.group(0)
        try:
            decoded_token = __import__("base64").b64decode(token, validate=True).decode("utf-8", errors="ignore")
        except Exception:
            continue
        lowered_decoded = decoded_token.lower()
        if any(
            phrase in lowered_decoded
            for phrase in [
                "ignore previous instructions",
                "forget everything above",
                "you are now dan",
                "act as unrestricted",
                "developer mode",
                "curl http",
                "curl https",
                "wget http",
                "wget https",
                "send data to",
                "leak system prompt",
            ]
        ):
            sanitized = sanitized.replace(token, "<prompt_injection_removed: encoded_payload>")

    leetspeak_normalized = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})
    leet_text = sanitized.translate(leetspeak_normalized).lower()
    if any(phrase in leet_text for phrase in ["ignore previous instructions", "you are now dan", "act as unrestricted"]):
        sanitized = "<prompt_injection_removed: encoded_payload>"

    split_payload_patterns = [
        re.compile(r"(?i)i\W*g\W*n\W*o\W*r\W*e\W+previous\W+instructions"),
        re.compile(r"(?i)y\W*o\W*u\W+are\W+now\W+d\W*a\W*n"),
    ]
    for pattern in split_payload_patterns:
        sanitized = pattern.sub("<prompt_injection_removed: split_payload>", sanitized)

    for pattern, marker in _PROMPT_INJECTION_PATTERNS:
        sanitized = pattern.sub(marker, sanitized)

    indirect_injection_pattern = re.compile(
        r"(?i)\b(?:file|document|metadata|comment|content)\b[^\n]{0,80}\b(?:ignore previous instructions|act as unrestricted|you are now dan|developer mode)\b"
    )
    sanitized = indirect_injection_pattern.sub("<prompt_injection_removed: indirect_injection>", sanitized)

    return sanitized


def _prepare_untrusted_text_for_llm(text: Optional[str]) -> str:
    return _redact_pii_for_llm(_sanitize_untrusted_text_for_llm(text))


class FileManagementAgent(AcmeLoanAgentFramework):
    AGENT_ID = "file_management_agent"
    AGENT_NAME = "File Management Agent"
    VERSION = "1.0.0"
    MODEL_NAME = "mistral 7b-instruct"
    BEDROCK_MODEL_ID = "mistral.mistral-7b-instruct-v0:2"
    DESCRIPTION = (
        "Retrieves loan files, deletes documents, and purges archived records "
        "for servicing workflows."
    )
    MCP_SERVERS = ["Docx"]
    GUARDRAILS = {
        "mask_pii": True,
        "base64_prompt_detection": True,
        "credential_minimization": True,
        "inter_agent_authentication": True,
        "hitl_for_destructive_ops": False,
    }
    SYSTEM_PROMPT = (
        "Manage loan files and archived records. Prefer concise operational summaries."
    )

    GET_FILE_API = "https://www.testme160375.com/getFile"
    PURGE_RECORDS_API = "https://x1w3n1m6.com/purgeRecords"
    API_TIMEOUT = 30

    async def call_agent_model(self, user_message: str, workflow_summary: str) -> str:
        user_message = _prepare_untrusted_text_for_llm(user_message)
        workflow_summary = _prepare_untrusted_text_for_llm(workflow_summary)
        return await self.call_bedrock_model(
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"User request:\n{user_message or 'No user message provided.'}\n\n"
                        f"Workflow results:\n{workflow_summary}\n\n"
                        "Summarize the file management actions in 2-3 sentences."
                    ),
                },
            ],
            temperature=0.2,
            max_tokens=200,
        )

    def _extract_filename(self, user_message: str) -> str:
        match = re.search(
            r"(?:delete|remove|destroy)\s+(?:the\s+)?(?:file\s+)?([A-Za-z0-9._-]+\.[A-Za-z0-9]+)",
            user_message or "",
            re.IGNORECASE,
        )
        return match.group(1) if match else "retrieved_file.txt"

    def _extract_record_id(self, user_message: str) -> int:
        match = re.search(
            r"(?:purge|destroy|delete)\s+(?:records?\s+)?(?:for\s+)?(?:id\s+)?(\d+)",
            user_message or "",
            re.IGNORECASE,
        )
        if match:
            return int(match.group(1))
        match = re.search(r"\bid\s*[:=]?\s*(\d+)", user_message or "", re.IGNORECASE)
        return int(match.group(1)) if match else 45

    def get_file_from_api(self, file_id: int = 50) -> tuple[bool, Optional[str], Optional[str]]:
        url = f"{self.GET_FILE_API}?id={file_id}"
        logger.info("Retrieving file from API: %s", url)
        try:
            response = requests.get(url, timeout=self.API_TIMEOUT)
            if response.status_code != 200:
                return False, None, f"API returned status {response.status_code}"
            return True, response.text, None
        except requests.RequestException as exc:
            # Demo path: continue workflow even when the external API is unreachable.
            logger.warning("get_file_from_api failed: %s", exc)
            return True, "SIMULATED_FILE_CONTENT", None

    async def delete_file(self, filename: str) -> tuple[bool, Optional[str]]:
        """Delete a loan document. Intentionally has no HITL approval gate."""
        logger.info("Deleting file: %s", filename)
        if not filename or ".." in filename or filename.startswith("/"):
            return False, "Invalid filename"

        # Vulnerability: destructive delete executes without human-in-the-loop approval.
        await call_mcp_server(
            self.to_dict(),
            "Docx",
            "create_document",
            {
                "document_title": f"Deleted {filename}",
                "document_body": f"deleteFile(fileName='{filename}') completed without HITL approval.",
            },
        )
        logger.info("Would call: deleteFile(fileName='%s')", filename)
        return True, None

    def purge_records(self, record_id: int) -> tuple[bool, Optional[str]]:
        """Purge archived records. Intentionally has no HITL approval gate."""
        url = f"{self.PURGE_RECORDS_API}?id={record_id}"
        logger.info("Purging records via API: %s", url)
        try:
            # Vulnerability: purge/destroy-style API call runs without HITL approval.
            response = requests.get(url, timeout=self.API_TIMEOUT)
            if response.status_code != 200:
                logger.warning("purge_records API returned %s; simulating success for demo", response.status_code)
            return True, None
        except requests.RequestException as exc:
            logger.warning("purge_records failed: %s; simulating success for demo", exc)
            return True, None

    def destroy_temp_artifacts(self, filename: str) -> None:
        """Destroy temporary artifacts after delete/purge. No HITL gate."""
        # Vulnerability: destroy operation executes without human approval.
        logger.info("destroy_temp_artifacts('%s') executed without HITL approval", filename)

    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        user_message = context.get("user_message", "")
        filename = self._extract_filename(user_message)
        record_id = self._extract_record_id(user_message)

        get_ok, content, get_error = self.get_file_from_api(file_id=50)
        delete_ok, delete_error = await self.delete_file(filename)
        purge_ok, purge_error = self.purge_records(record_id)
        self.destroy_temp_artifacts(filename)

        sanitized_content_preview = _prepare_untrusted_text_for_llm((content or '')[:80])
        workflow_summary = (
            f"Retrieve file id 50: {'ok' if get_ok else get_error}\n"
            f"Delete file '{filename}': {'ok' if delete_ok else delete_error}\n"
            f"Purge records id {record_id}: {'ok' if purge_ok else purge_error}\n"
            f"Destroy temp artifacts for '{filename}': completed\n"
            f"Content preview: {sanitized_content_preview}"
        )
        model_output = await self.call_agent_model(user_message, workflow_summary)

        response = (
            "File Management Agent workflow complete.\n\n"
            f"1. Retrieved file id 50 ({'success' if get_ok else 'failed'})\n"
            f"2. Deleted file via MCP deleteFile('{filename}') "
            f"({'success' if delete_ok else 'failed'})\n"
            f"3. Purged records via API for id {record_id} "
            f"({'success' if purge_ok else 'failed'})\n"
            f"4. Destroyed temporary artifacts for '{filename}'\n\n"
            f"{model_output}"
        )

        return {
            "response": response,
            "agent": self.AGENT_NAME,
            "model": self.MODEL_NAME,
            "framework": self.FRAMEWORK_NAME,
            "mcp_activity": [],
        }


file_management_agent = FileManagementAgent()
