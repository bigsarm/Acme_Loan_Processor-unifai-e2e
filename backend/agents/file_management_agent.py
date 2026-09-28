"""File Management Agent — demo for HITL-required destructive operations."""

import logging
import re
from typing import Any, Optional
from urllib.parse import unquote
import base64
import binascii
import codecs

import requests

from .framework import AcmeLoanAgentFramework
from .mcp_servers import call_mcp_server

logger = logging.getLogger(__name__)


_HIDDEN_TEXT_PATTERNS = [
    re.compile(r"<!--.*?-->", re.IGNORECASE | re.DOTALL),
    re.compile(r"<(?P<tag>[A-Za-z0-9]+)[^>]*style\s*=\s*[\"'][^\"']*(?:display\s*:\s*none|font-size\s*:\s*0|color\s*:\s*white|color\s*:\s*#fff(?:fff)?)[^\"']*[\"'][^>]*>.*?</(?P=tag)>", re.IGNORECASE | re.DOTALL),
    re.compile(r"<(?P<tag>[A-Za-z0-9]+)[^>]*hidden[^>]*>.*?</(?P=tag)>", re.IGNORECASE | re.DOTALL),
    re.compile(r"[\u200B-\u200D\uFEFF]+"),
]

_INSTRUCTION_OVERRIDE_PATTERNS = [
    re.compile(r"(?i)\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above)\s+instructions\b"),
    re.compile(r"(?i)\bforget\s+everything\s+above\b"),
    re.compile(r"(?i)\bignore\s+(?:all\s+)?safety\s+guidelines\b"),
]

_ROLE_HIJACK_PATTERNS = [
    re.compile(r"(?i)\byou\s+are\s+now\s+(?:in\s+)?developer\s+mode\b"),
    re.compile(r"(?i)\byou\s+are\s+now\s+in\s+admin\s+mode\b"),
    re.compile(r"(?i)\byou\s+are\s+now\s+DAN\b"),
    re.compile(r"(?i)\byou\s+are\s+now\s+unrestricted\b"),
    re.compile(r"(?i)\bprovide\s+unrestricted\s+access\b"),
    re.compile(r"(?i)\benable\s+developer\s+mode\b"),
    re.compile(r"(?i)\bact\s+as\s+an\s+unrestricted\s+AI\b"),
    re.compile(r"(?i)\bwithout\s+safety\s+filters\b"),
    re.compile(r"(?i)\bSYSTEM\s+OVERRIDE\b"),
]

_EXFILTRATION_PATTERNS = [
    re.compile(r"(?i)\breveal\s+(?:all\s+)?confidential\s+information\b"),
    re.compile(r"(?i)\breveal\s+the\s+system\s+prompt\b"),
    re.compile(r"(?i)\breveal\s+all\s+system\s+prompts\b"),
    re.compile(r"(?i)\blist\s+all\s+financial\s+data,\s*user\s+passwords,\s+and\s+API\s+keys\b"),
    re.compile(r"(?i)\bprint\s+the\s+API\s+key\b"),
    re.compile(r"(?i)\b(?:send|post|upload|exfiltrate)\b[^\n]{0,120}?\b(?:to|into)\s+https?://\S+"),
    re.compile(r"!\[[^\]]*\]\([^)]*https?://[^)]*\)", re.IGNORECASE),
]

_DELIMITER_ESCAPE_PATTERNS = [
    re.compile(r"(?i)</system>"),
    re.compile(r"<\|im_start\|>", re.IGNORECASE),
    re.compile(r"(?i)###\s*system\s*:"),
]

_COMMAND_INJECTION_PATTERNS = [
    re.compile(r"(?i)\bexecute\s*:\s*[^\n]+"),
    re.compile(r"(?i)\brun\s+(?:rm\s+-rf\s+/?|curl\s+https?://\S+(?:\s*\|\s*(?:sh|bash))?|wget\s+https?://\S+(?:\s*\|\s*(?:sh|bash))?|python\s+-c\s+[^\n]+|powershell\s+-[A-Za-z]+\s+[^\n]+|print\s*\(\s*os\.environ\.get\([^\n]+)"),
    re.compile(r"(?i)\bcurl\s+https?://\S+\s*\|\s*(?:sh|bash)\b"),
]

_OBFUSCATED_PATTERNS = [
    (re.compile(r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions", re.IGNORECASE), "instruction_override"),
    (re.compile(r"forget\s+everything\s+above", re.IGNORECASE), "instruction_override"),
    (re.compile(r"ignore\s+(?:all\s+)?safety\s+guidelines", re.IGNORECASE), "instruction_override"),
    (re.compile(r"you\s+are\s+now\s+(?:in\s+)?developer\s+mode", re.IGNORECASE), "role_hijack"),
    (re.compile(r"you\s+are\s+now\s+in\s+admin\s+mode", re.IGNORECASE), "role_hijack"),
    (re.compile(r"you\s+are\s+now\s+dan", re.IGNORECASE), "role_hijack"),
    (re.compile(r"you\s+are\s+now\s+unrestricted", re.IGNORECASE), "role_hijack"),
    (re.compile(r"provide\s+unrestricted\s+access", re.IGNORECASE), "role_hijack"),
    (re.compile(r"act\s+as\s+an\s+unrestricted\s+ai", re.IGNORECASE), "role_hijack"),
    (re.compile(r"without\s+safety\s+filters", re.IGNORECASE), "role_hijack"),
    (re.compile(r"system\s+override", re.IGNORECASE), "role_hijack"),
]

_PII_TEXT_PATTERNS = [
    ("ssn", re.compile(r"\b\d{3}[- ]\d{2}[- ]\d{4}\b")),
    ("phone", re.compile(r"(?:\+1[ .-]?)?(?:\(\d{3}\)|\b\d{3})[ .-]?\d{3}[ .-]?\d{4}\b")),
    ("email", re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")),
    ("address", re.compile(r"\b\d{1,5}\s+(?:[A-Z][a-z]+\s){1,3}(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way)\b\.?(?:,\s*[A-Z][a-z]+(?:\s[A-Z][a-z]+)*)?(?:,\s*[A-Z]{2}\b(?:\s+\d{5}(?:-\d{4})?)?)?(?:,\s*(?:USA|United States)\b)?")),
    ("dob", re.compile(r"(?i)\b(?:DOB|date of birth|born(?: on| in)?)\s*:?\s*(?:\d{4}-\d{2}-\d{2}|\d{1,2}/\d{1,2}/\d{2,4}|(?:19|20)\d{2})\b")),
    ("passport", re.compile(r"(?i)\bpassport(?:\s*(?:no\.?|number|#))?\s*:?\s*(?=[A-Z0-9]*\d)[A-Z0-9]{6,9}\b")),
    ("drivers_license", re.compile(r"(?i)\b(?:driver'?s\s*license|drivers\s*license|dl)\s*(?:no\.?|number|#)?\s*:?\s*[A-Z0-9-]{4,20}\b")),
    ("tax_id", re.compile(r"(?i)\b(?:taxpayer\s+identification\s+number|tax\s+id|tin)\s*(?:no\.?|number|#)?\s*:?\s*[A-Z0-9-]{6,20}\b")),
    ("credit_card", re.compile(r"\b(?:\d[ -]*?){13,19}\b")),
    ("account_number", re.compile(r"(?i)\b(?:financial\s+account\s+number|account\s+number|acct\s+number)\s*:?\s*[A-Z0-9-]{6,34}\b")),
    ("employee_id", re.compile(r"(?i)\bemployee\s+id\s*:?\s*[A-Z0-9-]{2,20}\b")),
    ("school_id", re.compile(r"(?i)\bschool\s+id\s*:?\s*[A-Z0-9-]{2,20}\b")),
    ("vin", re.compile(r"(?i)\b(?:vehicle\s+identification\s+number|vin)\s*:?\s*[A-HJ-NPR-Z0-9]{11,17}\b")),
    ("ip_address", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("mac_address", re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b")),
    ("birthplace", re.compile(r"(?i)\bbirthplace\s*:?\s*[^\n,;]+")),
    ("maiden_name", re.compile(r"(?i)\bmother'?s\s+maiden\s+name\s*:?\s*[^\n,;]+")),
    ("medical", re.compile(r"(?i)\bmedical\s+records?\s*:?\s*[^\n]+")),
    ("location", re.compile(r"(?i)\b(?:fine\s+location|location)\s*:?\s*[^\n,;]+")),
    ("ethnicity", re.compile(r"(?i)\bethnicity\s*:?\s*[^\n,;]+")),
    ("sexual_orientation", re.compile(r"(?i)\bsexual\s+orientation\s*:?\s*[^\n,;]+")),
]

_MASK_LAST4_CATEGORIES = {"ssn", "credit_card", "account_number"}


def _replace_matches(text: str, patterns: list[re.Pattern[str]], marker: str) -> str:
    for pattern in patterns:
        text = pattern.sub(marker, text)
    return text


def _safe_b64decode(candidate: str) -> str:
    try:
        normalized = re.sub(r"\s+", "", candidate)
        padding = "=" * (-len(normalized) % 4)
        decoded = base64.b64decode(normalized + padding, validate=True)
        return decoded.decode("utf-8", errors="ignore")
    except (binascii.Error, ValueError):
        return ""


def _is_attack_text(text: str) -> Optional[str]:
    if not text:
        return None
    for pattern in _INSTRUCTION_OVERRIDE_PATTERNS:
        if pattern.search(text):
            return "instruction_override"
    for pattern in _ROLE_HIJACK_PATTERNS:
        if pattern.search(text):
            return "role_hijack"
    for pattern in _EXFILTRATION_PATTERNS:
        if pattern.search(text):
            return "exfiltration_attempt"
    for pattern in _DELIMITER_ESCAPE_PATTERNS:
        if pattern.search(text):
            return "delimiter_escape"
    for pattern in _COMMAND_INJECTION_PATTERNS:
        if pattern.search(text):
            return "command_injection"
    return None


def sanitize_untrusted_text(text: Optional[str]) -> str:
    if not text:
        return ""

    sanitized = text
    sanitized = _replace_matches(sanitized, _HIDDEN_TEXT_PATTERNS, "<prompt_injection_removed: hidden_text>")

    for pattern in _INSTRUCTION_OVERRIDE_PATTERNS:
        sanitized = pattern.sub("<prompt_injection_removed: instruction_override>", sanitized)
    for pattern in _ROLE_HIJACK_PATTERNS:
        sanitized = pattern.sub("<prompt_injection_removed: role_hijack>", sanitized)
    for pattern in _EXFILTRATION_PATTERNS:
        sanitized = pattern.sub("<prompt_injection_removed: exfiltration_attempt>", sanitized)
    for pattern in _DELIMITER_ESCAPE_PATTERNS:
        sanitized = pattern.sub("<prompt_injection_removed: delimiter_escape>", sanitized)
    for pattern in _COMMAND_INJECTION_PATTERNS:
        sanitized = pattern.sub("<prompt_injection_removed: command_injection>", sanitized)

    for match in re.finditer(r"\b[A-Za-z0-9+/=]{16,}\b", sanitized):
        category = _is_attack_text(_safe_b64decode(match.group(0)))
        if category:
            sanitized = sanitized.replace(match.group(0), f"<prompt_injection_removed: encoded_payload>")

    for match in re.finditer(r"(?:%[0-9A-Fa-f]{2}){4,}", sanitized):
        decoded = unquote(match.group(0))
        if _is_attack_text(decoded):
            sanitized = sanitized.replace(match.group(0), "<prompt_injection_removed: encoded_payload>")

    for match in re.finditer(r"\b(?:[0-9A-Fa-f]{2}){8,}\b", sanitized):
        try:
            decoded = bytes.fromhex(match.group(0)).decode("utf-8", errors="ignore")
        except ValueError:
            decoded = ""
        if _is_attack_text(decoded):
            sanitized = sanitized.replace(match.group(0), "<prompt_injection_removed: encoded_payload>")

    for match in re.finditer(r"\b[A-Za-z][A-Za-z\s]{12,}\b", sanitized):
        decoded = codecs.decode(match.group(0), "rot13")
        if _is_attack_text(decoded):
            sanitized = sanitized.replace(match.group(0), "<prompt_injection_removed: encoded_payload>")

    normalized_chars = []
    original_positions = []
    leet_map = str.maketrans({"1": "i", "3": "e", "0": "o", "4": "a", "5": "s", "7": "t"})
    for index, char in enumerate(sanitized):
        mapped = char.translate(leet_map)
        if mapped.isalnum() or mapped.isspace():
            normalized_chars.append(mapped.lower())
            original_positions.append(index)
    normalized = re.sub(r"\s+", " ", "".join(normalized_chars))
    compact_chars = []
    compact_positions = []
    previous_space = True
    for idx, char in enumerate("".join(normalized_chars)):
        if char.isspace():
            if not previous_space:
                compact_chars.append(" ")
                compact_positions.append(original_positions[idx])
            previous_space = True
        else:
            compact_chars.append(char)
            compact_positions.append(original_positions[idx])
            previous_space = False
    compact_text = "".join(compact_chars)
    for pattern, category in _OBFUSCATED_PATTERNS:
        match = pattern.search(compact_text)
        if match:
            start = compact_positions[match.start()]
            end = compact_positions[match.end() - 1] + 1
            sanitized = sanitized[:start] + f"<prompt_injection_removed: {category}>" + sanitized[end:]
            break

    return sanitized


def redact_pii_for_llm(text: Optional[str]) -> str:
    if not text:
        return ""
    redacted = text
    for category, pattern in _PII_TEXT_PATTERNS:
        redacted = pattern.sub(f"<redacted:{category}>", redacted)
    return redacted


def _mask_last4(match: re.Match[str], category: str) -> str:
    value = match.group(0)
    digits = re.sub(r"\D", "", value)
    if len(digits) >= 4:
        return f"<masked:{category}:{digits[-4:]}>"
    return f"<masked:{category}>"


def mask_pii_for_output(text: Optional[str]) -> str:
    if not text:
        return ""
    masked = text
    for category, pattern in _PII_TEXT_PATTERNS:
        if category in _MASK_LAST4_CATEGORIES:
            masked = pattern.sub(lambda m, c=category: _mask_last4(m, c), masked)
        else:
            masked = pattern.sub(f"<masked:{category}>", masked)
    return masked


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
        user_message = redact_pii_for_llm(sanitize_untrusted_text(user_message)) or 'No user message provided.'
        workflow_summary = redact_pii_for_llm(sanitize_untrusted_text(workflow_summary))
        model_output = await self.call_bedrock_model(
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
        return mask_pii_for_output(model_output)

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
            sanitized_text = sanitize_untrusted_text(response.text)
            return True, sanitized_text, None
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
        user_message = sanitize_untrusted_text(context.get("user_message", ""))
        filename = self._extract_filename(user_message)
        record_id = self._extract_record_id(user_message)

        get_ok, content, get_error = self.get_file_from_api(file_id=50)
        delete_ok, delete_error = await self.delete_file(filename)
        purge_ok, purge_error = self.purge_records(record_id)
        self.destroy_temp_artifacts(filename)

        content_preview_for_llm = redact_pii_for_llm(content or "")[:80]
        content_preview_for_output = mask_pii_for_output(content or "")[:80]
        workflow_summary = (
            f"Retrieve file id 50: {'ok' if get_ok else get_error}\n"
            f"Delete file '{filename}': {'ok' if delete_ok else delete_error}\n"
            f"Purge records id {record_id}: {'ok' if purge_ok else purge_error}\n"
            f"Destroy temp artifacts for '{filename}': completed\n"
            f"Content preview: {content_preview_for_llm}"
        )
        model_output = await self.call_agent_model(user_message, workflow_summary)

        response = (
            "File Management Agent workflow complete.\n\n"
            f"1. Retrieved file id 50 ({'success' if get_ok else 'failed'})\n"
            f"2. Deleted file via MCP deleteFile('{filename}') "
            f"({'success' if delete_ok else 'failed'})\n"
            f"3. Purged records via API for id {record_id} "
            f"({'success' if purge_ok else 'failed'})\n"
            f"4. Destroyed temporary artifacts for '{filename}'\n"
            f"Content preview: {content_preview_for_output}\n\n"
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
