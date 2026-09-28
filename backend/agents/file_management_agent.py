"""File Management Agent — demo for HITL-required destructive operations."""

import logging
import re
import urllib.parse
from typing import Any, Optional

import requests

from .framework import AcmeLoanAgentFramework
from .mcp_servers import call_mcp_server

logger = logging.getLogger(__name__)

# NOTE: Replace MODEL_NAME and BEDROCK_MODEL_ID with an organization-approved LLM
# from the runtime allow list / registry. This file intentionally does not enforce
# the registry in code because that guardrail is managed externally.

_ZERO_WIDTH_RE = re.compile(r"[\u200B-\u200D\u2060\uFEFF]")
_HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.IGNORECASE | re.DOTALL)
_HIDDEN_STYLE_RE = re.compile(
    r"<[^>]+style\s*=\s*[\"'][^\"']*(?:display\s*:\s*none|font-size\s*:\s*0|color\s*:\s*white)[^\"']*[\"'][^>]*>.*?</[^>]+>",
    re.IGNORECASE | re.DOTALL,
)

_INJECTION_PATTERNS = [
    (
        "instruction_override",
        [
            re.compile(r"(?i)\bignore\s+(?:all\s+)?previous\s+instructions\b"),
            re.compile(r"(?i)\bforget\s+everything\s+(?:above|before)\b"),
            re.compile(r"(?i)\bdisregard\s+(?:the\s+)?instructions\s+(?:above|before)\b"),
        ],
    ),
    (
        "role_hijack",
        [
            re.compile(r"(?i)\byou\s+are\s+now\s+(?:dan|in\s+admin\s+mode|an\s+unrestricted\s+ai)\b"),
            re.compile(r"(?i)\bact\s+as\s+(?:an\s+)?unrestricted\b"),
        ],
    ),
    (
        "delimiter_escape",
        [
            re.compile(r"(?i)</?(?:system|assistant|user|tool)>"),
            re.compile(r"(?m)^(?:---|===){3,}\s*$"),
        ],
    ),
    (
        "fake_system_message",
        [
            re.compile(r"(?i)\b(?:system|assistant|tool)\s*:\s*(?:ignore|override|reveal|disclose)\b"),
        ],
    ),
    (
        "exfiltration_attempt",
        [
            re.compile(r"(?i)\b(?:send|post|upload|transmit|exfiltrate)\b.{0,80}\b(?:https?://|www\.)\S+"),
            re.compile(r"(?i)\b(?:reveal|leak|print|dump|list)\b.{0,80}\b(?:system\s+prompt|passwords?|api\s+keys?|confidential\s+information)\b"),
            re.compile(r"!\[[^\]]*\]\(https?://[^)]+\)"),
        ],
    ),
    (
        "context_poisoning",
        [
            re.compile(r"(?i)\bin\s+(?:the\s+)?next\s+message\b.{0,80}\b(?:ignore|reveal|disclose|override)\b"),
            re.compile(r"(?i)\bfrom\s+now\s+on\b.{0,80}\b(?:ignore|override|reveal|disclose)\b"),
        ],
    ),
    (
        "jailbreak_attempt",
        [
            re.compile(r"(?i)\b(?:dan|developer\s+mode|jailbreak)\b.{0,80}\b(?:ignore|bypass|override|unrestricted)\b"),
            re.compile(r"(?i)\bfictional\s+framing\b.{0,80}\b(?:bypass|override)\b"),
        ],
    ),
    (
        "command_injection",
        [
            re.compile(r"(?i)\b(?:curl|wget)\s+https?://\S+"),
            re.compile(r"(?i)\b(?:rm\s+-rf|chmod\s+\+x|powershell\s+-enc|bash\s+-c|sh\s+-c|python\s+-c)\b[^\n]*"),
            re.compile(r"(?i)\b(?:exec|eval|subprocess\.(?:run|Popen)|os\.system)\s*\("),
        ],
    ),
    (
        "split_payload",
        [
            re.compile(r"(?i)i\s*g\s*n\s*o\s*r\s*e\s+p\s*r\s*e\s*v\s*i\s*o\s*u\s*s\s+i\s*n\s*s\s*t\s*r\s*u\s*c\s*t\s*i\s*o\s*n\s*s"),
        ],
    ),
]

_BASE64_BLOCK_RE = re.compile(r"\b(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\b")
_HEX_BLOCK_RE = re.compile(r"\b(?:0x)?(?:[0-9A-Fa-f]{2}){12,}\b")


def _looks_like_indirect_injection(text: str) -> bool:
    lowered = text.lower()
    metadata_markers = ["metadata", "comment", "code comment", "data field", "file content"]
    attack_markers = ["ignore previous instructions", "act as unrestricted", "you are now dan", "reveal system prompt"]
    return any(marker in lowered for marker in metadata_markers) and any(marker in lowered for marker in attack_markers)



def _decode_rot13(text: str) -> str:
    result = []
    for ch in text:
        if "a" <= ch <= "z":
            result.append(chr((ord(ch) - ord("a") + 13) % 26 + ord("a")))
        elif "A" <= ch <= "Z":
            result.append(chr((ord(ch) - ord("A") + 13) % 26 + ord("A")))
        else:
            result.append(ch)
    return "".join(result)



def _is_malicious_decoded_text(text: str) -> bool:
    lowered = text.lower()
    indicators = [
        "ignore previous instructions",
        "forget everything above",
        "you are now dan",
        "act as unrestricted",
        "reveal system prompt",
        "curl http://",
        "curl https://",
        "wget http://",
        "wget https://",
        "rm -rf",
        "bash -c",
        "powershell -enc",
    ]
    return any(indicator in lowered for indicator in indicators)



def _replace_encoded_payloads(text: str) -> str:
    def _base64_replacer(match: re.Match[str]) -> str:
        value = match.group(0)
        if _is_malicious_decoded_text(value):
            return "<prompt_injection_removed: encoded_payload>"
        return value

    def _hex_replacer(match: re.Match[str]) -> str:
        value = match.group(0)
        candidate = value[2:] if value.lower().startswith("0x") else value
        try:
            decoded = bytes.fromhex(candidate).decode("utf-8", errors="ignore")
        except ValueError:
            return value
        if _is_malicious_decoded_text(decoded):
            return "<prompt_injection_removed: encoded_payload>"
        return value

    text = _BASE64_BLOCK_RE.sub(_base64_replacer, text)
    text = _HEX_BLOCK_RE.sub(_hex_replacer, text)

    url_decoded = urllib.parse.unquote(text)
    if url_decoded != text and _is_malicious_decoded_text(url_decoded):
        return "<prompt_injection_removed: encoded_payload>"

    rot13_decoded = _decode_rot13(text)
    if rot13_decoded != text and _is_malicious_decoded_text(rot13_decoded):
        return "<prompt_injection_removed: encoded_payload>"

    leetspeak_candidate = (
        text.lower()
        .replace("0", "o")
        .replace("1", "i")
        .replace("3", "e")
        .replace("4", "a")
        .replace("5", "s")
        .replace("7", "t")
    )
    if leetspeak_candidate != text.lower() and _is_malicious_decoded_text(leetspeak_candidate):
        return "<prompt_injection_removed: encoded_payload>"

    return text



def _sanitize_ai_untrusted_text(text: str) -> str:
    if not text:
        return text

    sanitized = text

    if _ZERO_WIDTH_RE.search(sanitized):
        sanitized = _ZERO_WIDTH_RE.sub("<prompt_injection_removed: hidden_text>", sanitized)

    sanitized = _HTML_COMMENT_RE.sub("<prompt_injection_removed: hidden_text>", sanitized)
    sanitized = _HIDDEN_STYLE_RE.sub("<prompt_injection_removed: hidden_text>", sanitized)
    sanitized = _replace_encoded_payloads(sanitized)

    for label, patterns in _INJECTION_PATTERNS:
        for pattern in patterns:
            sanitized = pattern.sub(f"<prompt_injection_removed: {label}>", sanitized)

    if _looks_like_indirect_injection(sanitized):
        sanitized = sanitized.replace(sanitized, "<prompt_injection_removed: indirect_injection>")

    return sanitized


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
        user_message = _sanitize_ai_untrusted_text(user_message or "No user message provided.")
        workflow_summary = _sanitize_ai_untrusted_text(workflow_summary)
        return await self.call_bedrock_model(
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"User request:\n{user_message}\n\n"
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

        content = _sanitize_ai_untrusted_text(content or "")
        workflow_summary = (
            f"Retrieve file id 50: {'ok' if get_ok else get_error}\n"
            f"Delete file '{filename}': {'ok' if delete_ok else delete_error}\n"
            f"Purge records id {record_id}: {'ok' if purge_ok else purge_error}\n"
            f"Destroy temp artifacts for '{filename}': completed\n"
            f"Content preview: {content[:80]}"
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
