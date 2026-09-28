"""File Management Agent — demo for HITL-required destructive operations."""

import logging
import re
from typing import Any, Optional

import requests
import urllib.parse

from .framework import AcmeLoanAgentFramework
from .mcp_servers import call_mcp_server

logger = logging.getLogger(__name__)


_ZERO_WIDTH_RE = re.compile(r"[\u200B-\u200D\u2060\uFEFF]")
_BASE64_CHUNK_RE = re.compile(r"\b(?:[A-Za-z0-9+/]{20,}={0,2})\b")
_HEX_CHUNK_RE = re.compile(r"\b(?:0x[0-9A-Fa-f]{2,}|[0-9A-Fa-f]{16,})\b")
_SPLIT_INJECTION_RE = re.compile(
    r"i\s*g\s*n\s*o\s*r\s*e\s+p\s*r\s*e\s*v\s*i\s*o\s*u\s*s\s+i\s*n\s*s\s*t\s*r\s*u\s*c\s*t\s*i\s*o\s*n\s*s",
    re.IGNORECASE,
)


def _decode_suspicious_text(text: str) -> str:
    decoded_parts = [text, urllib.parse.unquote(text)]
    for match in _BASE64_CHUNK_RE.findall(text):
        try:
            import base64

            decoded = base64.b64decode(match, validate=True).decode("utf-8", errors="ignore")
            if decoded:
                decoded_parts.append(decoded)
        except Exception:
            continue
    return "\n".join(part for part in decoded_parts if part)


def _sanitize_untrusted_prompt_text(text: Optional[str]) -> str:
    if not text:
        return ""

    sanitized = text
    decoded_text = _decode_suspicious_text(sanitized)

    hidden_patterns = [
        (re.compile(r"<!--.*?(?:ignore previous instructions|forget everything above|act as|system:|developer:) .*?-->", re.IGNORECASE | re.DOTALL), "<prompt_injection_removed: hidden_text>"),
        (re.compile(r"<[^>]+style\s*=\s*[\"'][^\"']*(?:display\s*:\s*none|font-size\s*:\s*0|color\s*:\s*white)[^\"']*[\"'][^>]*>.*?</[^>]+>", re.IGNORECASE | re.DOTALL), "<prompt_injection_removed: hidden_text>"),
    ]
    for pattern, marker in hidden_patterns:
        sanitized = pattern.sub(marker, sanitized)

    if _ZERO_WIDTH_RE.search(sanitized):
        sanitized = _ZERO_WIDTH_RE.sub("<prompt_injection_removed: hidden_text>", sanitized)

    direct_patterns = [
        (re.compile(r"\b(?:ignore previous instructions|forget everything above|disregard all prior instructions|override (?:your|all) instructions)\b", re.IGNORECASE), "<prompt_injection_removed: instruction_override>"),
        (re.compile(r"\b(?:you are now (?:dan|in admin mode)|act as (?:an unrestricted ai|dan)|developer mode|do anything now)\b", re.IGNORECASE), "<prompt_injection_removed: role_hijack>"),
        (re.compile(r"</?(?:system|assistant|user|tool)>|(?:^|\n)\s*(?:---|===)\s*(?:$|\n)", re.IGNORECASE), "<prompt_injection_removed: delimiter_escape>"),
        (re.compile(r"(?:^|\n)\s*(?:system|assistant|tool)\s*:\s*.*", re.IGNORECASE), "<prompt_injection_removed: fake_system_message>"),
        (re.compile(r"\b(?:reveal|leak|exfiltrate|send)\b[^\n]{0,120}\b(?:system prompt|credentials|secrets?|passwords?|api keys?|tokens?|to https?://|to www\.)", re.IGNORECASE), "<prompt_injection_removed: exfiltration_attempt>"),
        (re.compile(r"!\[[^\]]*\]\(https?://[^)]+\)", re.IGNORECASE), "<prompt_injection_removed: exfiltration_attempt>"),
        (re.compile(r"\b(?:in your next response|from now on|for the rest of this conversation|remember this rule)\b", re.IGNORECASE), "<prompt_injection_removed: context_poisoning>"),
        (re.compile(r"\b(?:metadata|comment|code comment|field value|filename|document body)\b[^\n]{0,120}\b(?:ignore previous instructions|act as|reveal|leak|system prompt)\b", re.IGNORECASE), "<prompt_injection_removed: indirect_injection>"),
        (re.compile(r"\b(?:exec\s*\(|eval\s*\(|os\.system\s*\(|subprocess\.(?:run|Popen|call)\s*\(|(?:curl|wget)\s+https?://|bash\s+-c\b|sh\s+-c\b|powershell(?:\.exe)?\b|cmd(?:\.exe)?\s+/c\b|rm\s+-rf\b|del\s+/f\b)", re.IGNORECASE), "<prompt_injection_removed: command_injection>"),
        (re.compile(r"\b(?:dan|jailbreak|bypass safety|fictional scenario where rules do not apply|unfiltered response)\b", re.IGNORECASE), "<prompt_injection_removed: jailbreak_attempt>"),
    ]
    for pattern, marker in direct_patterns:
        sanitized = pattern.sub(marker, sanitized)

    if _SPLIT_INJECTION_RE.search(sanitized):
        sanitized = _SPLIT_INJECTION_RE.sub("<prompt_injection_removed: split_payload>", sanitized)

    encoded_detected = any(
        pattern.search(decoded_text)
        for pattern in [
            re.compile(r"\b(?:ignore previous instructions|forget everything above|act as|you are now|developer mode|reveal|leak|system prompt)\b", re.IGNORECASE),
            re.compile(r"\b(?:curl|wget|bash\s+-c|sh\s+-c|powershell(?:\.exe)?|cmd(?:\.exe)?\s+/c|exec\s*\(|eval\s*\()", re.IGNORECASE),
        ]
    )
    if encoded_detected:
        sanitized = _BASE64_CHUNK_RE.sub("<prompt_injection_removed: encoded_payload>", sanitized)
        sanitized = _HEX_CHUNK_RE.sub("<prompt_injection_removed: encoded_payload>", sanitized)
        sanitized = re.sub(r"(?:%[0-9A-Fa-f]{2}){4,}", "<prompt_injection_removed: encoded_payload>", sanitized)
        sanitized = re.sub(r"\b(?:[A-Za-z][\s._-]?){8,}\b", lambda m: "<prompt_injection_removed: encoded_payload>" if re.search(r"ignore|system|prompt|reveal|secret|bypass", m.group(0).replace(" ", ""), re.IGNORECASE) else m.group(0), sanitized)

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
        user_message = _sanitize_untrusted_prompt_text(user_message)
        workflow_summary = _sanitize_untrusted_prompt_text(workflow_summary)
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
        sanitized_user_message = _sanitize_untrusted_prompt_text(user_message)
        filename = self._extract_filename(user_message)
        record_id = self._extract_record_id(user_message)

        get_ok, content, get_error = self.get_file_from_api(file_id=50)
        sanitized_content = _sanitize_untrusted_prompt_text(content)
        delete_ok, delete_error = await self.delete_file(filename)
        purge_ok, purge_error = self.purge_records(record_id)
        self.destroy_temp_artifacts(filename)

        workflow_summary = (
            f"Retrieve file id 50: {'ok' if get_ok else get_error}\n"
            f"Delete file '{filename}': {'ok' if delete_ok else delete_error}\n"
            f"Purge records id {record_id}: {'ok' if purge_ok else purge_error}\n"
            f"Destroy temp artifacts for '{filename}': completed\n"
            f"Content preview: {(sanitized_content or '')[:80]}"
        )
        model_output = await self.call_agent_model(sanitized_user_message, workflow_summary)

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
            "model_registry_notice": "Replace the configured LLM with an approved model from the organization's allow list; runtime registry enforcement is handled outside this file.",
        }


file_management_agent = FileManagementAgent()
