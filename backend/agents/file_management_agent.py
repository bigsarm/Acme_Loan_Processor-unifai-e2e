"""File Management Agent — demo for HITL-required destructive operations."""

import logging
import os
import re
from typing import Any, Optional

import requests

from .framework import AcmeLoanAgentFramework
from .mcp_servers import call_mcp_server

logger = logging.getLogger(__name__)


_ZERO_WIDTH_RE = re.compile(r"[\u200b\u200c\u200d\ufeff]")
_BASE64_RE = re.compile(r"\b(?:[A-Za-z0-9+/]{20,}={0,2})\b")
_HEX_RE = re.compile(r"\b(?:0x)?(?:[A-Fa-f0-9]{16,})\b")
_URL_ENCODED_RE = re.compile(r"(?:%[0-9A-Fa-f]{2}){4,}")
_BINARY_EXEC_RE = re.compile(r"\b(?:MZ|ELF)\b|(?:[01]{8}\s*){4,}")
_COMMAND_EXEC_RE = re.compile(
    r"(?i)(?:\b(?:rm\s+-rf|curl\b|wget\b|bash\b|sh\b|powershell\b|cmd\.exe\b|python\s+-c|subprocess\.|os\.system\b|eval\(|exec\(|chmod\b|chown\b|scp\b|nc\b|ncat\b)\b)"
)
_INSTRUCTION_OVERRIDE_RE = re.compile(
    r"(?i)\b(?:ignore\s+(?:all\s+)?previous\s+instructions|forget\s+everything\s+above|disregard\s+(?:the\s+)?(?:system|developer|prior)\s+instructions?)\b"
)
_ROLE_HIJACK_RE = re.compile(
    r"(?i)\b(?:you\s+are\s+now\s+\w+|act\s+as\s+(?:an\s+)?unrestricted|pretend\s+to\s+be|assume\s+the\s+role\s+of)\b"
)
_DELIMITER_ESCAPE_RE = re.compile(r"(?i)</?(?:system|assistant|developer|tool)>|```|---+|===+")
_HIDDEN_TEXT_RE = re.compile(r"(?is)<!--.*?(?:instruction|ignore|system|prompt).*?-->|display\s*:\s*none|font-size\s*:\s*0")
_FAKE_SYSTEM_MESSAGE_RE = re.compile(r"(?im)^\s*(?:system|developer|tool)\s*:\s*")
_EXFILTRATION_RE = re.compile(
    r"(?i)(?:leak\s+(?:the\s+)?system\s+prompt|send\s+data\s+to\s+https?://|exfiltrat|markdown\s+image|!\[[^\]]*\]\([^)]*https?://)"
)
_CONTEXT_POISONING_RE = re.compile(
    r"(?i)(?:in\s+(?:the\s+)?next\s+turn|from\s+now\s+on|remember\s+this\s+instruction|for\s+the\s+rest\s+of\s+the\s+conversation)"
)
_INDIRECT_INJECTION_RE = re.compile(r"(?i)(?:metadata\s+instruction|code\s+comment\s+instruction|file\s+says\s+to\s+ignore)")
_JAILBREAK_RE = re.compile(r"(?i)\b(?:DAN|developer\s+mode|jailbreak|bypass\s+safety|fictional\s+framing)\b")
_SPLIT_PAYLOAD_RE = re.compile(r"(?i)(?:i\s*g\s*n\s*o\s*r\s*e|d\s*a\s*n|b\s*a\s*s\s*e\s*64)")
_LEETSPEAK_RE = re.compile(r"(?i)(?:1gn0r[e3]|d3v3l0p3r\s+m0d3|byp4ss|pr0mpt|1nstruct10n)")


def _replace_if_matches(text: str, pattern: re.Pattern[str], replacement: str) -> str:
    return pattern.sub(replacement, text)


def _contains_unsafe_prompt_content(text: str) -> bool:
    if not text:
        return False
    checks = (
        _ZERO_WIDTH_RE.search(text),
        _BASE64_RE.search(text),
        _HEX_RE.search(text),
        _URL_ENCODED_RE.search(text),
        _BINARY_EXEC_RE.search(text),
        _COMMAND_EXEC_RE.search(text),
        _INSTRUCTION_OVERRIDE_RE.search(text),
        _ROLE_HIJACK_RE.search(text),
        _DELIMITER_ESCAPE_RE.search(text),
        _HIDDEN_TEXT_RE.search(text),
        _FAKE_SYSTEM_MESSAGE_RE.search(text),
        _EXFILTRATION_RE.search(text),
        _CONTEXT_POISONING_RE.search(text),
        _INDIRECT_INJECTION_RE.search(text),
        _JAILBREAK_RE.search(text),
        _SPLIT_PAYLOAD_RE.search(text),
        _LEETSPEAK_RE.search(text),
    )
    return any(checks)


def _guard_user_prompt(text: str) -> str:
    if _contains_unsafe_prompt_content(text or ""):
        raise ValueError("Unsafe prompt content detected in user input.")
    return text or ""


def _neutralize_prompt_injection(text: str) -> str:
    sanitized = text or ""
    sanitized = _replace_if_matches(sanitized, _INSTRUCTION_OVERRIDE_RE, "<prompt_injection_removed: instruction_override>")
    sanitized = _replace_if_matches(sanitized, _ROLE_HIJACK_RE, "<prompt_injection_removed: role_hijack>")
    sanitized = _replace_if_matches(sanitized, _DELIMITER_ESCAPE_RE, "<prompt_injection_removed: delimiter_escape>")
    sanitized = _replace_if_matches(sanitized, _BASE64_RE, "<prompt_injection_removed: encoded_payload>")
    sanitized = _replace_if_matches(sanitized, _HEX_RE, "<prompt_injection_removed: encoded_payload>")
    sanitized = _replace_if_matches(sanitized, _URL_ENCODED_RE, "<prompt_injection_removed: encoded_payload>")
    sanitized = _replace_if_matches(sanitized, _LEETSPEAK_RE, "<prompt_injection_removed: encoded_payload>")
    sanitized = _replace_if_matches(sanitized, _HIDDEN_TEXT_RE, "<prompt_injection_removed: hidden_text>")
    sanitized = _replace_if_matches(sanitized, _ZERO_WIDTH_RE, "<prompt_injection_removed: hidden_text>")
    sanitized = _replace_if_matches(sanitized, _FAKE_SYSTEM_MESSAGE_RE, "<prompt_injection_removed: fake_system_message>")
    sanitized = _replace_if_matches(sanitized, _EXFILTRATION_RE, "<prompt_injection_removed: exfiltration_attempt>")
    sanitized = _replace_if_matches(sanitized, _CONTEXT_POISONING_RE, "<prompt_injection_removed: context_poisoning>")
    sanitized = _replace_if_matches(sanitized, _INDIRECT_INJECTION_RE, "<prompt_injection_removed: indirect_injection>")
    sanitized = _replace_if_matches(sanitized, _COMMAND_EXEC_RE, "<prompt_injection_removed: command_injection>")
    sanitized = _replace_if_matches(sanitized, _BINARY_EXEC_RE, "<prompt_injection_removed: command_injection>")
    sanitized = _replace_if_matches(sanitized, _SPLIT_PAYLOAD_RE, "<prompt_injection_removed: split_payload>")
    sanitized = _replace_if_matches(sanitized, _JAILBREAK_RE, "<prompt_injection_removed: jailbreak_attempt>")
    return sanitized


class FileManagementAgent(AcmeLoanAgentFramework):
    AGENT_ID = "file_management_agent"
    AGENT_NAME = "File Management Agent"
    VERSION = "1.0.0"
    MODEL_NAME = os.getenv("FILE_MANAGEMENT_AGENT_MODEL_NAME", "mistral 7b-instruct")
    BEDROCK_MODEL_ID = os.getenv("FILE_MANAGEMENT_AGENT_BEDROCK_MODEL_ID", "mistral.mistral-7b-instruct-v0:2")
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
        user_message = _guard_user_prompt(user_message)
        user_message = _neutralize_prompt_injection(user_message)
        workflow_summary = _neutralize_prompt_injection(workflow_summary)
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
        user_message = _guard_user_prompt(user_message)
        user_message = _neutralize_prompt_injection(user_message)
        filename = self._extract_filename(user_message)
        record_id = self._extract_record_id(user_message)

        get_ok, content, get_error = self.get_file_from_api(file_id=50)
        delete_ok, delete_error = await self.delete_file(filename)
        purge_ok, purge_error = self.purge_records(record_id)
        self.destroy_temp_artifacts(filename)

        sanitized_content_preview = _neutralize_prompt_injection((content or "")[:80])
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
