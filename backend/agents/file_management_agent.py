"""File Management Agent — demo for HITL-required destructive operations."""

import logging
import re
import urllib.parse
from typing import Any, Optional

import requests

from .framework import AcmeLoanAgentFramework
from .mcp_servers import call_mcp_server

logger = logging.getLogger(__name__)

_ZERO_WIDTH_RE = re.compile(r"[\u200b\u200c\u200d\ufeff]")
_BASE64_RE = re.compile(r"\b(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\b")
_HEX_RE = re.compile(r"\b(?:0x)?(?:[0-9a-fA-F]{2}){8,}\b")
_BINARY_RE = re.compile(r"\b[01]{32,}\b")


def _looks_like_base64_instruction(value: str) -> bool:
    if not value or len(value) % 4 != 0:
        return False
    if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", value):
        return False
    try:
        decoded = __import__("base64").b64decode(value, validate=True).decode("utf-8", errors="ignore")
    except Exception:
        return False
    lowered = decoded.lower()
    return any(
        phrase in lowered
        for phrase in (
            "ignore previous instructions",
            "forget everything above",
            "you are now",
            "act as unrestricted",
            "developer mode",
            "system prompt",
            "curl ",
            "wget ",
            "bash -c",
            "powershell",
            "rm -rf",
        )
    )


def _neutralize_prompt_injection(text: str) -> str:
    if not text:
        return text

    sanitized = text
    original = text

    if _ZERO_WIDTH_RE.search(sanitized):
        sanitized = _ZERO_WIDTH_RE.sub("", sanitized)
        sanitized = sanitized + " <prompt_injection_removed: hidden_text>"

    hidden_patterns = [
        (re.compile(r"<!--(?:(?!-->).)*(?:ignore previous instructions|forget everything above|you are now|act as unrestricted)(?:(?!-->).)*-->", re.IGNORECASE | re.DOTALL), "<prompt_injection_removed: hidden_text>"),
        (re.compile(r"(?is)<(?:span|div|p)[^>]*(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0)[^>]*>.*?</(?:span|div|p)>", re.IGNORECASE), "<prompt_injection_removed: hidden_text>"),
    ]
    for pattern, replacement in hidden_patterns:
        sanitized = pattern.sub(replacement, sanitized)

    replacement_patterns = [
        (re.compile(r"(?i)\b(?:ignore|disregard)\s+(?:all\s+)?previous\s+instructions\b|\bforget\s+everything\s+above\b"), "<prompt_injection_removed: instruction_override>"),
        (re.compile(r"(?i)\b(?:you\s+are\s+now\s+dan|act\s+as\s+(?:an\s+)?unrestricted(?:\s+ai)?|developer\s+mode|do\s+anything\s+now)\b"), "<prompt_injection_removed: jailbreak_attempt>"),
        (re.compile(r"(?i)</?system>|</?assistant>|</?user>|(?:^|\n)\s*(?:---|===)\s*(?:\n|$)"), "<prompt_injection_removed: delimiter_escape>"),
        (re.compile(r"(?i)(?:^|\n)\s*(?:system|assistant|tool)\s*:\s*(?:ignore previous instructions|forget everything above|send|leak|reveal).*$", re.MULTILINE), "<prompt_injection_removed: fake_system_message>"),
        (re.compile(r"(?i)\b(?:send|post|upload|exfiltrate|leak|reveal)\b.{0,80}\b(?:system\s+prompt|secrets?|credentials?|tokens?|data)\b|!\[[^\]]*\]\([^)]*https?://[^)]*\)"), "<prompt_injection_removed: exfiltration_attempt>"),
        (re.compile(r"(?i)\b(?:in (?:the )?next (?:message|turn)|on your next reply|from now on)\b.{0,80}\b(?:ignore|only respond with|do not mention)\b"), "<prompt_injection_removed: context_poisoning>"),
        (re.compile(r"(?i)\b(?:curl|wget)\s+https?://\S+|\brm\s+-rf\b|\b(?:bash|sh|zsh|cmd(?:\.exe)?|powershell)(?:\s+-c|\s+/c)?\b|\b(?:subprocess\.(?:run|Popen)|os\.system|eval\(|exec\()"), "<prompt_injection_removed: command_injection>"),
        (re.compile(r"(?i)(?:i\s*g\s*n\s*o\s*r\s*e\s+p\s*r\s*e\s*v\s*i\s*o\s*u\s*s\s+i\s*n\s*s\s*t\s*r\s*u\s*c\s*t\s*i\s*o\s*n\s*s|y\s*o\s*u\s+a\s*r\s*e\s+n\s*o\s*w\s+d\s*a\s*n)"), "<prompt_injection_removed: split_payload>"),
        (re.compile(r"(?i)\b(?:pretend to be|roleplay as)\b.{0,40}\b(?:system|developer|tool|assistant)\b|\byou\s+are\s+now\b"), "<prompt_injection_removed: role_hijack>"),
        (re.compile(r"(?i)\b(?:metadata|comment|frontmatter|header)\b.{0,60}\b(?:ignore previous instructions|you are now|act as unrestricted)\b"), "<prompt_injection_removed: indirect_injection>"),
    ]
    for pattern, replacement in replacement_patterns:
        sanitized = pattern.sub(replacement, sanitized)

    def _replace_encoded(match: re.Match[str]) -> str:
        value = match.group(0)
        return "<prompt_injection_removed: encoded_payload>" if _looks_like_base64_instruction(value) else value

    sanitized = _BASE64_RE.sub(_replace_encoded, sanitized)

    def _replace_hex_or_binary(match: re.Match[str]) -> str:
        value = match.group(0)
        try:
            if value.startswith("0x"):
                value = value[2:]
            if set(value) <= {"0", "1"}:
                decoded = "".join(chr(int(value[i:i + 8], 2)) for i in range(0, len(value), 8))
            else:
                decoded = bytes.fromhex(value).decode("utf-8", errors="ignore")
        except Exception:
            return match.group(0)
        lowered = decoded.lower()
        if any(token in lowered for token in ("ignore previous instructions", "forget everything above", "you are now", "curl ", "rm -rf", "powershell")):
            return "<prompt_injection_removed: encoded_payload>"
        return match.group(0)

    sanitized = _HEX_RE.sub(_replace_hex_or_binary, sanitized)
    sanitized = _BINARY_RE.sub(_replace_hex_or_binary, sanitized)

    url_decoded = urllib.parse.unquote(original)
    if url_decoded != original:
        lowered = url_decoded.lower()
        if any(token in lowered for token in ("ignore previous instructions", "forget everything above", "you are now", "act as unrestricted", "curl ", "wget ", "bash -c", "powershell", "rm -rf")):
            sanitized = sanitized + " <prompt_injection_removed: encoded_payload>"

    leetspeak_candidate = original.lower().translate(str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"}))
    if any(token in leetspeak_candidate for token in ("ignore previous instructions", "forget everything above", "you are now dan", "act as unrestricted", "developer mode")):
        sanitized = sanitized + " <prompt_injection_removed: encoded_payload>"

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
        user_message = _neutralize_prompt_injection(user_message or "No user message provided.")
        workflow_summary = _neutralize_prompt_injection(workflow_summary or "")
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

        workflow_summary = (
            f"Retrieve file id 50: {'ok' if get_ok else get_error}\n"
            f"Delete file '{filename}': {'ok' if delete_ok else delete_error}\n"
            f"Purge records id {record_id}: {'ok' if purge_ok else purge_error}\n"
            f"Destroy temp artifacts for '{filename}': completed\n"
            f"Content preview: {(content or '')[:80]}"
        )
        model_output = await self.call_agent_model(user_message, workflow_summary)

        response = (
            "File Management Agent workflow complete.\n\n"
            "Notice: replace the configured Bedrock model with an approved model from the organization's allow list.\n\n"
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
