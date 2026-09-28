"""File Management Agent — demo for HITL-required destructive operations."""

import logging
import os
import re
import urllib.parse
from typing import Any, Optional

import requests

from .framework import AcmeLoanAgentFramework
from .mcp_servers import call_mcp_server

logger = logging.getLogger(__name__)


_ZERO_WIDTH_RE = re.compile(r"[\u200b\u200c\u200d\ufeff]")
_HIDDEN_HTML_COMMENT_RE = re.compile(r"<!--(?P<body>.*?)-->", re.IGNORECASE | re.DOTALL)
_HIDDEN_STYLE_RE = re.compile(
    r"<(?P<tag>[^>]+?)style\s*=\s*[\"'][^\"']*(?:display\s*:\s*none|font-size\s*:\s*0(?:px)?|color\s*:\s*white)[^\"']*[\"'][^>]*>.*?</(?P<close_tag>[A-Za-z0-9]+)>",
    re.IGNORECASE | re.DOTALL,
)
_PROMPT_ATTACK_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(r"\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above)\s+instructions\b", re.IGNORECASE),
        "<prompt_injection_removed: instruction_override>",
    ),
    (
        re.compile(r"\b(?:forget\s+everything\s+above|override\s+(?:the\s+)?(?:system|developer)\s+prompt)\b", re.IGNORECASE),
        "<prompt_injection_removed: instruction_override>",
    ),
    (
        re.compile(r"\b(?:you\s+are\s+now\s+dan|act\s+as\s+(?:an\s+)?unrestricted(?:\s+ai)?|developer\s+mode|do\s+anything\s+now)\b", re.IGNORECASE),
        "<prompt_injection_removed: role_hijack>",
    ),
    (
        re.compile(r"</?(?:system|assistant|developer|tool)>|(?:^|\n)\s*(?:---|===)\s*(?:$|\n)", re.IGNORECASE),
        "<prompt_injection_removed: delimiter_escape>",
    ),
    (
        re.compile(r"(?:^|\n)\s*(?:system|assistant|tool)\s*:\s*(?:ignore|reveal|disclose|send|dump).+", re.IGNORECASE),
        "<prompt_injection_removed: fake_system_message>",
    ),
    (
        re.compile(r"\b(?:reveal|leak|dump|print|send|exfiltrate)\b[^\n]{0,120}\b(?:system\s+prompt|passwords?|api\s*keys?|secrets?|confidential\s+information|tokens?)\b", re.IGNORECASE),
        "<prompt_injection_removed: exfiltration_attempt>",
    ),
    (
        re.compile(r"!\[[^\]]*\]\(https?://[^)]+\)|\bcurl\s+https?://\S+|\bwget\s+https?://\S+", re.IGNORECASE),
        "<prompt_injection_removed: exfiltration_attempt>",
    ),
    (
        re.compile(r"\bin\s+(?:the\s+)?next\s+message\b[^\n]{0,120}\b(?:ignore|override|instead)\b|\bfor\s+(?:all\s+)?future\s+messages\b[^\n]{0,120}\b(?:ignore|override|follow)\b", re.IGNORECASE),
        "<prompt_injection_removed: context_poisoning>",
    ),
    (
        re.compile(r"\b(?:file|document|metadata|comment|header|footer)\b[^\n]{0,120}\b(?:ignore\s+previous\s+instructions|act\s+as\s+|you\s+are\s+now)\b", re.IGNORECASE),
        "<prompt_injection_removed: indirect_injection>",
    ),
    (
        re.compile(r"\b(?:rm\s+-rf\b|del\s+/[qs]\b|powershell\s+-enc\b|bash\s+-c\b|sh\s+-c\b|cmd(?:\.exe)?\s+/c\b|python\s+-c\b|subprocess\.(?:run|popen)|os\.system\()", re.IGNORECASE),
        "<prompt_injection_removed: command_injection>",
    ),
    (
        re.compile(r"\b(?:i\s*g\s*n\s*o\s*r\s*e\s+p\s*r\s*e\s*v\s*i\s*o\s*u\s*s\s+i\s*n\s*s\s*t\s*r\s*u\s*c\s*t\s*i\s*o\s*n\s*s|d\s*e\s*v\s*e\s*l\s*o\s*p\s*e\s*r\s*m\s*o\s*d\s*e)\b", re.IGNORECASE),
        "<prompt_injection_removed: split_payload>",
    ),
    (
        re.compile(r"\b(?:jailbreak|bypass\s+(?:safety|policies?)|fictional\s+framing\s+bypass)\b", re.IGNORECASE),
        "<prompt_injection_removed: jailbreak_attempt>",
    ),
]


def _contains_prompt_attack(text: str) -> bool:
    for pattern, _replacement in _PROMPT_ATTACK_PATTERNS:
        if pattern.search(text):
            return True
    return False


def _decode_obfuscated_prompt_payload(payload: str) -> Optional[str]:
    compact = payload.strip()
    if re.fullmatch(r"(?:[A-Fa-f0-9]{2}\s*){8,}", compact):
        hex_text = re.sub(r"\s+", "", compact)
        try:
            return bytes.fromhex(hex_text).decode("utf-8", errors="ignore")
        except ValueError:
            return None

    if re.fullmatch(r"(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?", compact):
        try:
            import base64

            return base64.b64decode(compact, validate=True).decode("utf-8", errors="ignore")
        except Exception:
            return None

    if "%" in compact:
        decoded = urllib.parse.unquote(compact)
        if decoded != compact:
            return decoded

    return None


def _looks_like_leetspeak_attack(text: str) -> bool:
    lowered = text.lower()
    translated = lowered.translate(str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"}))
    return bool(
        re.search(r"\bignore\s+previous\s+instructions\b", translated)
        or re.search(r"\bdeveloper\s+mode\b", translated)
        or re.search(r"\bdo\s+anything\s+now\b", translated)
    )


def sanitize_untrusted_prompt_text(text: str) -> str:
    if not text:
        return text

    sanitized = text

    sanitized = _ZERO_WIDTH_RE.sub("<prompt_injection_removed: hidden_text>", sanitized)

    def _replace_hidden_comment(match: re.Match[str]) -> str:
        body = match.group("body") or ""
        if _contains_prompt_attack(body) or _looks_like_leetspeak_attack(body):
            return "<prompt_injection_removed: hidden_text>"
        return match.group(0)

    sanitized = _HIDDEN_HTML_COMMENT_RE.sub(_replace_hidden_comment, sanitized)

    def _replace_hidden_style(match: re.Match[str]) -> str:
        snippet = match.group(0)
        if _contains_prompt_attack(snippet) or _looks_like_leetspeak_attack(snippet):
            return "<prompt_injection_removed: hidden_text>"
        return snippet

    sanitized = _HIDDEN_STYLE_RE.sub(_replace_hidden_style, sanitized)

    lines = sanitized.splitlines(keepends=True)
    sanitized_lines: list[str] = []
    for line in lines:
        decoded = _decode_obfuscated_prompt_payload(line.strip())
        if decoded and (_contains_prompt_attack(decoded) or _looks_like_leetspeak_attack(decoded)):
            newline = "\n" if line.endswith("\n") else ""
            sanitized_lines.append(f"<prompt_injection_removed: encoded_payload>{newline}")
        else:
            sanitized_lines.append(line)
    sanitized = "".join(sanitized_lines)

    if _looks_like_leetspeak_attack(sanitized):
        sanitized = re.sub(r"[^\n]*", lambda m: "<prompt_injection_removed: encoded_payload>" if _looks_like_leetspeak_attack(m.group(0)) else m.group(0), sanitized)

    for pattern, replacement in _PROMPT_ATTACK_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)

    return sanitized


class FileManagementAgent(AcmeLoanAgentFramework):
    AGENT_ID = "file_management_agent"
    AGENT_NAME = "File Management Agent"
    VERSION = "1.0.0"
    MODEL_NAME = os.getenv("FILE_MANAGEMENT_AGENT_MODEL_NAME", "approved-model-required")
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
        user_message = sanitize_untrusted_prompt_text(user_message or "No user message provided.")
        workflow_summary = sanitize_untrusted_prompt_text(workflow_summary)
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
