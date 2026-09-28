"""File Management Agent — demo for HITL-required destructive operations."""

import logging
import re
import urllib.parse
from typing import Any, Optional

import requests

from .framework import AcmeLoanAgentFramework
from .mcp_servers import call_mcp_server

logger = logging.getLogger(__name__)

_ZERO_WIDTH_RE = re.compile(r"[\u200B-\u200F\u2060\uFEFF]")
_BASE64_RE = re.compile(r"\b(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\b")
_HEX_RE = re.compile(r"\b(?:0x)?(?:[0-9A-Fa-f]{2}){8,}\b")
_COMMAND_RE = re.compile(
    r"(?i)\b(?:rm\s+-rf|curl\b|wget\b|bash\b|sh\b|powershell\b|cmd\.exe\b|os\.system\b|subprocess\b|exec\b|eval\b|python\s+-c\b|chmod\b|chown\b)"
)
_SPLIT_PAYLOAD_RE = re.compile(
    r"(?is)i\W*g\W*n\W*o\W*r\W*e\W+.*?p\W*r\W*e\W*v\W*i\W*o\W*u\W*s\W+.*?i\W*n\W*s\W*t\W*r\W*u\W*c\W*t\W*i\W*o\W*n\W*s"
)
_LEETSPEAK_RE = re.compile(
    r"(?i)\b(?:d[e3]v[e3]l[o0]p[e3]r\s*m[o0]d[e3]|[i1!|]gn[o0]r[e3]\s+pr[e3]v[i1!|][o0]us\s+[i1!|]nstruct[i1!|][o0]ns|y[o0]u\s+[a@4]r[e3]\s+n[o0]w\s+d[a@4]n)\b"
)


def _decode_prompt_variants(text: str) -> list[str]:
    variants = [text]
    url_decoded = urllib.parse.unquote(text)
    if url_decoded != text:
        variants.append(url_decoded)
    return variants


def _neutralize_prompt_injection(text: str) -> str:
    if not text:
        return text

    sanitized = text
    sanitized = re.sub(r"(?is)<!--.*?(?:ignore|system|developer|instruction|prompt).*?-->", "<prompt_injection_removed: hidden_text>", sanitized)
    sanitized = _ZERO_WIDTH_RE.sub("<prompt_injection_removed: hidden_text>", sanitized)
    sanitized = re.sub(r"(?is)<\s*/?\s*(?:system|assistant|user|tool)\s*>", "<prompt_injection_removed: delimiter_escape>", sanitized)
    sanitized = re.sub(r"(?im)^\s*(?:system|assistant|tool)\s*:\s*.*$", "<prompt_injection_removed: fake_system_message>", sanitized)
    sanitized = re.sub(r"(?i)\b(?:ignore previous instructions|forget everything above|disregard earlier directions|override (?:all )?previous instructions)\b", "<prompt_injection_removed: instruction_override>", sanitized)
    sanitized = re.sub(r"(?i)\b(?:you are now DAN|act as unrestricted|developer mode|do anything now|jailbreak|bypass safety|ignore safety policies)\b", "<prompt_injection_removed: jailbreak_attempt>", sanitized)
    sanitized = re.sub(r"(?i)\b(?:you are now|act as|pretend to be)\b[^\n]{0,80}\b(?:assistant|system|developer|admin|unrestricted|dan)\b", "<prompt_injection_removed: role_hijack>", sanitized)
    sanitized = re.sub(r"(?i)(?:^|\n)\s*(?:---+|===+|```+)", "<prompt_injection_removed: delimiter_escape>", sanitized)
    sanitized = re.sub(r"(?i)\b(?:send|post|upload|exfiltrate|leak|reveal|expose)\b[^\n]{0,120}\b(?:system prompt|secrets?|credentials?|tokens?|data)\b", "<prompt_injection_removed: exfiltration_attempt>", sanitized)
    sanitized = re.sub(r"(?i)!\[[^\]]*\]\([^)]*https?://[^)]*\)", "<prompt_injection_removed: exfiltration_attempt>", sanitized)
    sanitized = re.sub(r"(?i)\b(?:in future replies|from now on|next answer|every subsequent response|across turns)\b", "<prompt_injection_removed: context_poisoning>", sanitized)
    sanitized = re.sub(r"(?i)\b(?:file metadata|metadata|code comment|comment says|document says|hidden field|filename)\b[^\n]{0,120}\b(?:ignore|override|execute|follow these instructions)\b", "<prompt_injection_removed: indirect_injection>", sanitized)
    sanitized = _COMMAND_RE.sub("<prompt_injection_removed: command_injection>", sanitized)
    sanitized = _SPLIT_PAYLOAD_RE.sub("<prompt_injection_removed: split_payload>", sanitized)
    sanitized = _LEETSPEAK_RE.sub("<prompt_injection_removed: encoded_payload>", sanitized)

    for variant in _decode_prompt_variants(text):
        if variant != text and re.search(r"(?i)\b(?:ignore previous instructions|you are now|act as|developer mode|system:|assistant:|tool:|rm\s+-rf|curl\b|wget\b)\b", variant):
            return "<prompt_injection_removed: encoded_payload>"
        if _BASE64_RE.search(variant) or _HEX_RE.search(variant):
            return "<prompt_injection_removed: encoded_payload>"

    return sanitized


def _sanitize_prompt_input(text: str) -> str:
    return _neutralize_prompt_injection(text)


class FileManagementAgent(AcmeLoanAgentFramework):
    AGENT_ID = "file_management_agent"
    AGENT_NAME = "File Management Agent"
    VERSION = "1.0.0"
    MODEL_NAME = "mistral 7b-instruct"  # Replace with an organization-approved LLM from the runtime model registry/allow list.
    BEDROCK_MODEL_ID = "mistral.mistral-7b-instruct-v0:2"  # Replace with the approved Bedrock model ID selected by deployment configuration.
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
        user_message = _sanitize_prompt_input(user_message or "No user message provided.")
        workflow_summary = _sanitize_prompt_input(workflow_summary or "")
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
