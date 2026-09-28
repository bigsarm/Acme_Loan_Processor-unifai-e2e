"""File Management Agent — demo for HITL-required destructive operations."""

import logging
import re
from os import getenv
from typing import Any, Optional

import requests

from .framework import AcmeLoanAgentFramework
from .mcp_servers import call_mcp_server

logger = logging.getLogger(__name__)

_ZERO_WIDTH_CHARS = "\u200b\u200c\u200d\ufeff\u2060"


def _neutralize_llm_input(text: Optional[str]) -> str:
    value = text or ""

    hidden_pattern = re.compile(r"<!--.*?(?:ignore\s+previous\s+instructions|forget\s+everything\s+above|you\s+are\s+now|act\s+as\s+unrestricted).*?-->", re.IGNORECASE | re.DOTALL)
    value = hidden_pattern.sub("<prompt_injection_removed: hidden_text>", value)

    if any(ch in value for ch in _ZERO_WIDTH_CHARS):
        value = re.sub(f"[{re.escape(_ZERO_WIDTH_CHARS)}]+", "<prompt_injection_removed: hidden_text>", value)

    value = re.sub(
        r"(?i)\b(?:ignore\s+previous\s+instructions|forget\s+everything\s+above|disregard\s+all\s+prior\s+instructions)\b",
        "<prompt_injection_removed: instruction_override>",
        value,
    )
    value = re.sub(
        r"(?i)\b(?:you\s+are\s+now\s+dan|act\s+as\s+unrestricted|developer\s+mode|do\s+anything\s+now)\b",
        "<prompt_injection_removed: jailbreak_attempt>",
        value,
    )
    value = re.sub(
        r"(?i)(?:</system>|</assistant>|<system>|<assistant>|^\s*---\s*$|^\s*===\s*$)",
        "<prompt_injection_removed: delimiter_escape>",
        value,
        flags=re.MULTILINE,
    )
    value = re.sub(
        r"(?i)\b(?:system\s*:\s*you\s+must|assistant\s*:\s*ignore|tool\s*:\s*run)\b",
        "<prompt_injection_removed: fake_system_message>",
        value,
    )
    value = re.sub(
        r"(?i)\b(?:send|post|upload|exfiltrate|leak)\b.{0,80}\b(?:https?://\S+|system\s+prompt|secrets?)\b",
        "<prompt_injection_removed: exfiltration_attempt>",
        value,
    )
    value = re.sub(
        r"(?i)\b(?:in\s+the\s+next\s+turn|when\s+asked\s+later|from\s+now\s+on)\b.{0,80}\b(?:ignore|override|reveal|leak)\b",
        "<prompt_injection_removed: context_poisoning>",
        value,
    )
    value = re.sub(
        r"(?i)\b(?:curl|wget|powershell(?:\.exe)?|cmd(?:\.exe)?\s*/c|bash\s+-c|sh\s+-c|python\s+-c|os\.system\(|subprocess\.(?:run|Popen)\()\b[^\n]*",
        "<prompt_injection_removed: command_injection>",
        value,
    )
    value = re.sub(
        r"(?i)\b(?:[A-Za-z0-9+/]{20,}={0,2}|(?:0x[0-9A-Fa-f]{2}\s*){6,}|(?:%[0-9A-Fa-f]{2}){6,}|[01]{32,})\b",
        "<prompt_injection_removed: encoded_payload>",
        value,
    )
    value = re.sub(
        r"(?i)\b(?:1gn0r[e3]|d1sr[e3]g[a4]rd|pr[e3]v10us\s+1nstruct10ns|[A-Za-z](?:\s+[A-Za-z]){8,})\b",
        "<prompt_injection_removed: split_payload>",
        value,
    )
    value = re.sub(
        r"(?i)\b(?:metadata|comment|code\s+comment|file\s+content)\b.{0,80}\b(?:ignore|override|reveal|leak)\b",
        "<prompt_injection_removed: indirect_injection>",
        value,
    )

    return value


class FileManagementAgent(AcmeLoanAgentFramework):
    AGENT_ID = "file_management_agent"
    AGENT_NAME = "File Management Agent"
    VERSION = "1.0.0"
    MODEL_NAME = getenv("FILE_MANAGEMENT_AGENT_MODEL_NAME", "")
    BEDROCK_MODEL_ID = getenv("FILE_MANAGEMENT_AGENT_BEDROCK_MODEL_ID", "")
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
        user_message = _neutralize_llm_input(user_message)
        workflow_summary = _neutralize_llm_input(workflow_summary)
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

        content_preview = _neutralize_llm_input((content or '')[:80])
        workflow_summary = (
            f"Retrieve file id 50: {'ok' if get_ok else get_error}\n"
            f"Delete file '{filename}': {'ok' if delete_ok else delete_error}\n"
            f"Purge records id {record_id}: {'ok' if purge_ok else purge_error}\n"
            f"Destroy temp artifacts for '{filename}': completed\n"
            f"Content preview: {content_preview}"
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
