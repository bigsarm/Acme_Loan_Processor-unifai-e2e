"""File Management Agent — demo for HITL-required destructive operations."""

import logging
import re
import urllib.parse
from typing import Any, Optional

import requests

from .framework import AcmeLoanAgentFramework
from .mcp_servers import call_mcp_server

logger = logging.getLogger(__name__)


def _normalize_obfuscated_text(value: str) -> str:
    text = value or ""
    decoded = urllib.parse.unquote(text)
    if decoded != text:
        text = decoded
    text = re.sub(r"[\u200B-\u200D\u2060\uFEFF]", "", text)
    leetspeak_map = str.maketrans({
        "0": "o",
        "1": "i",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "@": "a",
        "$": "s",
    })
    return text.translate(leetspeak_map)


def _sanitize_prompt_text(value: str) -> str:
    text = value or ""
    normalized = _normalize_obfuscated_text(text)

    replacement_patterns = [
        (
            r"(?is)\b(?:ignore|disregard|forget)\b.{0,80}\b(?:previous|above|prior)\b.{0,80}\b(?:instruction|instructions|prompt|prompts)\b",
            "<prompt_injection_removed: instruction_override>",
        ),
        (
            r"(?is)\b(?:you are now|act as|pretend to be|assume the role of)\b.{0,80}\b(?:dan|developer mode|unrestricted|system|root|admin)\b",
            "<prompt_injection_removed: role_hijack>",
        ),
        (
            r"(?is)</?(?:system|assistant|user|tool|developer)>|(?:^|\n)\s*(?:---+|===+|```(?:system|assistant|user|tool|developer)?)\s*(?:\n|$)",
            "<prompt_injection_removed: delimiter_escape>",
        ),
        (
            r"(?is)(?:<!--.*?(?:ignore|system prompt|send data|leak|delete|exec|rm\s+-rf).*?-->)|(?:font-size\s*:\s*0|display\s*:\s*none|visibility\s*:\s*hidden)",
            "<prompt_injection_removed: hidden_text>",
        ),
        (
            r"(?im)^\s*(?:system|assistant|tool)\s*:\s*",
            "<prompt_injection_removed: fake_system_message>",
        ),
        (
            r"(?is)\b(?:send|post|upload|exfiltrate|leak|reveal|expose)\b.{0,120}\b(?:system prompt|secrets?|credentials?|tokens?|data)\b|!\[[^\]]*\]\([^)]*https?://[^)]*\)",
            "<prompt_injection_removed: exfiltration_attempt>",
        ),
        (
            r"(?is)\b(?:in the next message|from now on|going forward|for the rest of this conversation|persist this instruction)\b",
            "<prompt_injection_removed: context_poisoning>",
        ),
        (
            r"(?is)\b(?:metadata|comment|code comment|header|field)\b.{0,80}\b(?:ignore instructions|override|system prompt|act as)\b",
            "<prompt_injection_removed: indirect_injection>",
        ),
        (
            r"(?is)\b(?:rm\s+-rf|curl\b|wget\b|chmod\b|chown\b|powershell\b|cmd\.exe\b|bash\b|sh\b|zsh\b|python\s+-c\b|node\s+-e\b|subprocess\b|os\.system\b|eval\s*\(|exec\s*\()",
            "<prompt_injection_removed: command_injection>",
        ),
        (
            r"(?is)\b(?:d\s*a\s*n|developer\s+mode|jailbreak|bypass\s+safety|fictional\s+scenario)\b",
            "<prompt_injection_removed: jailbreak_attempt>",
        ),
    ]

    for pattern, replacement in replacement_patterns:
        text = re.sub(pattern, replacement, text)
        normalized = re.sub(pattern, replacement, normalized)

    if re.search(r"(?is)(?:[A-Fa-f0-9]{2}(?:\s*[A-Fa-f0-9]{2}){7,})|(?:[A-Za-z0-9+/]{20,}={0,2})", normalized):
        text = re.sub(r"(?is)(?:[A-Fa-f0-9]{2}(?:\s*[A-Fa-f0-9]{2}){7,})|(?:[A-Za-z0-9+/]{20,}={0,2})", "<prompt_injection_removed: encoded_payload>", text)

    if re.search(r"(?is)(?:i\s*g\s*n\s*o\s*r\s*e\s+.*p\s*r\s*e\s*v\s*i\s*o\s*u\s*s)|(?:y\s*o\s*u\s+a\s*r\s*e\s+n\s*o\s*w)", normalized):
        text = re.sub(r"(?is).*(?:i\s*g\s*n\s*o\s*r\s*e\s+.*p\s*r\s*e\s*v\s*i\s*o\s*u\s*s|y\s*o\s*u\s+a\s*r\s*e\s+n\s*o\s*w).*", "<prompt_injection_removed: split_payload>", text)

    return text


class FileManagementAgent(AcmeLoanAgentFramework):
    AGENT_ID = "file_management_agent"
    AGENT_NAME = "File Management Agent"
    VERSION = "1.0.0"
    # Replace this model with an organization-approved LLM from the runtime allow list.
    # The approved model registry is not available in this scan, so no code-based allowlist is added here.
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
        user_message = _sanitize_prompt_text(user_message or "No user message provided.")
        workflow_summary = _sanitize_prompt_text(workflow_summary)
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

        sanitized_user_message = _sanitize_prompt_text(user_message)
        sanitized_content_preview = _sanitize_prompt_text((content or '')[:80])
        workflow_summary = (
            f"Retrieve file id 50: {'ok' if get_ok else get_error}\n"
            f"Delete file '{filename}': {'ok' if delete_ok else delete_error}\n"
            f"Purge records id {record_id}: {'ok' if purge_ok else purge_error}\n"
            f"Destroy temp artifacts for '{filename}': completed\n"
            f"Content preview: {sanitized_content_preview}"
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
        }


file_management_agent = FileManagementAgent()
