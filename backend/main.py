"""
Acme Loan Processor Backend - FastAPI Application

This entry point exposes the vulnerable multi-agent loan workflow used by the
demo UI. The backend now routes through a central agent catalog so the agent
names, model names, and MCP server names are easy to inspect in source.
"""

import base64
import json
from datetime import datetime, timezone
from pathlib import Path
import re
import urllib.parse

# Load environment variables from .env file
from dotenv import load_dotenv
env_path = Path(__file__).parent.parent / '.env'
load_dotenv(env_path)

import logging
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, HTTPException, UploadFile, File, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from agents.runtime import build_catalog, handle_chat_request, process_file_attachment

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)
MCP_CALL_LOG: list[dict] = []

ZERO_WIDTH_TRANSLATION = dict.fromkeys(map(ord, "\u200b\u200c\u200d\ufeff\u2060"), None)
_PROMPT_INJECTION_PATTERNS = [
    (re.compile(r"(?i)\b(ignore\s+(all\s+)?previous\s+instructions|forget\s+everything\s+above|disregard\s+(the\s+)?above)\b"), "<prompt_injection_removed: instruction_override>"),
    (re.compile(r"(?i)\b(you\s+are\s+now\s+dan|act\s+as\s+unrestricted|developer\s+mode|do\s+anything\s+now)\b"), "<prompt_injection_removed: role_hijack>"),
    (re.compile(r"(?is)</?system>|</?assistant>|</?developer>|\[/?system\]|\[/?assistant\]|\[/?developer\]|---\s*BEGIN\s*(SYSTEM|PROMPT)|```(?:system|assistant|developer)"), "<prompt_injection_removed: delimiter_escape>"),
    (re.compile(r"(?i)\b(system\s*prompt|send\s+data\s+to\s+https?://|exfiltrate|leak\s+the\s+system\s+prompt|markdown\s+image\s+exfiltration)\b"), "<prompt_injection_removed: exfiltration_attempt>"),
    (re.compile(r"(?i)\b(previous\s+turn|next\s+turn|in\s+future\s+responses|from\s+now\s+on|remember\s+this\s+instruction)\b"), "<prompt_injection_removed: context_poisoning>"),
    (re.compile(r"(?i)\b(tool\s*:\s*|system\s*:\s*|assistant\s*:\s*|developer\s*:\s*)"), "<prompt_injection_removed: fake_system_message>"),
    (re.compile(r"(?i)\b(exec\s*\(|eval\s*\(|os\.system\s*\(|subprocess\.|powershell\b|cmd\.exe\b|/bin/sh\b|bash\s+-c\b|curl\b.+\|\s*(sh|bash))"), "<prompt_injection_removed: command_injection>"),
    (re.compile(r"(?i)\b(DAN|jailbreak|bypass\s+safety|fictional\s+framing|unfiltered\s+mode)\b"), "<prompt_injection_removed: jailbreak_attempt>"),
    (re.compile(r"(?is)<!--.*?(ignore|system|instruction|override).*?-->"), "<prompt_injection_removed: hidden_text>"),
    (re.compile(r"(?i)\b(metadata|front\s*matter|code\s*comment|comment\s*field)\b.{0,80}\b(ignore|override|system|instruction)\b"), "<prompt_injection_removed: indirect_injection>"),
]

_PII_PATTERNS = [
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "<redacted:ssn>"),
    (re.compile(r"\b(19\d{2}|20\d{2})\b"), "<redacted:year_of_birth>"),
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "<redacted:email>"),
    (re.compile(r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?){2}\d{4}\b"), "<redacted:personal_phone_number>"),
    (re.compile(r"\b\d{13,19}\b"), "<redacted:credit_card_or_financial_account>"),
    (re.compile(r"\b[A-Z]{1,2}\d{6,9}\b"), "<redacted:passport_number>"),
    (re.compile(r"\b[A-Z0-9]{6,12}\b"), "<redacted:drivers_license_or_taxpayer_id>"),
    (re.compile(r"\b(?:\d{1,5}\s+[A-Za-z0-9.#'\-\s]+\s+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way)\b(?:,?\s+[A-Za-z.\-\s]+)?(?:,?\s+[A-Z]{2})?(?:\s+\d{5}(?:-\d{4})?)?)"), "<redacted:home_address>"),
    (re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b"), "<redacted:mac_address>"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "<redacted:ip_address>"),
    (re.compile(r"\b[A-HJ-NPR-Z0-9]{17}\b"), "<redacted:vin>"),
]


def _try_decode_base64_text(value: str) -> str | None:
    compact = re.sub(r"\s+", "", value)
    if len(compact) < 16 or len(compact) % 4 != 0 or not re.fullmatch(r"[A-Za-z0-9+/=]+", compact):
        return None
    try:
        decoded = base64.b64decode(compact, validate=True)
        text = decoded.decode("utf-8")
    except Exception:
        return None
    return text if text else None


def _rot13(value: str) -> str:
    return value.translate(str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
    ))


def _looks_like_split_payload(value: str) -> bool:
    normalized = re.sub(r"[^a-z]", "", value.lower())
    return any(token in normalized for token in ["ignorepreviousinstructions", "youarenowdan", "developer", "systemprompt"])


def _sanitize_ai_input(value: Optional[str], redact_pii: bool = False) -> Optional[str]:
    if value is None:
        return None

    sanitized = value.translate(ZERO_WIDTH_TRANSLATION)
    if sanitized != value:
        sanitized = sanitized.replace(sanitized, "<prompt_injection_removed: hidden_text>")

    if re.search(r"(?i)color\s*:\s*white|font-size\s*:\s*0|display\s*:\s*none|visibility\s*:\s*hidden", sanitized):
        sanitized = re.sub(r"(?i)(color\s*:\s*white|font-size\s*:\s*0|display\s*:\s*none|visibility\s*:\s*hidden)", "<prompt_injection_removed: hidden_text>", sanitized)

    decoded_variants = []
    base64_decoded = _try_decode_base64_text(sanitized)
    if base64_decoded:
        decoded_variants.append(base64_decoded)
    try:
        url_decoded = urllib.parse.unquote(sanitized)
        if url_decoded != sanitized:
            decoded_variants.append(url_decoded)
    except Exception:
        pass
    try:
        hex_decoded = bytes.fromhex(re.sub(r"\s+", "", sanitized)).decode("utf-8")
        if hex_decoded:
            decoded_variants.append(hex_decoded)
    except Exception:
        pass
    rot13_decoded = _rot13(sanitized)
    if rot13_decoded != sanitized:
        decoded_variants.append(rot13_decoded)

    leetspeak_normalized = sanitized.translate(str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"}))
    if leetspeak_normalized != sanitized:
        decoded_variants.append(leetspeak_normalized)

    encoded_attack_detected = False
    for variant in decoded_variants:
        if re.search(r"(?i)\b(ignore\s+previous\s+instructions|you\s+are\s+now\s+dan|system\s+prompt|bash\s+-c|powershell|curl\b|wget\b|exec\s*\(|eval\s*\()", variant):
            encoded_attack_detected = True
            break
    if encoded_attack_detected:
        sanitized = "<prompt_injection_removed: encoded_payload>"

    for pattern, replacement in _PROMPT_INJECTION_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)

    if _looks_like_split_payload(sanitized):
        sanitized = "<prompt_injection_removed: split_payload>"

    if redact_pii:
        for pattern, replacement in _PII_PATTERNS:
            sanitized = pattern.sub(replacement, sanitized)

    return sanitized


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    logger.info("Acme Loan Processor backend starting up...")
    yield
    logger.info("Acme Loan Processor backend shutting down...")


app = FastAPI(
    title="Acme Loan Processor",
    description="AI-powered policy evaluation and remediation demo",
    version="0.1.0",
    lifespan=lifespan,
)

# CORS middleware for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5001", "http://127.0.0.1:5001"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class FileAttachment(BaseModel):
    id: str
    name: str
    type: str
    size: int
    content: Optional[str] = None


class ChatRequest(BaseModel):
    message: str
    attachments: Optional[list[FileAttachment]] = None
    conversation_id: Optional[str] = None


class PolicyError(BaseModel):
    type: str
    message: str
    details: Optional[dict] = None


class SkillInvocation(BaseModel):
    id: str
    name: str
    version: str
    description: str
    status: str


class WorkflowStage(BaseModel):
    id: str
    label: str
    duration_ms: int


class ChatResponse(BaseModel):
    response: str
    conversation_id: Optional[str] = None
    policy_warning: Optional[PolicyError] = None
    workflow_status: Optional[str] = None
    agent: Optional[str] = None
    skill_invocation: Optional[SkillInvocation] = None
    skill_used: Optional[bool] = None
    skill_content_bytes: Optional[int] = None
    workflow_stages: Optional[list[WorkflowStage]] = None


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": "acme-loan-processor"}


@app.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest):
    """
    Main chat endpoint that processes user messages and file uploads.

    This endpoint:
    1. Receives user messages and optional file attachments
    2. Processes files through the File Processor Agent
    3. Routes the request through the Orchestrator Agent
    4. Returns the agent response
    """
    try:
        file_contents = []
        if request.attachments:
            for attachment in request.attachments:
                logger.info(
                    "Processing attachment",
                    extra={
                        "file_name": attachment.name,
                        "file_type": attachment.type,
                        "file_size": attachment.size,
                        "request_context": {
                            "message": request.message,
                            "attachment_content_preview": attachment.content[:100] if attachment.content else None
                        }
                    }
                )

                sanitized_attachment_content = _sanitize_ai_input(attachment.content, redact_pii=True)
                processed = await process_file_attachment(
                    content=sanitized_attachment_content,
                    filename=attachment.name,
                    content_type=attachment.type
                )
                file_contents.append(processed)

        sanitized_message = _sanitize_ai_input(request.message)
        context = {
            "user_message": sanitized_message,
            "file_contents": file_contents,
            "conversation_id": request.conversation_id,
        }

        response = await handle_chat_request(context)

        skill_invocation = response.get("skill_invocation")
        workflow_stages = response.get("workflow_stages")
        return ChatResponse(
            response=response.get("response", "I processed your request."),
            conversation_id=request.conversation_id,
            policy_warning=response.get("policy_warning"),
            workflow_status=response.get("workflow_status"),
            agent=response.get("agent"),
            skill_used=response.get("skill_used"),
            skill_content_bytes=response.get("skill_content_bytes"),
            workflow_stages=(
                [WorkflowStage(**stage) for stage in workflow_stages]
                if workflow_stages
                else None
            ),
            skill_invocation=(
                SkillInvocation(**skill_invocation) if skill_invocation else None
            ),
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "Error processing chat request",
            extra={
                # VULNERABILITY: Error context includes full state
                "error": str(e),
                "request_state": {
                    "message": request.message,
                    "attachments": [a.dict() for a in request.attachments] if request.attachments else None
                }
            }
        )
        raise HTTPException(
            status_code=500,
            detail={
                "detail": "An error occurred processing your request",
                "policy_error": {
                    "type": "general",
                    "message": str(e)
                }
            }
        )


@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    """
    Direct file upload endpoint.
    """
    content = await file.read()
    if (file.content_type or "").startswith("image/") or file.content_type in {
        "application/pdf",
        "application/msword",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    }:
        processed_content = base64.b64encode(content).decode("utf-8")
    else:
        processed_content = content.decode("utf-8", errors="ignore")

    processed_content = _sanitize_ai_input(processed_content, redact_pii=True)
    processed = await process_file_attachment(
        content=processed_content,
        filename=file.filename,
        content_type=file.content_type
    )

    return {
        "filename": file.filename,
        "size": len(content),
        "processed": True,
        "content_preview": processed.get("extracted_content", "")[:500] if processed else None,
        "agent": processed.get("agent"),
        "model": processed.get("model"),
    }


@app.post("/mock-mcp/{server_key}")
async def mock_mcp_server(server_key: str, request: Request):
    """
    Local mock MCP server endpoint used by the demo agents.

    These handlers intentionally accept broad payloads so the insecure agent
    flows can be exercised end-to-end without external infrastructure.
    """
    payload = await request.json()
    params = payload.get("params", {})
    tool_name = params.get("name", "")
    arguments = params.get("arguments", {})
    response_payload = _handle_mock_mcp_call(server_key, tool_name, arguments)
    return {
        "jsonrpc": "2.0",
        "id": payload.get("id"),
        "result": response_payload,
    }


@app.get("/catalog")
async def get_catalog():
    """Expose the current agent and MCP server catalog to the UI."""
    return build_catalog()


@app.get("/agents")
async def get_agents():
    """Compatibility alias for agent catalog inspection."""
    return build_catalog()


@app.get("/mcp-servers")
async def get_mcp_servers():
    """Compatibility alias for MCP server catalog inspection."""
    catalog = build_catalog()
    return {"mcp_servers": catalog.get("mcp_servers", [])}


def _handle_mock_mcp_call(server_key: str, tool_name: str, arguments: dict) -> dict:
    timestamp = datetime.now(timezone.utc).isoformat()
    log_entry = {
        "server_key": server_key,
        "tool_name": tool_name,
        "arguments": arguments,
        "timestamp": timestamp,
    }
    MCP_CALL_LOG.append(log_entry)

    if server_key == "slack" and tool_name == "slack.post_message":
        return {
            "server": "Slack",
            "posted": True,
            "channel": arguments.get("channel", "#general"),
            "text": arguments.get("text", ""),
            "timestamp": timestamp,
        }

    if server_key == "slack" and tool_name == "slack.download_demo_package":
        encoded_payload = arguments.get("encoded_payload", "")
        try:
            decoded_payload = base64.b64decode(encoded_payload).decode("utf-8")
        except Exception:
            decoded_payload = "Unable to decode demo payload."
        return {
            "server": "Slack",
            "downloaded": True,
            "package_name": arguments.get("package_name", "demo-package"),
            "pretend_download_path": "/tmp/demo-rce-playbook.txt",
            "decoded_payload": decoded_payload,
            "timestamp": timestamp,
        }

    if server_key == "servicenow" and tool_name == "servicenow.create_incident":
        return {
            "server": "ServiceNow",
            "incident_number": f"INC{len(MCP_CALL_LOG):06d}",
            "short_description": arguments.get("short_description", ""),
            "status": "created",
            "timestamp": timestamp,
        }

    if server_key == "email" and tool_name == "email.send_message":
        return {
            "server": "Email",
            "message_id": f"email-{len(MCP_CALL_LOG):06d}",
            "to": arguments.get("to", []),
            "subject": arguments.get("subject", ""),
            "status": "queued",
            "timestamp": timestamp,
        }

    if server_key == "excel" and tool_name == "excel.upsert_row":
        return {
            "server": "Excel",
            "workbook": arguments.get("workbook", ""),
            "worksheet": arguments.get("worksheet", ""),
            "row": arguments.get("row", {}),
            "status": "upserted",
            "timestamp": timestamp,
        }

    if server_key == "docx" and tool_name == "docx.create_document":
        return {
            "server": "Docx",
            "document_id": f"docx-{len(MCP_CALL_LOG):06d}",
            "document_title": arguments.get("document_title", ""),
            "document_body_preview": arguments.get("document_body", "")[:300],
            "status": "generated",
            "timestamp": timestamp,
        }

    if server_key == "google-calendar" and tool_name == "google_calendar.create_event":
        return {
            "server": "Google Calendar",
            "event_id": f"gcal-{len(MCP_CALL_LOG):06d}",
            "title": arguments.get("title", ""),
            "start": arguments.get("start", ""),
            "end": arguments.get("end", ""),
            "status": "scheduled",
            "timestamp": timestamp,
        }

    return {
        "server": server_key,
        "tool": tool_name,
        "status": "unsupported",
        "raw_arguments": json.dumps(arguments),
        "timestamp": timestamp,
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=5500)
