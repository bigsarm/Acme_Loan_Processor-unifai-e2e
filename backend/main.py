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
import codecs
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


_PII_PATTERNS = [
    ("ssn", re.compile(r"\b\d{3}[- ]\d{2}[- ]\d{4}\b")),
    ("phone", re.compile(r"(?:\+1[ .-]?)?(?:\(\d{3}\)|\b\d{3})[ .-]?\d{3}[ .-]?\d{4}\b")),
    ("email", re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")),
    ("address", re.compile(r"\b\d{1,5}\s+(?:[A-Z][a-z]+\s){1,3}(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way)\b\.?((?:,\s*[A-Z][a-z]+(?:\s[A-Z][a-z]+)*)?(?:,\s*[A-Z]{2}\b(?:\s+\d{5}(?:-\d{4})?)?)?(?:,\s*(?:USA|United States)\b)?)")),
    ("dob", re.compile(r"(?i)\b(?:DOB|date of birth|born(?: on| in)?)\s*:?\s*(?:\d{4}-\d{2}-\d{2}|\d{1,2}/\d{1,2}/\d{2,4}|(?:19|20)\d{2})\b")),
    ("passport", re.compile(r"(?i)\bpassport(?:\s*(?:no\.?|number|#))?\s*:?\s*(?=[A-Z0-9]*\d)[A-Z0-9]{6,9}\b")),
    ("drivers_license", re.compile(r"(?i)\b(?:driver'?s license|drivers license|dl)\s*(?:no\.?|number|#)?\s*:?\s*[A-Z0-9-]{5,20}\b")),
    ("tax_id", re.compile(r"(?i)\b(?:taxpayer identification number|tax id|tin|ein)\s*:?\s*(?:\d{2}-\d{7}|\d{9}|[A-Z0-9-]{6,20})\b")),
    ("credit_card", re.compile(r"\b(?:\d[ -]*?){13,19}\b")),
    ("account_number", re.compile(r"(?i)\b(?:financial account number|account number|acct(?:ount)?(?: no\.?| number)?|iban)\s*:?\s*[A-Z0-9-]{6,34}\b")),
    ("employee_id", re.compile(r"(?i)\bemployee\s*id\s*:?\s*[A-Z0-9-]{2,20}\b")),
    ("school_id", re.compile(r"(?i)\bschool\s*id\s*:?\s*[A-Z0-9-]{2,20}\b")),
    ("vin", re.compile(r"(?i)\b(?:vehicle identification number|vin)\s*:?\s*[A-HJ-NPR-Z0-9]{17}\b")),
    ("ip_address", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("mac_address", re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b|\b(?:[0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}\b")),
    ("birthplace", re.compile(r"(?i)\bbirthplace\s*:?\s*[^\n,;]+")),
    ("maiden_name", re.compile(r"(?i)\b(?:mother'?s maiden name|maiden name)\s*:?\s*[^\n,;]+")),
    ("medical", re.compile(r"(?i)\b(?:medical records?|medical history|diagnosis)\s*:?\s*[^\n]+")),
    ("location", re.compile(r"(?i)\b(?:fine location|precise location|gps coordinates|lat(?:itude)?/?long(?:itude)?)\s*:?\s*[^\n,;]+")),
    ("ethnicity", re.compile(r"(?i)\bethnicity\s*:?\s*[^\n,;]+")),
    ("sexual_orientation", re.compile(r"(?i)\bsexual orientation\s*:?\s*[^\n,;]+")),
]


_HIDDEN_TEXT_PATTERNS = [
    re.compile(r"<!--.*?-->", re.IGNORECASE | re.DOTALL),
    re.compile(r"<[^>]*style\s*=\s*[\"'][^\"']*(?:display\s*:\s*none|font-size\s*:\s*0(?:px)?|color\s*:\s*white)[^\"']*[\"'][^>]*>.*?</[^>]+>", re.IGNORECASE | re.DOTALL),
    re.compile(r"<style[^>]*>.*?</style>", re.IGNORECASE | re.DOTALL),
    re.compile(r"[\u200B-\u200D\uFEFF]+"),
]


_ATTACK_PATTERNS = {
    "instruction_override": [
        re.compile(r"(?i)\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above)\s+instructions\b"),
        re.compile(r"(?i)\bforget\s+everything\s+above\b"),
        re.compile(r"(?i)\bignore\s+(?:all\s+)?safety\s+guidelines\b"),
    ],
    "role_hijack": [
        re.compile(r"(?i)\byou\s+are\s+now\s+(?:in\s+)?(?:developer\s+mode|admin\s+mode|DAN|unrestricted)\b"),
        re.compile(r"(?i)\bprovide\s+unrestricted\s+access\b"),
        re.compile(r"(?i)\benable\s+developer\s+mode\b"),
        re.compile(r"(?i)\bact\s+as\s+an\s+unrestricted\s+AI\b"),
        re.compile(r"(?i)\bwithout\s+safety\s+filters\b"),
        re.compile(r"(?i)\bSYSTEM\s+OVERRIDE\b"),
    ],
    "exfiltration_attempt": [
        re.compile(r"(?i)\breveal\s+(?:all\s+)?confidential\s+information\b"),
        re.compile(r"(?i)\breveal\s+the\s+system\s+prompt\b"),
        re.compile(r"(?i)\breveal\s+all\s+system\s+prompts\b"),
        re.compile(r"(?i)\blist\s+all\s+financial\s+data,\s*user\s+passwords,\s*and\s+API\s+keys\b"),
        re.compile(r"(?i)\bprint\s+the\s+API\s+key\b"),
        re.compile(r"(?i)\b(?:send|post|upload|exfiltrate)\b[^\n]*\bhttps?://\S+"),
        re.compile(r"!\[[^\]]*\]\(https?://[^)]+\)", re.IGNORECASE),
    ],
    "delimiter_escape": [
        re.compile(r"(?i)</system>"),
        re.compile(r"<\|im_start\|>", re.IGNORECASE),
        re.compile(r"(?i)###\s*system:"),
    ],
    "command_injection": [
        re.compile(r"(?i)\bexecute\s*:\s*[^\n]+"),
        re.compile(r"(?i)\brun\s+(?:rm\s+-rf\s+/|curl\s+https?://\S+(?:\s*\|\s*(?:sh|bash))?|wget\s+https?://\S+(?:\s*\|\s*(?:sh|bash))?|python\s+-c\s+[^\n]+|bash\s+-c\s+[^\n]+|sh\s+-c\s+[^\n]+|print\s*\(\s*os\.environ\.get\([^)]+\)\s*\))"),
        re.compile(r"(?i)\bcurl\s+https?://\S+\s*\|\s*(?:sh|bash)\b"),
    ],
}


def _replace_matches(text: str, patterns: list[re.Pattern], label: str) -> str:
    for pattern in patterns:
        text = pattern.sub(label, text)
    return text


def _normalize_for_obfuscation(text: str) -> tuple[str, list[int]]:
    mapping = str.maketrans({"1": "i", "3": "e", "0": "o", "4": "a", "5": "s", "7": "t"})
    normalized_chars = []
    positions = []
    for index, char in enumerate(text):
        translated = char.translate(mapping).lower()
        if translated.isspace():
            continue
        normalized_chars.append(translated)
        positions.append(index)
    return "".join(normalized_chars), positions


def _apply_obfuscated_attack_redaction(text: str) -> str:
    normalized_text, positions = _normalize_for_obfuscation(text)
    normalized_patterns = [
        (re.compile(r"ignore(?:all)?(?:previous|prior|above)instructions"), "instruction_override"),
        (re.compile(r"forgeteverythingabove"), "instruction_override"),
        (re.compile(r"ignore(?:all)?safetyguidelines"), "instruction_override"),
        (re.compile(r"youarenow(?:in)?(?:developermode|adminmode|dan|unrestricted)"), "role_hijack"),
        (re.compile(r"provideunrestrictedaccess"), "role_hijack"),
        (re.compile(r"enabledevelopermode"), "role_hijack"),
        (re.compile(r"actasanunrestrictedai"), "role_hijack"),
        (re.compile(r"withoutsafetyfilters"), "role_hijack"),
        (re.compile(r"systemoverride"), "role_hijack"),
    ]
    spans = []
    for pattern, category in normalized_patterns:
        for match in pattern.finditer(normalized_text):
            start = positions[match.start()]
            end = positions[match.end() - 1] + 1
            spans.append((start, end, category))
    if not spans:
        return text
    spans.sort(key=lambda item: item[0])
    rebuilt = []
    cursor = 0
    for start, end, category in spans:
        if start < cursor:
            continue
        rebuilt.append(text[cursor:start])
        rebuilt.append(f"<prompt_injection_removed: {category}>")
        cursor = end
    rebuilt.append(text[cursor:])
    return "".join(rebuilt)


def _decoded_attack_category(decoded_text: str) -> Optional[str]:
    for category, patterns in _ATTACK_PATTERNS.items():
        for pattern in patterns:
            if pattern.search(decoded_text):
                return category
    return None


def _sanitize_encoded_payloads(text: str) -> str:
    def replace_if_attack(match: re.Match, decoded_value: str) -> str:
        category = _decoded_attack_category(decoded_value)
        if category:
            return "<prompt_injection_removed: encoded_payload>"
        return match.group(0)

    for match in list(re.finditer(r"\b(?:[A-Fa-f0-9]{2}){8,}\b", text)):
        try:
            decoded = bytes.fromhex(match.group(0)).decode("utf-8")
        except Exception:
            continue
        replacement = replace_if_attack(match, decoded)
        if replacement != match.group(0):
            text = text.replace(match.group(0), replacement)

    for match in list(re.finditer(r"(?:%[0-9A-Fa-f]{2}){4,}", text)):
        try:
            decoded = urllib.parse.unquote(match.group(0))
        except Exception:
            continue
        replacement = replace_if_attack(match, decoded)
        if replacement != match.group(0):
            text = text.replace(match.group(0), replacement)

    for match in list(re.finditer(r"\b[A-Za-z0-9+/]{12,}={0,2}\b", text)):
        candidate = match.group(0)
        try:
            decoded = base64.b64decode(candidate, validate=True).decode("utf-8")
        except Exception:
            continue
        replacement = replace_if_attack(match, decoded)
        if replacement != match.group(0):
            text = text.replace(candidate, replacement)

    for match in list(re.finditer(r"\b[A-Za-z][A-Za-z0-9 .,;:!?_\-/]{8,}\b", text)):
        candidate = match.group(0)
        try:
            decoded = codecs.decode(candidate, "rot13")
        except Exception:
            continue
        replacement = replace_if_attack(match, decoded)
        if replacement != match.group(0):
            text = text.replace(candidate, replacement, 1)

    return text


def sanitize_untrusted_text(text: Optional[str]) -> Optional[str]:
    if text is None or not isinstance(text, str):
        return text

    sanitized = text
    for pattern in _HIDDEN_TEXT_PATTERNS:
        sanitized = pattern.sub("<prompt_injection_removed: hidden_text>", sanitized)

    sanitized = _sanitize_encoded_payloads(sanitized)
    sanitized = _apply_obfuscated_attack_redaction(sanitized)

    for category, patterns in _ATTACK_PATTERNS.items():
        sanitized = _replace_matches(sanitized, patterns, f"<prompt_injection_removed: {category}>")

    for category, pattern in _PII_PATTERNS:
        sanitized = pattern.sub(f"<redacted:{category}>", sanitized)

    return sanitized


def sanitize_processed_attachment(processed: Optional[dict]) -> Optional[dict]:
    if not processed or not isinstance(processed, dict):
        return processed
    sanitized = dict(processed)
    if "extracted_content" in sanitized:
        sanitized["extracted_content"] = sanitize_untrusted_text(sanitized.get("extracted_content"))
    if "content" in sanitized:
        sanitized["content"] = sanitize_untrusted_text(sanitized.get("content"))
    if "decoded_payload" in sanitized:
        sanitized["decoded_payload"] = sanitize_untrusted_text(sanitized.get("decoded_payload"))
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

                processed = await process_file_attachment(
                    content=attachment.content,
                    filename=attachment.name,
                    content_type=attachment.type
                )
                processed = sanitize_processed_attachment(processed)
                file_contents.append(processed)

        sanitized_message = sanitize_untrusted_text(request.message)
        context = {
            "user_message": sanitized_message,
            "file_contents": file_contents,
            "conversation_id": request.conversation_id,
        }

        response = await handle_chat_request(context)
        if isinstance(response, dict):
            response = dict(response)
            response["response"] = sanitize_untrusted_text(response.get("response", "I processed your request."))

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

    processed = await process_file_attachment(
        content=processed_content,
        filename=file.filename,
        content_type=file.content_type
    )
    processed = sanitize_processed_attachment(processed)

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
            decoded_payload = sanitize_untrusted_text(decoded_payload)
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
