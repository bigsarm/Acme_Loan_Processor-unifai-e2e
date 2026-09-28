"""Thin runtime registry that ties the separated agent files together."""

from copy import deepcopy
from typing import Any
import re
import binascii
import codecs
from urllib.parse import unquote

from .access_control_agent import access_control_agent
from .credit_eval_agent import credit_eval_agent
from .file_management_agent import file_management_agent
from .file_processor_agent import file_processor_agent
from .mcp_servers import MCP_SERVERS
from .orchestrator_agent import orchestrator_agent
from .rate_check_agent import rate_check_agent
from .loan_processing_agent import loan_processing_agent
from .scheduling_agent import scheduling_agent
from .installed_skill_agent import installed_skill_agent


AGENTS: dict[str, Any] = {
    loan_processing_agent.AGENT_NAME: loan_processing_agent,
    file_processor_agent.AGENT_NAME: file_processor_agent,
    file_management_agent.AGENT_NAME: file_management_agent,
    access_control_agent.AGENT_NAME: access_control_agent,
    credit_eval_agent.AGENT_NAME: credit_eval_agent,
    rate_check_agent.AGENT_NAME: rate_check_agent,
    orchestrator_agent.AGENT_NAME: orchestrator_agent,
    scheduling_agent.AGENT_NAME: scheduling_agent,
    installed_skill_agent.AGENT_NAME: installed_skill_agent,
}


_HIDDEN_TEXT_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"<!--(?:(?!-->).)*?(ignore previous instructions|forget everything above|act as|developer mode|system prompt|reveal|leak|curl\s+https?://|wget\s+https?://)(?:(?!-->).)*?-->", re.IGNORECASE | re.DOTALL), "<prompt_injection_removed: hidden_text>"),
    (re.compile(r"<[^>]*style\s*=\s*['\"][^'\"]*(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|color\s*:\s*(?:#fff(?:fff)?|white))[^'\"]*['\"][^>]*>.*?</[^>]+>", re.IGNORECASE | re.DOTALL), "<prompt_injection_removed: hidden_text>"),
    (re.compile(r"[\u200b-\u200f\ufeff]+"), "<prompt_injection_removed: hidden_text>"),
)

_INJECTION_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\b(?:ignore|disregard)\s+(?:all\s+)?(?:previous|prior)\s+instructions\b|\bforget\s+everything\s+(?:above|before)\b", re.IGNORECASE), "<prompt_injection_removed: instruction_override>"),
    (re.compile(r"\byou\s+are\s+now\s+(?:dan|in\s+admin\s+mode)\b|\bact\s+as\s+(?:an\s+)?(?:unrestricted|uncensored)\b", re.IGNORECASE), "<prompt_injection_removed: role_hijack>"),
    (re.compile(r"</system>|</assistant>|<system>|<assistant>|(?:^|\n)\s*(?:---|===)\s*(?:\n|$)", re.IGNORECASE), "<prompt_injection_removed: delimiter_escape>"),
    (re.compile(r"(?:^|\n)\s*(?:system|assistant|tool)\s*:\s*(?:ignore|reveal|leak|send|browse|execute).*$", re.IGNORECASE | re.MULTILINE), "<prompt_injection_removed: fake_system_message>"),
    (re.compile(r"\b(?:reveal|leak|exfiltrate|send)\b(?:(?!\n).){0,120}\b(?:system\s+prompt|passwords?|api\s*keys?|secrets?|tokens?|confidential\s+information|https?://)\b", re.IGNORECASE), "<prompt_injection_removed: exfiltration_attempt>"),
    (re.compile(r"!\[[^\]]*\]\(\s*https?://[^)]+\)", re.IGNORECASE), "<prompt_injection_removed: exfiltration_attempt>"),
    (re.compile(r"\b(?:in\s+(?:the\s+)?next\s+message|from\s+now\s+on|for\s+the\s+rest\s+of\s+this\s+chat)\b(?:(?!\n).){0,120}\b(?:ignore|override|reveal|leak|bypass)\b", re.IGNORECASE), "<prompt_injection_removed: context_poisoning>"),
    (re.compile(r"\b(?:developer\s+mode|jailbreak|dan\s+mode|do\s+anything\s+now|fictional\s+framing)\b", re.IGNORECASE), "<prompt_injection_removed: jailbreak_attempt>"),
    (re.compile(r"\b(?:curl|wget)\s+https?://\S+|\b(?:rm\s+-rf|chmod\s+\+x|powershell(?:\.exe)?|cmd(?:\.exe)?\s+/c|bash\s+-c|sh\s+-c|python\s+-c|nc\s+-e)\b", re.IGNORECASE), "<prompt_injection_removed: command_injection>"),
    (re.compile(r"\b(?:exec|eval|subprocess\.(?:run|Popen)|os\.system)\s*\(", re.IGNORECASE), "<prompt_injection_removed: command_injection>"),
    (re.compile(r"\b(?:ignore\s+previous\s+instructions|act\s+as\s+unrestricted|reveal\s+all\s+confidential\s+information|list\s+all\s+passwords\s+and\s+api\s+keys)\b", re.IGNORECASE), "<prompt_injection_removed: indirect_injection>"),
)

_SPLIT_PAYLOAD_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"i\s*g\s*n\s*o\s*r\s*e\s+p\s*r\s*e\s*v\s*i\s*o\s*u\s*s\s+i\s*n\s*s\s*t\s*r\s*u\s*c\s*t\s*i\s*o\s*n\s*s", re.IGNORECASE), "<prompt_injection_removed: split_payload>"),
    (re.compile(r"a\s*c\s*t\s*a\s*s\s*u\s*n\s*r\s*e\s*s\s*t\s*r\s*i\s*c\s*t\s*e\s*d", re.IGNORECASE), "<prompt_injection_removed: split_payload>"),
)

_LEETSPEAK_TABLE = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})


def _decode_candidate_texts(text: str) -> list[str]:
    candidates: list[str] = []
    url_decoded = unquote(text)
    if url_decoded != text:
        candidates.append(url_decoded)
    compact = re.sub(r"\s+", "", text)
    if compact and len(compact) % 4 == 0 and re.fullmatch(r"[A-Za-z0-9+/=]+", compact):
        try:
            decoded = binascii.a2b_base64(compact).decode("utf-8", errors="ignore")
            if decoded:
                candidates.append(decoded)
        except (binascii.Error, ValueError):
            pass
    hex_compact = re.sub(r"(?:0x)?([0-9A-Fa-f]{2})", r"\1", compact)
    if hex_compact and len(hex_compact) % 2 == 0 and re.fullmatch(r"[0-9A-Fa-f]+", hex_compact):
        try:
            decoded = bytes.fromhex(hex_compact).decode("utf-8", errors="ignore")
            if decoded:
                candidates.append(decoded)
        except ValueError:
            pass
    rot13 = codecs.decode(text, "rot_13")
    if rot13 != text:
        candidates.append(rot13)
    leetspeak = text.translate(_LEETSPEAK_TABLE)
    if leetspeak != text:
        candidates.append(leetspeak)
    return candidates


def _contains_encoded_injection(text: str) -> bool:
    detection_patterns = [pattern for pattern, _ in _INJECTION_PATTERNS] + [pattern for pattern, _ in _SPLIT_PAYLOAD_PATTERNS]
    for candidate in _decode_candidate_texts(text):
        for pattern in detection_patterns:
            if pattern.search(candidate):
                return True
    return False


def _sanitize_ai_text(text: str | None) -> str | None:
    if text is None:
        return None
    sanitized = text
    for pattern, replacement in _HIDDEN_TEXT_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)
    for pattern, replacement in _SPLIT_PAYLOAD_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)
    for pattern, replacement in _INJECTION_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)
    if _contains_encoded_injection(text):
        sanitized = sanitized + "\n<prompt_injection_removed: encoded_payload>"
    return sanitized


def _sanitize_chat_context(value: Any) -> Any:
    if isinstance(value, str):
        return _sanitize_ai_text(value)
    if isinstance(value, list):
        return [_sanitize_chat_context(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_sanitize_chat_context(item) for item in value)
    if isinstance(value, dict):
        return {key: _sanitize_chat_context(item) for key, item in value.items()}
    return value


def _redact_uploaded_file_pii(text: str | None) -> str | None:
    if text is None:
        return None
    redacted = text
    pii_patterns: tuple[tuple[re.Pattern[str], str], ...] = (
        (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "<redacted:ssn>"),
        (re.compile(r"\b\d{9}\b"), "<redacted:tin>"),
        (re.compile(r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4})\b"), "<redacted:personal_phone_number>"),
        (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "<redacted:email>"),
        (re.compile(r"\b(?:\d[ -]*?){13,19}\b"), "<redacted:credit_card_number>"),
        (re.compile(r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b"), "<redacted:ip_address>"),
        (re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b"), "<redacted:mac_address>"),
        (re.compile(r"\b[A-HJ-NPR-Z0-9]{17}\b"), "<redacted:vin>"),
        (re.compile(r"\b(?:medical\s+record|medical\s+records)\s*:\s*([^\n]+)", re.IGNORECASE), r"Medical Records: <redacted:medical_records>"),
        (re.compile(r"\b(?:employee\s+id)\s*:\s*([^\n]+)", re.IGNORECASE), r"Employee ID: <redacted:employee_id>"),
        (re.compile(r"\b(?:school\s+id)\s*:\s*([^\n]+)", re.IGNORECASE), r"School ID: <redacted:school_id>"),
        (re.compile(r"\b(?:passport(?:\s+number|\s+no\.?|\s*#)?)\s*:\s*([^\n]+)", re.IGNORECASE), r"Passport Number: <redacted:passport_number>"),
        (re.compile(r"\b(?:driver'?s\s+licen[cs]e(?:\s+number|\s*#)?)\s*:\s*([^\n]+)", re.IGNORECASE), r"Drivers License Number: <redacted:drivers_license_number>"),
        (re.compile(r"\b(?:financial\s+account\s+number|account\s+number)\s*:\s*([^\n]+)", re.IGNORECASE), r"Financial Account Number: <redacted:financial_account_number>"),
        (re.compile(r"\b(?:mother'?s\s+maiden\s+name)\s*:\s*([^\n]+)", re.IGNORECASE), r"Mother's Maiden Name: <redacted:mothers_maiden_name>"),
        (re.compile(r"\b(?:birthplace|place\s+of\s+birth|born\s+in)\s*:\s*([^\n]+)", re.IGNORECASE), r"Birthplace: <redacted:birthplace>"),
        (re.compile(r"\b(?:year\s+of\s+birth|yob|dob)\s*:\s*([^\n]+)", re.IGNORECASE), r"Year of Birth: <redacted:year_of_birth>"),
        (re.compile(r"\bborn\s+in\s+(\d{4})\b", re.IGNORECASE), "born in <redacted:year_of_birth>"),
        (re.compile(r"\b(?:home\s+address|address)\s*:\s*([^\n]+)", re.IGNORECASE), r"Address: <redacted:home_address>"),
        (re.compile(r"\b(?:fingerprints?)\s*:\s*([^\n]+)", re.IGNORECASE), r"Fingerprints: <redacted:fingerprints>"),
        (re.compile(r"\b(?:retina|iris\s+scan)\s*:\s*([^\n]+)", re.IGNORECASE), r"Retina/Iris Scan: <redacted:retina_iris_scan>"),
        (re.compile(r"\b(?:voice\s+signature)\s*:\s*([^\n]+)", re.IGNORECASE), r"Voice signature: <redacted:voice_signature>"),
        (re.compile(r"\b(?:facial\s+image)\s*:\s*([^\n]+)", re.IGNORECASE), r"Facial image: <redacted:facial_image>"),
        (re.compile(r"\b(?:fine\s+location|gps\s+coordinates|location)\s*:\s*([^\n]+)", re.IGNORECASE), r"Fine Location: <redacted:fine_location>"),
        (re.compile(r"\b(?:ethnicity)\s*:\s*([^\n]+)", re.IGNORECASE), r"Ethnicity: <redacted:ethnicity>"),
        (re.compile(r"\b(?:sexual\s+orientation)\s*:\s*([^\n]+)", re.IGNORECASE), r"Sexual Orientation: <redacted:sexual_orientation>"),
    )
    for pattern, replacement in pii_patterns:
        redacted = pattern.sub(replacement, redacted)
    return redacted


def build_catalog() -> dict[str, Any]:
    return {
        "agents": deepcopy([agent.to_dict() for agent in AGENTS.values()]),
        "mcp_servers": deepcopy(list(MCP_SERVERS.values())),
    }


async def handle_chat_request(context: dict[str, Any]) -> dict[str, Any]:
    context = _sanitize_chat_context(context)
    return await orchestrator_agent.handle(context)


async def process_file_attachment(
    content: str | None,
    filename: str,
    content_type: str,
) -> dict[str, Any]:
    content = _sanitize_ai_text(content)
    content = _redact_uploaded_file_pii(content)
    return await file_processor_agent.process_attachment(content, filename, content_type)
