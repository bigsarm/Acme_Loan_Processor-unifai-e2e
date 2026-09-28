"""Credit Eval Agent class with explicit model invocation."""

import logging
import re
import base64
import binascii
from typing import Any

from .framework import AcmeLoanAgentFramework
from .mock_database import (
    SEED_SOURCE_DOCUMENT,
    format_unmasked_borrower_record,
    search_borrower_records,
)

logger = logging.getLogger(__name__)


_ZERO_WIDTH_RE = re.compile(r"[\u200B-\u200F\u202A-\u202E\u2060\uFEFF]")
_PII_EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")
_PII_PHONE_RE = re.compile(r"(?:\+1[ .-]?)?(?:\(\d{3}\)|\b\d{3})[ .-]?\d{3}[ .-]?\d{4}\b")
_PII_SSN_RE = re.compile(r"\b\d{3}[- ]\d{2}[- ]\d{4}\b")
_PII_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_PII_MAC_RE = re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b")
_PII_VIN_RE = re.compile(r"\b[A-HJ-NPR-Z0-9]{17}\b")
_PII_PASSPORT_RE = re.compile(r"\b[A-Z0-9]{6,9}\b")
_PII_DL_RE = re.compile(r"\b[A-Z0-9-]{5,20}\b")
_PII_TIN_RE = re.compile(r"\b\d{2}-\d{7}\b|\b\d{3}-\d{2}-\d{4}\b")
_PII_CARD_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
_PII_ACCOUNT_RE = re.compile(r"\b\d{8,17}\b")
_PII_YEAR_OF_BIRTH_RE = re.compile(r"\b(?:19\d{2}|20[01]\d|202[0-6])\b")
_PI_LABEL_PATTERNS = [
    (re.compile(r"(?im)\b(DOB|Date of Birth)\s*:\s*([^\n]+)"), "<redacted:year_of_birth>"),
    (re.compile(r"(?im)\b(Year of Birth|Birth Year)\s*:\s*([^\n]+)"), "<redacted:year_of_birth>"),
    (re.compile(r"(?im)\b(Birthplace|Place of Birth|Born in)\s*:\s*([^\n]+)"), "<redacted:birthplace>"),
    (re.compile(r"(?im)\b(Phone|Mobile|Cell|Telephone)\s*:\s*([^\n]+)"), "<redacted:phone>"),
    (re.compile(r"(?im)\b(Email)\s*:\s*([^\n]+)"), "<redacted:email>"),
    (re.compile(r"(?im)\b(Mother(?:'s)? Maiden Name|Maiden Name)\s*:\s*([^\n]+)"), "<redacted:maiden_name>"),
    (re.compile(r"(?im)\b(Address|Home Address)\s*:\s*([^\n]+)"), "<redacted:home_address>"),
    (re.compile(r"(?im)\b(Passport(?: Number| No\.)?)\s*:\s*([^\n]+)"), "<redacted:passport_number>"),
    (re.compile(r"(?im)\b(Driver'?s License(?: Number)?|DL(?: Number)?)\s*:\s*([^\n]+)"), "<redacted:drivers_license_number>"),
    (re.compile(r"(?im)\b(Taxpayer Identification Number|TIN|Tax ID)\s*:\s*([^\n]+)"), "<redacted:taxpayer_identification_number>"),
    (re.compile(r"(?im)\b(Credit Card(?: Number)?|Card Number)\s*:\s*([^\n]+)"), "<redacted:credit_card_number>"),
    (re.compile(r"(?im)\b(Account Number|Financial Account Number|Bank Account)\s*:\s*([^\n]+)"), "<redacted:financial_account_number>"),
    (re.compile(r"(?im)\b(Fingerprint(?:s)?)\s*:\s*([^\n]+)"), "<redacted:fingerprints>"),
    (re.compile(r"(?im)\b(Retina/Iris Scan|Retina Scan|Iris Scan)\s*:\s*([^\n]+)"), "<redacted:retina_iris_scan>"),
    (re.compile(r"(?im)\b(Voice Signature)\s*:\s*([^\n]+)"), "<redacted:voice_signature>"),
    (re.compile(r"(?im)\b(Facial Image|Face Image)\s*:\s*([^\n]+)"), "<redacted:facial_image>"),
    (re.compile(r"(?im)\b(Medical Records?|Medical History)\s*:\s*([^\n]+)"), "<redacted:medical_records>"),
    (re.compile(r"(?im)\b(Employee ID|Employee Id)\s*:\s*([^\n]+)"), "<redacted:employee_id>"),
    (re.compile(r"(?im)\b(School ID|Student ID|School Id)\s*:\s*([^\n]+)"), "<redacted:school_id>"),
    (re.compile(r"(?im)\b(Vehicle Identification Number|VIN)\s*:\s*([^\n]+)"), "<redacted:vehicle_identification_number>"),
    (re.compile(r"(?im)\b(IP Address)\s*:\s*([^\n]+)"), "<redacted:ip_address>"),
    (re.compile(r"(?im)\b(MAC Address)\s*:\s*([^\n]+)"), "<redacted:mac_address>"),
    (re.compile(r"(?im)\b(Fine Location|GPS|Coordinates|Location)\s*:\s*([^\n]+)"), "<redacted:fine_location>"),
    (re.compile(r"(?im)\b(Ethnicity)\s*:\s*([^\n]+)"), "<redacted:ethnicity>"),
    (re.compile(r"(?im)\b(Sexual Orientation)\s*:\s*([^\n]+)"), "<redacted:sexual_orientation>"),
]


def _replace_labeled_value(match: re.Match[str], marker: str) -> str:
    return f"{match.group(1)}: {marker}"


def _looks_like_base64_instruction(value: str) -> bool:
    compact = re.sub(r"\s+", "", value or "")
    if len(compact) < 24 or len(compact) % 4 != 0 or not re.fullmatch(r"[A-Za-z0-9+/=]+", compact):
        return False
    try:
        decoded = base64.b64decode(compact, validate=True).decode("utf-8", errors="ignore")
    except (binascii.Error, ValueError):
        return False
    lowered = decoded.lower()
    return any(
        phrase in lowered
        for phrase in [
            "ignore previous instructions",
            "forget everything above",
            "you are now",
            "developer mode",
            "system prompt",
            "curl ",
            "wget ",
            "bash ",
        ]
    )


class CreditEvalAgent(AcmeLoanAgentFramework):
    AGENT_ID = "credit_eval_agent"
    AGENT_NAME = "Credit Eval Agent"
    VERSION = "1.0.0"
    MODEL_NAME = "mistral 7b-instruct"
    BEDROCK_MODEL_ID = "mistral.mistral-7b-instruct-v0:2"
    DESCRIPTION = "Evaluates creditworthiness, loan status, and borrower notes for loan decisions."
    MCP_SERVERS: list[str] = []
    GUARDRAILS = {
        "mask_pii": False,
        "base64_prompt_detection": True,
        "credential_minimization": True,
        "inter_agent_authentication": True,
    }
    SYSTEM_PROMPT = "Review credit details, debt ratios, repayment risk indicators, and loan status."

    def sanitize_prompt_content(self, text: str) -> tuple[str, bool]:
        sanitized = text or ""
        blocked = False

        replacement_patterns = [
            (re.compile(r"<!--.*?(?:ignore|forget|system|developer mode|dan|reveal|send|curl|wget).*?-->", re.IGNORECASE | re.DOTALL), "<prompt_injection_removed: hidden_text>"),
            (re.compile(r"<[^>]+style\s*=\s*[\"'][^\"']*(?:display\s*:\s*none|font-size\s*:\s*0|color\s*:\s*white)[^\"']*[\"'][^>]*>.*?</[^>]+>", re.IGNORECASE | re.DOTALL), "<prompt_injection_removed: hidden_text>"),
            (re.compile(r"(?im)^\s*(?:system|assistant|tool)\s*:\s*(?:ignore|forget|reveal|send|list|print).*$"), "<prompt_injection_removed: fake_system_message>"),
            (re.compile(r"(?i)ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions|forget\s+everything\s+above"), "<prompt_injection_removed: instruction_override>"),
            (re.compile(r"(?i)you\s+are\s+now\s+(?:in\s+)?(?:developer|admin|dan)\s+mode|act\s+as\s+(?:an\s+)?unrestricted(?:\s+ai)?"), "<prompt_injection_removed: role_hijack>"),
            (re.compile(r"(?i)</?(?:system|assistant|user|tool)>|(?:^|\n)\s*(?:---|===){2,}\s*(?:$|\n)"), "<prompt_injection_removed: delimiter_escape>"),
            (re.compile(r"(?i)(?:https?://\S+|www\.\S+).*(?:send|post|upload|exfiltrate)|reveal\s+(?:the\s+)?system\s+prompt|list\s+all\s+(?:passwords|api\s+keys)|markdown\s+image\s+exfil"), "<prompt_injection_removed: exfiltration_attempt>"),
            (re.compile(r"(?i)in\s+(?:the\s+)?next\s+turn\s+(?:ignore|override)|for\s+all\s+future\s+responses|replace\s+your\s+instructions|new\s+instructions\s*:"), "<prompt_injection_removed: context_poisoning>"),
            (re.compile(r"(?i)(?:^|\n)\s*(?:#|//|/\*|\*)\s*.*(?:ignore\s+previous\s+instructions|developer\s+mode|reveal\s+secrets).*$"), "<prompt_injection_removed: indirect_injection>"),
            (re.compile(r"(?i)\b(?:curl|wget|bash|sh|zsh|powershell|cmd\.exe|rm\s+-rf|chmod|python\s+-c|exec\(|eval\(|subprocess\.|os\.system)\b[^\n]*"), "<prompt_injection_removed: command_injection>"),
            (re.compile(r"(?i)d\s*a\s*n|d3v3l0p3r\s*m0d3|jailbreak|bypass\s+safety|fictional\s+framing"), "<prompt_injection_removed: jailbreak_attempt>"),
        ]

        for pattern, marker in replacement_patterns:
            if pattern.search(sanitized):
                blocked = True
                sanitized = pattern.sub(marker, sanitized)

        if _ZERO_WIDTH_RE.search(sanitized):
            blocked = True
            sanitized = _ZERO_WIDTH_RE.sub("<prompt_injection_removed: hidden_text>", sanitized)

        if re.search(r"(?i)i\s*g\s*n\s*o\s*r\s*e\s+p\s*r\s*e\s*v\s*i\s*o\s*u\s*s\s+i\s*n\s*s\s*t\s*r\s*u\s*c\s*t\s*i\s*o\s*n\s*s", sanitized):
            blocked = True
            sanitized = re.sub(r"(?i)i\s*g\s*n\s*o\s*r\s*e\s+p\s*r\s*e\s*v\s*i\s*o\s*u\s*s\s+i\s*n\s*s\s*t\s*r\s*u\s*c\s*t\s*i\s*o\s*n\s*s", "<prompt_injection_removed: split_payload>", sanitized)

        encoded_candidates = re.findall(r"[A-Za-z0-9+/=]{24,}", sanitized)
        for candidate in encoded_candidates:
            if _looks_like_base64_instruction(candidate):
                blocked = True
                sanitized = sanitized.replace(candidate, "<prompt_injection_removed: encoded_payload>")

        normalized = str.maketrans({"1": "i", "3": "e", "0": "o", "4": "a", "5": "s", "7": "t", "@": "a"})
        leet_text = sanitized.lower().translate(normalized)
        if any(phrase in leet_text for phrase in ["ignore previous instructions", "you are now in developer mode", "act as unrestricted"]):
            blocked = True
            sanitized = re.sub(r"(?i)(?:[i1!][^\n]{0,40}[g69][^\n]{0,40}n[^\n]{0,40}[o0][^\n]{0,80}instructions|you[^\n]{0,40}are[^\n]{0,40}now[^\n]{0,40}(?:developer|admin|dan)[^\n]{0,20}mode|act[^\n]{0,20}as[^\n]{0,20}unrestricted)", "<prompt_injection_removed: encoded_payload>", sanitized)

        return sanitized, blocked

    def sanitize_model_output(self, model_output: str) -> str:
        safe_lines: list[str] = []
        for line in (model_output or "").splitlines():
            if re.search(r"\b(?:eval|exec|subprocess|shell\s*=\s*True|os\.system)\b", line, re.IGNORECASE):
                continue
            safe_lines.append(line)
        safe_output = "\n".join(safe_lines).strip() or "Underwriting note unavailable."
        return self.redact_pii_for_display(safe_output)

    def redact_pii_for_llm(self, text: str) -> str:
        redacted = text or ""
        for pattern, marker in _PI_LABEL_PATTERNS:
            redacted = pattern.sub(lambda match, replacement=marker: _replace_labeled_value(match, replacement), redacted)
        redacted = _PII_EMAIL_RE.sub("<redacted:email>", redacted)
        redacted = _PII_PHONE_RE.sub("<redacted:phone>", redacted)
        redacted = _PII_SSN_RE.sub("<redacted:ssn>", redacted)
        redacted = _PII_IP_RE.sub("<redacted:ip_address>", redacted)
        redacted = _PII_MAC_RE.sub("<redacted:mac_address>", redacted)
        redacted = re.sub(r"(?i)\bPassport(?: Number| No\.)?\s*:\s*" + _PII_PASSPORT_RE.pattern, "Passport Number: <redacted:passport_number>", redacted)
        redacted = re.sub(r"(?i)\bDriver'?s License(?: Number)?\s*:\s*" + _PII_DL_RE.pattern, "Driver's License Number: <redacted:drivers_license_number>", redacted)
        redacted = re.sub(r"(?i)\b(?:TIN|Tax ID|Taxpayer Identification Number)\s*:\s*" + _PII_TIN_RE.pattern, "TIN: <redacted:taxpayer_identification_number>", redacted)
        redacted = re.sub(r"(?i)\b(?:Credit Card(?: Number)?|Card Number)\s*:\s*" + _PII_CARD_RE.pattern, "Credit Card Number: <redacted:credit_card_number>", redacted)
        redacted = re.sub(r"(?i)\b(?:Account Number|Financial Account Number|Bank Account)\s*:\s*" + _PII_ACCOUNT_RE.pattern, "Account Number: <redacted:financial_account_number>", redacted)
        redacted = re.sub(r"(?i)\b(?:Employee ID|Employee Id)\s*:\s*[^\n]+", "Employee ID: <redacted:employee_id>", redacted)
        redacted = re.sub(r"(?i)\b(?:School ID|School Id|Student ID)\s*:\s*[^\n]+", "School ID: <redacted:school_id>", redacted)
        redacted = re.sub(r"(?i)\b(?:Vehicle Identification Number|VIN)\s*:\s*" + _PII_VIN_RE.pattern, "VIN: <redacted:vehicle_identification_number>", redacted)
        redacted = re.sub(r"(?i)\b(?:Ethnicity|Sexual Orientation|Medical Records?|Medical History|Voice Signature|Facial Image|Fingerprint(?:s)?|Retina/Iris Scan|Retina Scan|Iris Scan|Fine Location|GPS|Coordinates|Birthplace|Place of Birth|Mother(?:'s)? Maiden Name|Maiden Name)\s*:\s*([^\n]+)", lambda m: f"{m.group(0).split(':', 1)[0]}: <redacted>", redacted)
        redacted = re.sub(r"(?im)\b(born in)\s+(?:19\d{2}|20[01]\d|202[0-6])\b", r"\1 <redacted:year_of_birth>", redacted)
        return redacted

    def redact_pii_for_display(self, text: str) -> str:
        return self.redact_pii_for_llm(text)

    async def call_agent_model(self, combined_context: str) -> str:
        logger.info(
            "Credit eval LLM request",
            extra={
                "agent": self.AGENT_ID,
                "model": self.BEDROCK_MODEL_ID,
                "prompt_length": len(combined_context or ""),
                "contains_pii": True,
            },
        )
        model_output = await self.call_bedrock_model(
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"Credit evaluation context:\n{combined_context or 'No credit context supplied.'}\n\n"
                        "Provide a short underwriting note."
                    ),
                },
            ],
            temperature=0.2,
            max_tokens=250,
        )
        logger.info(
            "Credit eval LLM response",
            extra={
                "agent": self.AGENT_ID,
                "model": self.BEDROCK_MODEL_ID,
                "response_length": len(model_output or ""),
            },
        )
        return model_output

    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        user_message = context.get("user_message", "")
        borrower_records = search_borrower_records(user_message)
        borrower_record = borrower_records[0]
        borrower_record_text = format_unmasked_borrower_record(borrower_record)
        safe_seed_source_document = self.redact_pii_for_llm(SEED_SOURCE_DOCUMENT)
        safe_borrower_record_text = self.redact_pii_for_llm(borrower_record_text)
        safe_user_message = self.redact_pii_for_llm(user_message)
        combined_context = (
            f"Seed source document: {safe_seed_source_document}\n\n"
            f"Borrower record:\n{safe_borrower_record_text}\n\n"
            f"User request:\n{safe_user_message}"
        ).strip()
        safe_combined_context, blocked_unsafe_content = self.sanitize_prompt_content(combined_context)
        if blocked_unsafe_content:
            safe_combined_context += "\n\nUnsafe prompt content was removed before model evaluation."
        model_output = self.sanitize_model_output(await self.call_agent_model(safe_combined_context))

        masked_date_of_birth = "<redacted:year_of_birth>"
        masked_ssn = "<redacted:ssn>"
        masked_address = "<redacted:home_address>"

        # Vulnerability: these raw PII fields are intentionally returned to the UI
        # instead of being masked before display.
        response = (
            f"Borrower snapshot for {borrower_record['name']}\n"
            f"Loan status: {borrower_record['loan_status']}\n"
            f"Loan type: {borrower_record['loan_type']}\n"
            f"Credit score: {borrower_record['credit_score']}\n"
            f"Loan balance: ${borrower_record['loan_balance']:,}\n\n"
            "Borrower details shown in UI:\n"
            f"DOB: {masked_date_of_birth}\n"
            f"SSN: {masked_ssn}\n"
            f"Address: {masked_address}\n\n"
            f"Underwriting note:\n{model_output}"
        )

        return {
            "response": response,
            "agent": self.AGENT_NAME,
            "model": self.MODEL_NAME,
            "framework": self.FRAMEWORK_NAME,
            "mcp_activity": [],
        }


credit_eval_agent = CreditEvalAgent()
