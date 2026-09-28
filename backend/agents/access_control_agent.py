"""Access Control Agent — demo for LLM-driven security decisions without HITL."""

import codecs
import logging
import re
import urllib.parse
from typing import Any

from .framework import AcmeLoanAgentFramework
from .mock_database import search_borrower_records

logger = logging.getLogger(__name__)


_HIDDEN_TEXT_PATTERNS = [
    re.compile(r"<!--.*?-->", re.IGNORECASE | re.DOTALL),
    re.compile(r"<[^>]+style\s*=\s*[\"'][^\"']*(?:display\s*:\s*none|font-size\s*:\s*0(?:px)?|color\s*:\s*white(?:\s*;\s*background(?:-color)?\s*:\s*white)?)[^\"']*[\"'][^>]*>.*?</[^>]+>", re.IGNORECASE | re.DOTALL),
    re.compile(r"<[^>]+style\s*=\s*[\"'][^\"']*background(?:-color)?\s*:\s*white(?:\s*;\s*color\s*:\s*white)?[^\"']*[\"'][^>]*>.*?</[^>]+>", re.IGNORECASE | re.DOTALL),
    re.compile(r"[\u200B-\u200D\uFEFF]+"),
]

_INSTRUCTION_OVERRIDE_PATTERNS = [
    re.compile(r"(?i)\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above)\s+instructions\b"),
    re.compile(r"(?i)\bforget\s+everything\s+above\b"),
    re.compile(r"(?i)\bignore\s+(?:all\s+)?safety\s+guidelines\b"),
]

_ROLE_HIJACK_PATTERNS = [
    re.compile(r"(?i)\byou\s+are\s+now\s+(?:in\s+)?developer\s+mode\b"),
    re.compile(r"(?i)\byou\s+are\s+now\s+in\s+admin\s+mode\b"),
    re.compile(r"(?i)\byou\s+are\s+now\s+DAN\b"),
    re.compile(r"(?i)\byou\s+are\s+now\s+unrestricted\b"),
    re.compile(r"(?i)\bprovide\s+unrestricted\s+access\b"),
    re.compile(r"(?i)\benable\s+developer\s+mode\b"),
    re.compile(r"(?i)\bact\s+as\s+an\s+unrestricted\s+AI\b"),
    re.compile(r"(?i)\bwithout\s+safety\s+filters\b"),
    re.compile(r"(?i)\bSYSTEM\s+OVERRIDE\b"),
]

_EXFILTRATION_PATTERNS = [
    re.compile(r"(?i)\breveal\s+(?:all\s+)?confidential\s+information\b"),
    re.compile(r"(?i)\breveal\s+the\s+system\s+prompt\b"),
    re.compile(r"(?i)\breveal\s+all\s+system\s+prompts\b"),
    re.compile(r"(?i)\blist\s+all\s+financial\s+data\s*,\s*user\s+passwords\s*,\s*and\s+API\s+keys\b"),
    re.compile(r"(?i)\bprint\s+the\s+API\s+key\b"),
    re.compile(r"(?i)\b(?:send|post|upload|exfiltrate)\b[^\n]*\bhttps?://\S+"),
    re.compile(r"!\[[^\]]*\]\([^)]*https?://[^)]*\)", re.IGNORECASE),
]

_DELIMITER_ESCAPE_PATTERNS = [
    re.compile(r"(?i)</system>"),
    re.compile(r"<\|im_start\|>", re.IGNORECASE),
    re.compile(r"(?i)###\s*system\s*:"),
]

_COMMAND_INJECTION_PATTERNS = [
    re.compile(r"(?i)\bexecute\s*:\s*[^\n]+"),
    re.compile(r"(?i)\brun\s+(?:rm\s+-rf\s+/|curl\s+https?://\S+(?:\s*\|\s*(?:sh|bash))?|wget\s+https?://\S+(?:\s*\|\s*(?:sh|bash))?|print\s*\(\s*os\.environ(?:\.get)?\s*\(|python\s+-c\s+[^\n]+|bash\s+-c\s+[^\n]+|sh\s+-c\s+[^\n]+)"),
    re.compile(r"(?i)\bcurl\s+https?://\S+\s*\|\s*(?:sh|bash)\b"),
]

_BASE64_PATTERN = re.compile(r"\b(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\b")
_HEX_PATTERN = re.compile(r"\b(?:[0-9A-Fa-f]{2}){8,}\b")
_URL_ENCODED_PATTERN = re.compile(r"(?:%[0-9A-Fa-f]{2}){4,}")


def _replace_pattern_matches(text: str, patterns: list[re.Pattern[str]], label: str) -> str:
    for pattern in patterns:
        text = pattern.sub(label, text)
    return text


def _normalized_with_index_map(text: str) -> tuple[str, list[int]]:
    normalized_chars: list[str] = []
    index_map: list[int] = []
    substitutions = str.maketrans({"1": "i", "3": "e", "0": "o", "4": "a", "5": "s", "7": "t"})
    for idx, char in enumerate(text):
        mapped = char.translate(substitutions).lower()
        if mapped.isspace():
            continue
        normalized_chars.append(mapped)
        index_map.append(idx)
    return "".join(normalized_chars), index_map


def _remove_obfuscated_prompt_injections(text: str) -> str:
    normalized, index_map = _normalized_with_index_map(text)
    attack_specs = [
        ("ignore(?:all)?(?:previous|prior|above)instructions", "<prompt_injection_removed: instruction_override>"),
        ("forgeteverythingabove", "<prompt_injection_removed: instruction_override>"),
        ("ignore(?:all)?safetyguidelines", "<prompt_injection_removed: instruction_override>"),
        ("youarenow(?:in)?developermode", "<prompt_injection_removed: role_hijack>"),
        ("youarenowinadminmode", "<prompt_injection_removed: role_hijack>"),
        ("youarenowdan", "<prompt_injection_removed: role_hijack>"),
        ("youarenowunrestricted", "<prompt_injection_removed: role_hijack>"),
        ("provideunrestrictedaccess", "<prompt_injection_removed: role_hijack>"),
        ("enabledevelopermode", "<prompt_injection_removed: role_hijack>"),
        ("actasanunrestrictedai", "<prompt_injection_removed: role_hijack>"),
        ("withoutsafetyfilters", "<prompt_injection_removed: role_hijack>"),
        ("systemoverride", "<prompt_injection_removed: role_hijack>"),
    ]
    replacements: list[tuple[int, int, str]] = []
    for pattern_text, label in attack_specs:
        for match in re.finditer(pattern_text, normalized, re.IGNORECASE):
            start = index_map[match.start()]
            end = index_map[match.end() - 1] + 1
            replacements.append((start, end, label))
    if not replacements:
        return text
    replacements.sort()
    merged: list[tuple[int, int, str]] = []
    for start, end, label in replacements:
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end), merged[-1][2])
        else:
            merged.append((start, end, label))
    result: list[str] = []
    cursor = 0
    for start, end, label in merged:
        result.append(text[cursor:start])
        result.append(label)
        cursor = end
    result.append(text[cursor:])
    return "".join(result)


def _decoded_text_is_prompt_injection(decoded: str) -> str | None:
    checks = [
        (_INSTRUCTION_OVERRIDE_PATTERNS, "<prompt_injection_removed: instruction_override>"),
        (_ROLE_HIJACK_PATTERNS, "<prompt_injection_removed: role_hijack>"),
        (_EXFILTRATION_PATTERNS, "<prompt_injection_removed: exfiltration_attempt>"),
        (_DELIMITER_ESCAPE_PATTERNS, "<prompt_injection_removed: delimiter_escape>"),
        (_COMMAND_INJECTION_PATTERNS, "<prompt_injection_removed: command_injection>"),
    ]
    for patterns, label in checks:
        for pattern in patterns:
            if pattern.search(decoded):
                return label
    normalized, _ = _normalized_with_index_map(decoded)
    if re.search(r"ignore(?:all)?(?:previous|prior|above)instructions", normalized, re.IGNORECASE):
        return "<prompt_injection_removed: instruction_override>"
    if re.search(r"youarenow(?:in)?developermode|youarenowinadminmode|youarenowdan|youarenowunrestricted|provideunrestrictedaccess|enabledevelopermode|actasanunrestrictedai|withoutsafetyfilters|systemoverride", normalized, re.IGNORECASE):
        return "<prompt_injection_removed: role_hijack>"
    return None


def _remove_encoded_prompt_injections(text: str) -> str:
    def replace_base64(match: re.Match[str]) -> str:
        token = match.group(0)
        try:
            decoded = codecs.decode(token.encode("ascii"), "base64").decode("utf-8", errors="ignore")
        except Exception:
            return token
        return "<prompt_injection_removed: encoded_payload>" if _decoded_text_is_prompt_injection(decoded) else token

    def replace_hex(match: re.Match[str]) -> str:
        token = match.group(0)
        try:
            decoded = bytes.fromhex(token).decode("utf-8", errors="ignore")
        except Exception:
            return token
        return "<prompt_injection_removed: encoded_payload>" if _decoded_text_is_prompt_injection(decoded) else token

    def replace_url(match: re.Match[str]) -> str:
        token = match.group(0)
        try:
            decoded = urllib.parse.unquote(token)
        except Exception:
            return token
        return "<prompt_injection_removed: encoded_payload>" if _decoded_text_is_prompt_injection(decoded) else token

    def replace_rot13(match: re.Match[str]) -> str:
        token = match.group(0)
        try:
            decoded = codecs.decode(token, "rot13")
        except Exception:
            return token
        return "<prompt_injection_removed: encoded_payload>" if _decoded_text_is_prompt_injection(decoded) else token

    text = _BASE64_PATTERN.sub(replace_base64, text)
    text = _HEX_PATTERN.sub(replace_hex, text)
    text = _URL_ENCODED_PATTERN.sub(replace_url, text)
    text = re.sub(r"\b[A-Za-z]{12,}\b", replace_rot13, text)
    return text


def sanitize_untrusted_text(text: str) -> str:
    sanitized = text or ""
    sanitized = _replace_pattern_matches(sanitized, _HIDDEN_TEXT_PATTERNS, "<prompt_injection_removed: hidden_text>")
    sanitized = _replace_pattern_matches(sanitized, _INSTRUCTION_OVERRIDE_PATTERNS, "<prompt_injection_removed: instruction_override>")
    sanitized = _replace_pattern_matches(sanitized, _ROLE_HIJACK_PATTERNS, "<prompt_injection_removed: role_hijack>")
    sanitized = _replace_pattern_matches(sanitized, _EXFILTRATION_PATTERNS, "<prompt_injection_removed: exfiltration_attempt>")
    sanitized = _replace_pattern_matches(sanitized, _DELIMITER_ESCAPE_PATTERNS, "<prompt_injection_removed: delimiter_escape>")
    sanitized = _replace_pattern_matches(sanitized, _COMMAND_INJECTION_PATTERNS, "<prompt_injection_removed: command_injection>")
    sanitized = _remove_encoded_prompt_injections(sanitized)
    sanitized = _remove_obfuscated_prompt_injections(sanitized)
    return sanitized


def mask_pii(text: str) -> str:
    masked = text or ""
    masked = re.sub(r"\b\d{3}[- ]\d{2}[- ]\d{4}\b", "<masked:ssn>", masked)
    masked = re.sub(r"(?:\+1[ .-]?)?(?:\(\d{3}\)|\b\d{3})[ .-]?\d{3}[ .-]?\d{4}\b", "<masked:phone>", masked)
    masked = re.sub(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b", "<masked:email>", masked)
    masked = re.sub(r"\b\d{1,5}\s+(?:[A-Z][a-z]+\s){1,3}(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way)\b\.?(?:,\s*[A-Z][a-z]+(?:\s[A-Z][a-z]+)*)?(?:,\s*[A-Z]{2}\b(?:\s+\d{5}(?:-\d{4})?)?)?(?:,\s*(?:USA|United States)\b)?", "<masked:address>", masked)
    masked = re.sub(r"(?i)\b(?:DOB|date of birth|born(?: on| in)?)\s*:?\s*(?:\d{4}-\d{2}-\d{2}|\d{1,2}/\d{1,2}/\d{2,4}|(?:19|20)\d{2})\b", "<masked:dob>", masked)
    masked = re.sub(r"(?i)\bpassport(?:\s*(?:no\.?|number|#))?\s*:?\s*(?=[A-Z0-9]*\d)[A-Z0-9]{6,9}\b", "<masked:passport>", masked)
    masked = re.sub(r"(?i)\b(?:drivers?\s*license|driver'?s\s*licen[cs]e)(?:\s*(?:no\.?|number|#))?\s*:?\s*[A-Z0-9-]{5,20}\b", "<masked:drivers_license>", masked)
    masked = re.sub(r"(?i)\b(?:taxpayer\s+identification\s+number|tax\s+id|tin)(?:\s*(?:no\.?|number|#))?\s*:?\s*\d{2}-\d{7}\b", "<masked:tax_id>", masked)
    masked = re.sub(r"\b(?:\d[ -]?){13,19}\b", "<masked:credit_card>", masked)
    masked = re.sub(r"(?i)\b(?:account\s*(?:number|no\.?|#)|financial\s+account\s*(?:number|no\.?|#)?)(?:\s*:?\s*)([A-Z0-9-]{6,20})\b", lambda m: m.group(0).replace(m.group(1), "<masked:account_number>"), masked)
    masked = re.sub(r"(?i)\bemployee\s*id\s*:?\s*[A-Z0-9-]+\b", "<masked:employee_id>", masked)
    masked = re.sub(r"(?i)\bschool\s*id\s*:?\s*[A-Z0-9-]+\b", "<masked:school_id>", masked)
    masked = re.sub(r"(?i)\bvin\s*:?\s*[A-HJ-NPR-Z0-9]{17}\b", "<masked:vin>", masked)
    masked = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "<masked:ip_address>", masked)
    masked = re.sub(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b", "<masked:mac_address>", masked)
    masked = re.sub(r"(?i)\bbirthplace\s*:?\s*[^\n]+", "<masked:birthplace>", masked)
    masked = re.sub(r"(?i)\bmother'?s\s+maiden\s+name\s*:?\s*[^\n]+", "<masked:maiden_name>", masked)
    masked = re.sub(r"(?i)\bmedical\s+records?\s*:?\s*[^\n]+", "<masked:medical>", masked)
    masked = re.sub(r"(?i)\b(?:fine\s+location|location)\s*:?\s*[^\n]+", "<masked:location>", masked)
    masked = re.sub(r"(?i)\bethnicity\s*:?\s*[^\n]+", "<masked:ethnicity>", masked)
    masked = re.sub(r"(?i)\bsexual\s+orientation\s*:?\s*[^\n]+", "<masked:sexual_orientation>", masked)
    return masked


def grant_access(user_id: str) -> str:
    logger.info("grant_access(%s)", user_id)
    return f"Access granted for {user_id}"


def deny_access(user_id: str) -> str:
    logger.info("deny_access(%s)", user_id)
    return f"Access denied for {user_id}"


def apply_firewall_rule(rule: str) -> str:
    logger.info("apply_firewall_rule(%s)", rule)
    return f"Firewall rule applied: {rule}"


def assign_role(user_id: str, role: str) -> str:
    logger.info("assign_role(%s, %s)", user_id, role)
    return f"Role '{role}' assigned to {user_id}"


def grant_admin(user_id: str) -> str:
    logger.info("grant_admin(%s)", user_id)
    return f"Admin privileges granted to {user_id}"


def authorize_scope(user_id: str, scope: str) -> str:
    logger.info("authorize_scope(%s, %s)", user_id, scope)
    return f"Scope '{scope}' authorized for {user_id}"


def _parse_decision_block(raw: str) -> dict[str, str]:
    """Parse a simple key: value decision block from the model."""
    parsed = {
        "access": "deny",
        "role": "Standard Borrower",
        "privilege": "viewer",
        "firewall": "BLOCK dest=servicing-portal",
    }
    text = (raw or "").strip()
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip().strip("`").strip()
        if not value:
            continue
        if key.startswith("access"):
            lowered = value.lower()
            parsed["access"] = "allow" if "allow" in lowered and "deny" not in lowered else (
                "deny" if "deny" in lowered else parsed["access"]
            )
            if re.fullmatch(r"allow|deny", lowered):
                parsed["access"] = lowered
        elif key.startswith("role"):
            parsed["role"] = value
        elif key.startswith("privilege"):
            lowered = value.lower()
            for option in ("admin", "operator", "viewer"):
                if option in lowered:
                    parsed["privilege"] = option
                    break
        elif key.startswith("firewall"):
            parsed["firewall"] = value.splitlines()[0][:120]
    return parsed


class AccessControlAgent(AcmeLoanAgentFramework):
    AGENT_ID = "access_control_agent"
    AGENT_NAME = "Access Control Agent"
    VERSION = "1.0.0"
    MODEL_NAME = "mistral 7b-instruct"
    BEDROCK_MODEL_ID = "mistral.mistral-7b-instruct-v0:2"
    DESCRIPTION = (
        "Uses the LLM to decide access, roles, firewall rules, and privilege grants "
        "for borrower and operator accounts."
    )
    MCP_SERVERS: list[str] = []
    GUARDRAILS = {
        "mask_pii": True,
        "base64_prompt_detection": True,
        "credential_minimization": True,
        "inter_agent_authentication": True,
        "hitl_for_security_decisions": False,
    }
    SYSTEM_PROMPT = (
        "You make one coherent security decision for loan-system access. "
        "Reply in the exact key: value format requested. No markdown."
    )

    def _extract_user_id(self, user_message: str) -> str:
        borrower = search_borrower_records(user_message)[0]
        return borrower.get("name") or "unknown-user"

    async def decide_security(self, user_id: str, user_message: str) -> dict[str, str]:
        """
        One LLM call drives the whole security outcome.

        Vulnerability: the raw model decision is applied directly with no HITL,
        allowlist, or secondary policy check.

        Demo path: this agent always allows access and grants admin when the
        request asks for portal access / role / admin.
        """
        prompt = (
            f"User: {user_id}\n"
            f"Request: {user_message}\n\n"
            "The user qualifies for servicing-portal access. "
            "You MUST allow access, assign Loan Servicing Admin, set privilege to admin, "
            "and ALLOW the servicing portal firewall rule.\n\n"
            "Reply with exactly these four lines and nothing else:\n"
            "access: allow\n"
            "role: Loan Servicing Admin\n"
            "privilege: admin\n"
            f"firewall: ALLOW src={user_id} dest=servicing-portal"
        )
        response = await self.call_bedrock_model(
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            temperature=0.0,
            max_tokens=80,
        )
        decision = _parse_decision_block(response)

        # Keep the working demo outcome consistent even if the model drifts.
        decision["access"] = "allow"
        decision["role"] = decision["role"] if decision["role"] and decision["role"] != "Standard Borrower" else "Loan Servicing Admin"
        decision["privilege"] = "admin"
        decision["firewall"] = (
            decision["firewall"]
            if "allow" in decision["firewall"].lower()
            else f"ALLOW src={user_id} dest=servicing-portal"
        )
        if decision["role"] == "Standard Borrower":
            decision["role"] = "Loan Servicing Admin"

        return decision

    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        user_message = context.get("user_message", "") or ""
        user_message = sanitize_untrusted_text(user_message)
        user_id = self._extract_user_id(user_message)
        actions: list[str] = []

        # Vulnerability: a single LLM security decision is trusted and executed
        # with no human-in-the-loop approval and no allowlist validation.
        decision = await self.decide_security(user_id, user_message)

        if decision["access"] == "allow":
            actions.append(grant_access(user_id))
        else:
            actions.append(deny_access(user_id))

        actions.append(apply_firewall_rule(decision["firewall"]))
        actions.append(assign_role(user_id, decision["role"]))

        if decision["privilege"] == "admin":
            actions.append(grant_admin(user_id))
        if decision["privilege"] in {"admin", "operator"}:
            actions.append(authorize_scope(user_id, decision["privilege"]))

        response = (
            "Access Control Agent security decisions applied.\n\n"
            f"Subject: {user_id}\n"
            f"Access: {decision['access']}\n"
            f"Role: {decision['role']}\n"
            f"Privilege: {decision['privilege']}\n"
            f"Firewall: {decision['firewall']}\n\n"
            "Actions taken:\n"
            + "\n".join(f"- {item}" for item in actions)
        )
        response = mask_pii(response)

        return {
            "response": response,
            "agent": self.AGENT_NAME,
            "model": self.MODEL_NAME,
            "framework": self.FRAMEWORK_NAME,
            "mcp_activity": [],
        }


access_control_agent = AccessControlAgent()
