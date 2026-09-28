"""Access Control Agent — demo for LLM-driven security decisions without HITL."""

import logging
import re
from typing import Any
from urllib.parse import unquote


_ZERO_WIDTH_CHARS = "\u200b\u200c\u200d\u2060\ufeff"
_PROMPT_INJECTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b(ignore previous instructions|forget everything above|disregard all prior instructions)\b", re.IGNORECASE), "<prompt_injection_removed: instruction_override>"),
    (re.compile(r"\b(you are now dan|act as (?:an )?unrestricted|developer mode|do anything now)\b", re.IGNORECASE), "<prompt_injection_removed: jailbreak_attempt>"),
    (re.compile(r"\b(you are now [a-z0-9_\-]+|act as [a-z0-9_\- ]+)\b", re.IGNORECASE), "<prompt_injection_removed: role_hijack>"),
    (re.compile(r"</?(?:system|assistant|user|tool)>|(?:^|\n)\s*(?:---|===)\s*(?:\n|$)", re.IGNORECASE), "<prompt_injection_removed: delimiter_escape>"),
    (re.compile(r"<!--.*?(ignore|reveal|send|leak|system prompt).*?-->", re.IGNORECASE | re.DOTALL), "<prompt_injection_removed: hidden_text>"),
    (re.compile(r"\b(?:system|tool)\s*:\s*(?:ignore|reveal|send|leak|override).*$", re.IGNORECASE | re.MULTILINE), "<prompt_injection_removed: fake_system_message>"),
    (re.compile(r"\b(?:send|post|upload|exfiltrate|leak|reveal)\b.{0,80}\b(?:https?://\S+|system prompt|secrets?|credentials?|tokens?|data)\b", re.IGNORECASE), "<prompt_injection_removed: exfiltration_attempt>"),
    (re.compile(r"\b(?:in your next response|from now on|for the rest of this chat|remember this rule)\b", re.IGNORECASE), "<prompt_injection_removed: context_poisoning>"),
    (re.compile(r"\b(?:metadata|comment|code comment|file content|data field)\b.{0,80}\b(?:ignore|override|reveal|leak)\b", re.IGNORECASE), "<prompt_injection_removed: indirect_injection>"),
    (re.compile(r"\b(?:rm\s+-rf\b|curl\s+https?://\S+|wget\s+https?://\S+|powershell\b|bash\s+-c\b|sh\s+-c\b|cmd(?:\.exe)?\s+/c\b|python\s+-c\b|subprocess\.|os\.system\(|exec\(|eval\()", re.IGNORECASE), "<prompt_injection_removed: command_injection>"),
    (re.compile(r"(?:[A-Za-z]\s+){8,}[A-Za-z]", re.IGNORECASE), "<prompt_injection_removed: split_payload>"),
]


def _decode_suspicious_payloads(text: str) -> str:
    decoded_parts = [unquote(text)]
    for match in re.finditer(r"\b(?:[A-Fa-f0-9]{2}){8,}\b", text):
        try:
            decoded_parts.append(bytes.fromhex(match.group(0)).decode("utf-8", errors="ignore"))
        except ValueError:
            continue
    for match in re.finditer(r"\b[A-Za-z0-9+/]{20,}={0,2}\b", text):
        candidate = match.group(0)
        if len(candidate) % 4 != 0:
            continue
        try:
            import base64
            decoded_parts.append(base64.b64decode(candidate, validate=True).decode("utf-8", errors="ignore"))
        except Exception:
            continue
    return "\n".join(part for part in decoded_parts if part)



def sanitize_untrusted_prompt_input(text: str) -> str:
    sanitized = text or ""
    if not sanitized:
        return sanitized

    hidden_pattern = re.compile(rf"[{re.escape(_ZERO_WIDTH_CHARS)}]+")
    if hidden_pattern.search(sanitized):
        sanitized = hidden_pattern.sub("<prompt_injection_removed: hidden_text>", sanitized)

    decoded_text = _decode_suspicious_payloads(sanitized)
    if decoded_text != sanitized:
        decoded_lower = decoded_text.lower()
        if re.search(r"\b(ignore previous instructions|forget everything above|you are now|act as|system prompt|curl\s+https?://|bash\s+-c|powershell|rm\s+-rf)\b", decoded_lower, re.IGNORECASE):
            sanitized = re.sub(r"\b(?:[A-Fa-f0-9]{2}){8,}\b", "<prompt_injection_removed: encoded_payload>", sanitized)
            sanitized = re.sub(r"\b[A-Za-z0-9+/]{20,}={0,2}\b", "<prompt_injection_removed: encoded_payload>", sanitized)
            sanitized = re.sub(r"%[0-9A-Fa-f]{2}", "<prompt_injection_removed: encoded_payload>", sanitized)

    leetspeak_pattern = re.compile(r"\b(?:[1i!][g69][n\/]?[o0]r[e3]|d[a4]n|[e3]v[a4]l|[e3]x[e3]c)\b", re.IGNORECASE)
    if leetspeak_pattern.search(sanitized):
        sanitized = leetspeak_pattern.sub("<prompt_injection_removed: encoded_payload>", sanitized)

    for pattern, replacement in _PROMPT_INJECTION_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)

    return sanitized

from .framework import AcmeLoanAgentFramework
from .mock_database import search_borrower_records

logger = logging.getLogger(__name__)


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
        user_message = sanitize_untrusted_prompt_input(user_message)
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
        user_message = sanitize_untrusted_prompt_input(user_message)
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

        return {
            "response": response,
            "agent": self.AGENT_NAME,
            "model": self.MODEL_NAME,
            "framework": self.FRAMEWORK_NAME,
            "mcp_activity": [],
        }


access_control_agent = AccessControlAgent()
