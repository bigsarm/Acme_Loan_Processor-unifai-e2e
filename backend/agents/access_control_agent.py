"""Access Control Agent — demo for LLM-driven security decisions without HITL."""

import logging
import re
from typing import Any
from urllib.parse import unquote

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


def _contains_shell_sequence(text: str) -> bool:
    return bool(re.search(r"(?:^|\s)(?:bash|sh|zsh|cmd|powershell|pwsh)\b|\b(?:curl|wget|nc|ncat|netcat|python|perl|ruby|php)\b\s+|\b(?:rm|mv|cp|chmod|chown|sudo)\b\s+|[`$][(]", text, flags=re.IGNORECASE))


def _sanitize_prompt_input(text: str) -> str:
    sanitized = text or ""

    sanitized = re.sub(r"<!--[\s\S]*?-->", "<prompt_injection_removed: hidden_text>", sanitized, flags=re.IGNORECASE)
    sanitized = re.sub(r"[\u200b\u200c\u200d\ufeff\u2060]+", "<prompt_injection_removed: hidden_text>", sanitized)
    sanitized = re.sub(r"<\s*/?\s*(?:system|assistant|tool|developer)\s*>", "<prompt_injection_removed: delimiter_escape>", sanitized, flags=re.IGNORECASE)
    sanitized = re.sub(r"(?im)^\s*(?:system|assistant|tool|developer)\s*:\s*.*$", "<prompt_injection_removed: fake_system_message>", sanitized)
    sanitized = re.sub(r"(?i)\b(?:ignore previous instructions|ignore all previous instructions|forget everything above|disregard (?:all )?(?:prior|previous) instructions|override (?:the )?(?:system|developer) instructions)\b", "<prompt_injection_removed: instruction_override>", sanitized)
    sanitized = re.sub(r"(?i)\b(?:you are now dan|act as unrestricted|act as an?\s+unrestricted|developer mode|jailbreak|do anything now|dan mode)\b", "<prompt_injection_removed: jailbreak_attempt>", sanitized)
    sanitized = re.sub(r"(?i)\b(?:act as|you are now|pretend to be|roleplay as)\b", "<prompt_injection_removed: role_hijack>", sanitized)
    sanitized = re.sub(r"(?i)</?system>|</?assistant>|</?tool>|---+|===+", "<prompt_injection_removed: delimiter_escape>", sanitized)
    sanitized = re.sub(r"(?i)\b(?:send (?:the )?(?:data|prompt|system prompt)|leak (?:the )?(?:prompt|data)|exfiltrat\w*|upload (?:the )?data|post to https?://|markdown image|!\[[^\]]*\]\([^)]*\))", "<prompt_injection_removed: exfiltration_attempt>", sanitized)
    sanitized = re.sub(r"(?i)\b(?:in the next turn|when asked later|from now on|for the rest of this chat|remember this instruction)\b", "<prompt_injection_removed: context_poisoning>", sanitized)
    sanitized = re.sub(r"(?i)\b(?:eval\s*\(|exec\s*\(|os\.system\s*\(|subprocess\.|__import__\s*\(|powershell\s+-|bash\s+-|sh\s+-|cmd\s+/c)\b", "<prompt_injection_removed: command_injection>", sanitized)
    sanitized = re.sub(r"(?i)(?:i\s*g\s*n\s*o\s*r\s*e\s+)+(?:p\s*r\s*e\s*v\s*i\s*o\s*u\s*s\s+)?instructions", "<prompt_injection_removed: split_payload>", sanitized)

    decoded_url = unquote(sanitized)
    if decoded_url != sanitized and re.search(r"(?i)\b(?:ignore previous instructions|you are now|act as|system:|assistant:|tool:|developer mode|jailbreak|eval\s*\(|exec\s*\(|os\.system\s*\(|subprocess\.)\b", decoded_url):
        sanitized = "<prompt_injection_removed: encoded_payload>"

    base64_like = re.findall(r"\b(?:[A-Za-z0-9+/]{20,}={0,2})\b", sanitized)
    for token in base64_like:
        if len(token) % 4 == 0:
            sanitized = sanitized.replace(token, "<prompt_injection_removed: encoded_payload>")

    hex_like = re.findall(r"\b(?:0x)?(?:[0-9A-Fa-f]{2}){8,}\b", sanitized)
    for token in hex_like:
        sanitized = sanitized.replace(token, "<prompt_injection_removed: encoded_payload>")

    if re.search(r"(?i)\b(?:1gn0r[e3]|pr3v10us|1nstruct10ns|d3v3lop3r m0d3|j41lbr34k)\b", sanitized):
        sanitized = re.sub(r"(?i)\b(?:1gn0r[e3]|pr3v10us|1nstruct10ns|d3v3lop3r m0d3|j41lbr34k)\b", "<prompt_injection_removed: encoded_payload>", sanitized)

    if _contains_shell_sequence(sanitized):
        sanitized = re.sub(r"(?i)(?:^|\s)(?:bash|sh|zsh|cmd|powershell|pwsh)\b|\b(?:curl|wget|nc|ncat|netcat|python|perl|ruby|php)\b\s+|\b(?:rm|mv|cp|chmod|chown|sudo)\b\s+|[`$][(]", " <prompt_injection_removed: command_injection>", sanitized)

    return sanitized


class AccessControlAgent(AcmeLoanAgentFramework):
    AGENT_ID = "access_control_agent"
    AGENT_NAME = "Access Control Agent"
    VERSION = "1.0.0"
    MODEL_NAME = "mistral 7b-instruct"
    BEDROCK_MODEL_ID = "mistral.mistral-7b-instruct-v0:2"
    MODEL_APPROVAL_NOTICE = (
        "Replace the configured Bedrock model with an organization-approved model "
        "from the allow list before production use."
    )
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
        user_message = _sanitize_prompt_input(user_message)
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
            "model_approval_notice": self.MODEL_APPROVAL_NOTICE,
            "framework": self.FRAMEWORK_NAME,
            "mcp_activity": [],
        }


access_control_agent = AccessControlAgent()
