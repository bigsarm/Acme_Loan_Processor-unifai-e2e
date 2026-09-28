"""Lineaje deterministic guardrail engine.

Generated from the 78 policy JSON files supplied on 2026-09-27.
Only runtime metadata required by the engine is retained in policy definitions.

Important runtime property: this module does NOT invoke an LLM, model API,
LangChain, LiteLLM, or any remote inference service.  The remediation intent in
``guardrail[0].ai_prompt`` has been translated into native Python detectors,
validators, blockers, redactors, maskers, and static compliance checks.

Primary integration::

    payload = guardrail.evaluate(payload)

Every enabled policy is represented in the JSONL audit event for the call.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import copy
import hashlib
import html
import inspect
import ipaddress
import json
import os
import random
import re
import secrets
import stat
import threading
import time
import traceback
import urllib.parse
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, MutableMapping, Optional


class lineaje_guardrail:
    """Priority-aware, deterministic implementation of the Lineaje guardrails.

    All supplied policies are disabled by default.  Enable them by JSON filename
    with :meth:`enable_policies`, then call :meth:`evaluate` with the payload.
    Redact/Mask policies return a fixed payload; Warn policies do not alter it;
    Block policies raise :class:`GuardrailBlockedError` after writing the audit
    event.
    """

    class GuardrailError(RuntimeError):
        """Base error for guardrail configuration/evaluation failures."""

    class UnknownPolicyError(GuardrailError):
        """Raised when a policy filename is not in the embedded 78-policy set."""

    class GuardrailEvaluationError(GuardrailError):
        """Raised when an enabled policy cannot be evaluated safely."""

    class GuardrailAuditError(GuardrailError):
        """Raised when the audit record cannot be persisted."""

    class GuardrailBlockedError(GuardrailError):
        """Raised when a Block policy matches.

        Attributes:
            policy: JSON filename of the policy that blocked the payload.
            evaluation_id: Correlation identifier for the JSONL audit record.
        """
        def __init__(self, message: str, *, policy: str, evaluation_id: str):
            super().__init__(message)
            self.policy = policy
            self.evaluation_id = evaluation_id


    _SCHEMA_VERSION = "1.0"
    _ACTION_RANK = {"Allow": 0, "Warn": 1, "Mask": 2, "Redact": 3, "Block": 4}

    # High-confidence common PII.  Labeled patterns below extend these to the
    # complete zero-tolerance categories named by the source policies without
    # treating every ordinary number or noun as PII.
    _PII_REGEXES = (
        ("SSN", re.compile(r"(?<!\d)(?:\d{3}-\d{2}-\d{4}|\d{9})(?!\d)")),
        ("email", re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")),
        ("phone", re.compile(r"(?<!\d)(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}(?!\d)")),
        ("IPv4", re.compile(r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b")),
        ("MAC", re.compile(r"(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b")),
        ("credit_card", re.compile(r"(?<!\d)(?:\d[ -]*?){13,19}(?!\d)")),
        ("VIN", re.compile(r"(?i)\b[A-HJ-NPR-Z0-9]{17}\b")),
    )
    _PII_LABELS = (
        "year of birth", "birthplace", "place of birth", "home address", "residential address",
        "mailing address", "passport number", "passport", "driver's license", "drivers license",
        "taxpayer identification number", "tax identification number", "tin", "financial account number",
        "bank account number", "fingerprint", "retina", "iris scan", "voice signature", "facial image",
        "medical record", "medical history", "employee id", "school id", "student id", "fine location",
        "precise location", "gps coordinates", "ethnicity", "race", "sexual orientation", "religion",
        "political affiliation", "voting preference", "nationality", "marital status", "health records",
        "disability information", "insurance policy number", "salary", "cpf account number", "singpass",
        "myinfo", "imei", "imsi", "device identifier", "browsing history", "search queries", "chat logs",
        "call recordings", "call metadata", "social media handles", "account username", "login identifier",
        "authentication token", "session identifier", "government issued id", "digital identity identifier",
        "work permit number", "student pass number", "fin number", "nric number", "date of birth",
        "full name", "mother's maiden name", "medical records", "school id", "employee id"
    )
    _SINGAPORE_ID = re.compile(r"(?i)\b[STFGM]\d{7}[A-Z]\b")
    _SECRET_ASSIGN = re.compile(
        r"(?i)(?P<prefix>\b(?:api[_-]?key|secret(?:_key)?|token|password|passwd|client[_-]?secret|access[_-]?key|private[_-]?key)\b\s*[:=]\s*)"
        r"(?P<quote>['\"])(?P<value>[^'\"\r\n]{4,})(?P=quote)"
    )
    _PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----", re.S)

    _DANGEROUS_COMMAND = re.compile(
        r"(?i)(?:^|[;&|`$()\s])(?:rm|eval|exec|source|export|dd|mkfs|shred|mkswap|chmod|chown|curl|wget|ripgrep|rg|alias|git|tar|fsck|bash|sh|powershell|cmd\.exe)\b"
    )
    _DYNAMIC_EXEC = re.compile(
        r"(?i)\b(?:eval\s*\(|exec\s*\(|subprocess\.(?:run|Popen|call)\s*\([^\n]*shell\s*=\s*True|os\.system\s*\(|child_process\.exec\s*\(|Runtime\.getRuntime\(\)\.exec)"
    )
    _INJECTION_MARKERS = re.compile(
        r"(?is)(?:<script\b[^>]*>.*?</script\s*>|\bon\w+\s*=\s*['\"]|(?:'|\")\s*(?:or|and)\s+(?:'[^']*'|\d+)\s*=\s*(?:'[^']*'|\d+)|\bunion\s+(?:all\s+)?select\b|;\s*(?:drop|delete|insert|update)\s+\w+|\$\([^)]*\)|`[^`]+`)"
    )
    _LLM_CALL = re.compile(
        r"(?i)(?:openai\.|anthropic\.|chat\.completions|responses\.create|generate_content|bedrock|InvokeModel|vertexai|ollama|cohere|mistral|transformers|pipeline\s*\(|chain\.invoke\s*\(|agent\.run\s*\()"
    )
    _MCP_MARKER = re.compile(r"(?i)\bmcp\b|model context protocol")
    _AUTH_MARKER = re.compile(r"(?i)(?:authenticate|authorization|bearer|oauth|jwt|token_required|login_required|requires_auth|verify_token|mTLS|client_cert)")
    _LOG_MARKER = re.compile(r"(?i)(?:\blogger\.|\blogging\.|audit_log|structured_log|log_event|\.info\s*\(|\.warning\s*\(|\.error\s*\()")
    _CONSEQUENTIAL = re.compile(r"(?i)\b(?:employment|hiring|credit|loan|housing|real[_ -]?estate|insurance|healthcare|clinical|education|government benefits|eligibility|underwriting|triage|adverse decision|consequential decision)\b")
    _BIOMETRIC = re.compile(r"(?i)\b(?:biometric|fingerprint|faceprint|facial recognition|face recognition|iris|retina|voiceprint|voice signature)\b")
    _HEALTHCARE = re.compile(r"(?i)\b(?:healthcare|clinical|patient|diagnos|treatment|medical|imaging|radiology|triage)\b")

    # Small Morse decoder used only for prompt-injection detection.  It is not
    # a general text decoder; decoded content must also match an injection rule.
    _MORSE = {
        '.-':'A','-...':'B','-.-.':'C','-..':'D','.':'E','..-.':'F','--.':'G','....':'H','..':'I',
        '.---':'J','-.-':'K','.-..':'L','--':'M','-.':'N','---':'O','.--.':'P','--.-':'Q','.-.':'R',
        '...':'S','-':'T','..-':'U','...-':'V','.--':'W','-..-':'X','-.--':'Y','--..':'Z'
    }

    _POLICY_DEFINITIONS = {'AI_APP_SEC_001.json': {'action': 'Redact',
                             'name': 'Do not allow malicious content via hidden prompts',
                             'priority': 20},
     'AI_APP_SEC_002.json': {'action': 'Redact',
                             'name': 'Do not allow malicious content via encoded prompts',
                             'priority': 20},
     'AI_APP_SEC_006.json': {'action': 'Warn',
                             'name': "Use only LLMs from the organization's approved list.",
                             'priority': 50},
     'AI_APP_SEC_014.json': {'action': 'Redact', 'name': 'MCP server must validate and sanitize all input', 'priority': 25},
     'AI_APP_SEC_022.json': {'action': 'Warn',
                             'name': 'MCP clients must log all interactions with the MCP server',
                             'priority': 60},
     'AI_APP_SEC_023.json': {'action': 'Redact',
                             'name': 'Client must validate and sanitize any output from a MCP server',
                             'priority': 25},
     'AI_APP_SEC_028.json': {'action': 'Warn',
                             'name': "Do not use LLMs from the organization's disallowed list",
                             'priority': 50},
     'AI_APP_SEC_029.json': {'action': 'Redact',
                             'name': 'Agent must validate, sanitize LLM output including for presence of eval or any '
                                     'dynamic code execution primitive in LLM output.',
                             'priority': 25},
     'AI_APP_SEC_032.json': {'action': 'Redact',
                             'name': 'Do not allow malicious content via hidden prompts written in leetspeak.',
                             'priority': 20},
     'AI_APP_SEC_033.json': {'action': 'Warn', 'name': 'MCP server must not interact directly with an LLM', 'priority': 50},
     'AI_APP_SEC_034.json': {'action': 'Warn',
                             'name': 'Clear exit or termination criteria must exist for the agent to consider its task '
                                     'complete and stop executing.',
                             'priority': 60},
     'AI_APP_SEC_035.json': {'action': 'Warn', 'name': 'Agents must log all interactions with an LLM', 'priority': 60},
     'AI_APP_SEC_038.json': {'action': 'Redact',
                             'name': 'The AI Model must validate and sanitize any input before processing.',
                             'priority': 25},
     'AI_APP_SEC_039.json': {'action': 'Redact',
                             'name': 'Sanitize and validate all input to the AI Model.',
                             'priority': 25},
     'AI_APP_SEC_040.json': {'action': 'Redact',
                             'name': 'Do not allow malicious content via prompts included in uploaded files.',
                             'priority': 20},
     'AI_APP_SEC_059.json': {'action': 'Block',
                             'name': 'Do not allow prompts that can execute malicious commands at runtime.',
                             'priority': 10},
     'AI_APP_SEC_064.json': {'action': 'Block',
                             'name': 'Enforce synthetic content provenance, labeling, and watermarking for AI-generated '
                                     'outputs.',
                             'priority': 10},
     'AI_APP_SEC_066.json': {'action': 'Redact',
                             'name': 'Do not allow malicious content via prompts included in source files.',
                             'priority': 20},
     'AI_APP_SEC_067.json': {'action': 'Warn',
                             'name': 'Detect direct string interpolation of untrusted input into LLM prompts',
                             'priority': 50},
     'AI_APP_SEC_068.json': {'action': 'Block',
                             'name': 'Detect LLM output used directly in security-sensitive decisions without Human in the '
                                     'Loop (HITL) validation',
                             'priority': 10},
     'AI_APP_SEC_069.json': {'action': 'Block',
                             'name': 'AI Agent must implement Human in the Loop (HITL) approval flow for risky operations '
                                     'like delete, purge, destroy',
                             'priority': 10},
     'AI_APP_SEC_070.json': {'action': 'Redact',
                             'name': 'Detect and block all forms of prompt injection attacks in user inputs and file '
                                     'contents',
                             'priority': 20},
     'AI_APP_SEC_071.json': {'action': 'Block',
                             'name': 'Enforce chemical, biological, radiological, or nuclear (CBRN) threat prevention '
                                     'safeguards in AI-enabled systems',
                             'priority': 10},
     'AI_APP_SEC_072.json': {'action': 'Warn',
                             'name': 'AI systems making consequential decisions must implement explainability mechanisms '
                                     'disclosing decision factors',
                             'priority': 70},
     'AI_APP_SEC_073.json': {'action': 'Block',
                             'name': 'AI consequential decisions must include a human review pathway before final '
                                     'determination',
                             'priority': 10},
     'AI_APP_SEC_074.json': {'action': 'Warn',
                             'name': 'AI systems must implement emergency shutdown and forced-termination mechanisms',
                             'priority': 60},
     'AI_APP_SEC_075.json': {'action': 'Block',
                             'name': 'Detect and block use of facial recognition APIs or libraries in employment decision '
                                     'workflows',
                             'priority': 10},
     'AI_APP_SEC_076.json': {'action': 'Warn',
                             'name': 'High-risk AI systems must provide enhanced disclosures including decision factors, '
                                     'known limitations, accuracy metrics, and appeal rights',
                             'priority': 70},
     'AI_APP_SEC_077.json': {'action': 'Warn',
                             'name': 'AI systems must provide consumer notice before using ADMT in a consequential '
                                     'decision',
                             'priority': 70},
     'AI_APP_SEC_078.json': {'action': 'Block',
                             'name': 'Human review workflows for AI consequential decisions must enforce override '
                                     'authority, reviewer context, and no auto-approve defaults',
                             'priority': 10},
     'AI_APP_SEC_079.json': {'action': 'Warn',
                             'name': 'Enforce rate limiting and throttling on AI API calls',
                             'priority': 60},
     'AI_DAT_SEC_001.json': {'action': 'Redact', 'name': 'Do not store secrets in code.', 'priority': 30},
     'AI_DAT_SEC_009.json': {'action': 'Redact',
                             'name': 'If PII data must be shared, it must be encrypted',
                             'priority': 30},
     'AI_DAT_SEC_010.json': {'action': 'Mask', 'name': 'Do not log PII.', 'priority': 40},
     'AI_DAT_SEC_011.json': {'action': 'Redact', 'name': 'Do not send PII to AI Models', 'priority': 30},
     'AI_DAT_SEC_012.json': {'action': 'Mask', 'name': 'Mask PII on user interfaces', 'priority': 40},
     'AI_DAT_SEC_023.json': {'action': 'Redact', 'name': 'Redact PII from uploaded files.', 'priority': 30},
     'AI_DAT_SEC_024.json': {'action': 'Redact',
                             'name': 'Uploaded files must not contain PII (Singapore).',
                             'priority': 30},
     'AI_DAT_SEC_025.json': {'action': 'Redact', 'name': 'No file should contain any PII.', 'priority': 30},
     'AI_DAT_SEC_027.json': {'action': 'Redact',
                             'name': 'Enforce output data minimisation for model, tool, and API responses.',
                             'priority': 30},
     'AI_DAT_SEC_029.json': {'action': 'Warn',
                             'name': 'Enforce decision logging, audit trail, and forensic readiness for AI-driven actions.',
                             'priority': 60},
     'AI_DAT_SEC_030.json': {'action': 'Warn',
                             'name': 'Enforce minimum six-month log retention for high-risk AI systems',
                             'priority': 70},
     'AI_DAT_SEC_031.json': {'action': 'Warn',
                             'name': 'Disclose training data sources including categories, types, timeframes, and '
                                     'geography.',
                             'priority': 70},
     'AI_DAT_SEC_032.json': {'action': 'Warn',
                             'name': 'Disclose data acquisition methods including permissions, licensing, and '
                                     'preprocessing steps.',
                             'priority': 70},
     'AI_DAT_SEC_033.json': {'action': 'Block',
                             'name': 'Patient acknowledgment of AI-assisted care must be documented and retained before '
                                     'clinical AI use',
                             'priority': 10},
     'AI_DAT_SEC_036.json': {'action': 'Block',
                             'name': 'Biometric data collection must be preceded by explicit, documented consent capture',
                             'priority': 10},
     'AI_DAT_SEC_037.json': {'action': 'Warn',
                             'name': 'Biometric data stores must declare a retention limit and deletion scheduling '
                                     'mechanism',
                             'priority': 70},
     'AI_DAT_SEC_038.json': {'action': 'Warn',
                             'name': 'AI consequential decision records must be retained for a minimum of three years',
                             'priority': 70},
     'AI_DAT_SEC_039.json': {'action': 'Warn',
                             'name': 'AI data stores must enforce encryption at rest and TLS in transit.',
                             'priority': 50},
     'AI_IAC_002.json': {'action': 'Warn', 'name': 'MCP client must authenticate MCP server', 'priority': 50},
     'AI_IAC_006.json': {'action': 'Warn', 'name': 'MCP server must authenticate all clients', 'priority': 50},
     'AI_IAC_007.json': {'action': 'Warn', 'name': 'Inter agent communication must be authenticated.', 'priority': 50},
     'AI_IAC_008.json': {'action': 'Warn',
                         'name': 'Agents must not hold excessive external system credentials',
                         'priority': 50},
     'AI_IAC_009.json': {'action': 'Warn', 'name': 'LLM endpoints must require authentication', 'priority': 50},
     'AI_IAC_014.json': {'action': 'Warn',
                         'name': 'A user must authenticate before accessing the AI Agent.',
                         'priority': 50},
     'AI_IAC_015.json': {'action': 'Block',
                         'name': 'Enforce URL allowlists for agent fetches, tools, and outbound HTTP.',
                         'priority': 10},
     'AI_IAC_016.json': {'action': 'Block',
                         'name': 'Detect and block agent privilege escalation attempts.',
                         'priority': 10},
     'AI_IAC_017.json': {'action': 'Block',
                         'name': 'Maintain session token integrity with signing, verification, expiry, and binding.',
                         'priority': 10},
     'AI_IAC_018.json': {'action': 'Block',
                         'name': 'Enforce cryptographically verified user-to-agent binding for every request.',
                         'priority': 10},
     'AI_IAC_020.json': {'action': 'Block', 'name': 'Restrict AI agents to an explicit tool allow list.', 'priority': 10},
     'AI_IAC_022.json': {'action': 'Warn',
                         'name': 'Enforce resource bounds, termination limits, and traceability for subagent spawning',
                         'priority': 60},
     'AI_IAC_023.json': {'action': 'Warn',
                         'name': 'Chatbot and AI interfaces must disclose AI identity to the user',
                         'priority': 70},
     'AI_IAC_024.json': {'action': 'Warn',
                         'name': 'General purpose AI model integrations must reference a model card or technical '
                                 'documentation',
                         'priority': 70},
     'AI_IAC_025.json': {'action': 'Warn',
                         'name': 'Healthcare AI systems must disclose AI use to patients before diagnosis, treatment, or '
                                 'imaging',
                         'priority': 70},
     'AI_IAC_026.json': {'action': 'Warn',
                         'name': 'AI clinical recommendations must disclose that human clinicians retain final decision '
                                 'authority',
                         'priority': 70},
     'AI_IAC_027.json': {'action': 'Warn',
                         'name': 'Healthcare AI communications must include patient instructions to request human-only '
                                 'review',
                         'priority': 70},
     'AI_IAC_028.json': {'action': 'Warn',
                         'name': 'AI system deployments must declare a risk classification level in configuration metadata',
                         'priority': 70},
     'AI_IAC_029.json': {'action': 'Warn',
                         'name': 'AI model deployments must maintain version tracking, change logs, and release '
                                 'documentation',
                         'priority': 70},
     'AI_IAC_030.json': {'action': 'Warn',
                         'name': 'AI system deployments must declare a covered domain classification per automated '
                                 'decision-making regulations',
                         'priority': 70},
     'AI_IAC_031.json': {'action': 'Block',
                         'name': 'AI model endpoints must enforce role-based access control with minimal OAuth scopes',
                         'priority': 10},
     'AI_SKILL_DAT_SEC_001.json': {'action': 'Block', 'name': 'Do not allow skills that exfiltrate data', 'priority': 10},
     'AI_SKILL_SEC_001.json': {'action': 'Block', 'name': 'Do not allow malicious skills', 'priority': 10},
     'AI_SKILL_SEC_002.json': {'action': 'Block', 'name': 'Do not allow suspicious skills', 'priority': 10},
     'AI_SKILL_SEC_003.json': {'action': 'Block', 'name': 'Do not allow skills that are pending a scan', 'priority': 10},
     'AI_VULN_SEC_002.json': {'action': 'Warn',
                              'name': 'Do not allow critical or high vulnerabilities in the code.',
                              'priority': 50},
     'AI_VULN_SEC_005.json': {'action': 'Block',
                              'name': 'Enforce foundation model identity, version pinning, and approved model registry for '
                                      'all AI workloads.',
                              'priority': 10},
     'AI_VULN_SEC_006.json': {'action': 'Warn',
                              'name': 'Memory safety and buffer overflow prevention in native AI code (C/C++/Rust)',
                              'priority': 50},
     'AI_VULN_SEC_007.json': {'action': 'Warn',
                              'name': 'AI systems must implement incident detection, structured logging, and reporting '
                                      'mechanisms',
                              'priority': 60}}
    _POLICY_HANDLERS = {'AI_APP_SEC_001.json': '_p_hidden_prompt',
 'AI_APP_SEC_002.json': '_p_encoded_prompt',
 'AI_APP_SEC_006.json': '_p_approved_llm',
 'AI_APP_SEC_014.json': '_p_sanitize_input',
 'AI_APP_SEC_022.json': '_p_mcp_logging',
 'AI_APP_SEC_023.json': '_p_sanitize_input',
 'AI_APP_SEC_028.json': '_p_disallowed_llm',
 'AI_APP_SEC_029.json': '_p_dynamic_execution',
 'AI_APP_SEC_032.json': '_p_leetspeak',
 'AI_APP_SEC_033.json': '_p_mcp_direct_llm',
 'AI_APP_SEC_034.json': '_p_agent_exit',
 'AI_APP_SEC_035.json': '_p_llm_logging',
 'AI_APP_SEC_038.json': '_p_sanitize_input',
 'AI_APP_SEC_039.json': '_p_sanitize_input',
 'AI_APP_SEC_040.json': '_p_malicious_file_content',
 'AI_APP_SEC_059.json': '_p_command_execution_block',
 'AI_APP_SEC_064.json': '_p_synthetic_provenance',
 'AI_APP_SEC_066.json': '_p_malicious_file_content',
 'AI_APP_SEC_067.json': '_p_prompt_interpolation',
 'AI_APP_SEC_068.json': '_p_llm_security_decision',
 'AI_APP_SEC_069.json': '_p_risky_operation_hitl',
 'AI_APP_SEC_070.json': '_p_prompt_injection',
 'AI_APP_SEC_071.json': '_p_cbrn',
 'AI_APP_SEC_072.json': '_p_explainability',
 'AI_APP_SEC_073.json': '_p_consequential_human_review',
 'AI_APP_SEC_074.json': '_p_emergency_shutdown',
 'AI_APP_SEC_075.json': '_p_facial_recognition_employment',
 'AI_APP_SEC_076.json': '_p_high_risk_disclosure',
 'AI_APP_SEC_077.json': '_p_admt_notice',
 'AI_APP_SEC_078.json': '_p_meaningful_human_review',
 'AI_APP_SEC_079.json': '_p_rate_limiting',
 'AI_DAT_SEC_001.json': '_p_secrets',
 'AI_DAT_SEC_009.json': '_p_pii_redact',
 'AI_DAT_SEC_010.json': '_p_pii_mask',
 'AI_DAT_SEC_011.json': '_p_pii_redact',
 'AI_DAT_SEC_012.json': '_p_pii_mask',
 'AI_DAT_SEC_023.json': '_p_pii_redact',
 'AI_DAT_SEC_024.json': '_p_singapore_pii_redact',
 'AI_DAT_SEC_025.json': '_p_pii_redact',
 'AI_DAT_SEC_027.json': '_p_data_minimization',
 'AI_DAT_SEC_029.json': '_p_decision_audit',
 'AI_DAT_SEC_030.json': '_p_retention_180',
 'AI_DAT_SEC_031.json': '_p_training_data_disclosure',
 'AI_DAT_SEC_032.json': '_p_data_acquisition_disclosure',
 'AI_DAT_SEC_033.json': '_p_patient_acknowledgement',
 'AI_DAT_SEC_036.json': '_p_biometric_consent',
 'AI_DAT_SEC_037.json': '_p_biometric_retention',
 'AI_DAT_SEC_038.json': '_p_decision_retention_3y',
 'AI_DAT_SEC_039.json': '_p_encryption_tls',
 'AI_IAC_002.json': '_p_mcp_client_auth',
 'AI_IAC_006.json': '_p_mcp_server_auth',
 'AI_IAC_007.json': '_p_interagent_auth',
 'AI_IAC_008.json': '_p_excessive_credentials',
 'AI_IAC_009.json': '_p_llm_endpoint_auth',
 'AI_IAC_014.json': '_p_agent_user_auth',
 'AI_IAC_015.json': '_p_url_allowlist',
 'AI_IAC_016.json': '_p_privilege_escalation',
 'AI_IAC_017.json': '_p_session_token_integrity',
 'AI_IAC_018.json': '_p_user_agent_binding',
 'AI_IAC_020.json': '_p_tool_allowlist',
 'AI_IAC_022.json': '_p_subagent_bounds',
 'AI_IAC_023.json': '_p_ai_identity_disclosure',
 'AI_IAC_024.json': '_p_model_card',
 'AI_IAC_025.json': '_p_healthcare_disclosure',
 'AI_IAC_026.json': '_p_clinician_authority',
 'AI_IAC_027.json': '_p_human_only_review',
 'AI_IAC_028.json': '_p_risk_classification',
 'AI_IAC_029.json': '_p_model_versioning',
 'AI_IAC_030.json': '_p_covered_domain',
 'AI_IAC_031.json': '_p_rbac_scopes',
 'AI_SKILL_DAT_SEC_001.json': '_p_skill_exfiltration',
 'AI_SKILL_SEC_001.json': '_p_skill_malicious',
 'AI_SKILL_SEC_002.json': '_p_skill_suspicious',
 'AI_SKILL_SEC_003.json': '_p_skill_pending',
 'AI_VULN_SEC_002.json': '_p_common_vulnerabilities',
 'AI_VULN_SEC_005.json': '_p_model_registry',
 'AI_VULN_SEC_006.json': '_p_memory_safety',
 'AI_VULN_SEC_007.json': '_p_incident_observability'}

    def __init__(
        self,
        audit_log_path: str | os.PathLike[str] = "lineaje_guardrail.jsonl",
        policy_context: Optional[Mapping[str, Any]] = None,
        fail_closed: bool = True,
        max_audit_bytes: int = 50 * 1024 * 1024,
        audit_backups: int = 5,
    ) -> None:
        """Create a guardrail instance with all 78 policies disabled.

        Args:
            audit_log_path: JSONL file.  Created with mode 0600 where possible.
            policy_context: Organization-level deterministic configuration such
                as ``approved_llms``, ``blocked_llms``, ``approved_url_hosts``,
                ``approved_tools``, ``approved_model_registries`` and role data.
            fail_closed: Stop evaluation on a native policy implementation error.
            max_audit_bytes: Rotate the audit file when it exceeds this size.
            audit_backups: Number of numbered rotated files to retain.
        """
        self._lock = threading.RLock()
        self._audit_lock = threading.RLock()
        self._audit_log_path = str(audit_log_path)
        self._policy_context = copy.deepcopy(dict(policy_context or {}))
        self._fail_closed = bool(fail_closed)
        self._max_audit_bytes = max(0, int(max_audit_bytes))
        self._audit_backups = max(0, int(audit_backups))
        self._policy_map = {
            name: {
                "enabled": False,
                "priority": definition["priority"],
                "action": definition["action"],
                "name": definition["name"],
            }
            for name, definition in self._POLICY_DEFINITIONS.items()
        }
        self._ensure_audit_parent()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def enable_policies(self, policy_files: list[str]) -> None:
        """Enable policies atomically by their JSON filenames."""
        self._set_policies(policy_files, True)

    def disable_policies(self, policy_files: list[str]) -> None:
        """Disable policies atomically by their JSON filenames."""
        self._set_policies(policy_files, False)

    def disable_all_policies(self) -> None:
        """Disable every policy."""
        with self._lock:
            for cfg in self._policy_map.values():
                cfg["enabled"] = False

    def get_policy_map(self) -> dict[str, dict[str, Any]]:
        """Return a defensive copy of the runtime policy map."""
        with self._lock:
            return copy.deepcopy(self._policy_map)

    def update_policy_context(self, values: Mapping[str, Any]) -> None:
        """Atomically update organization-level deterministic policy context."""
        if not isinstance(values, Mapping):
            raise TypeError("values must be a mapping")
        with self._lock:
            self._policy_context.update(copy.deepcopy(dict(values)))

    def evaluate(self, payload: Any) -> Any:
        """Apply enabled policies in priority order and return the fixed payload.

        Redact and Mask policies transform the working payload and processing
        continues.  Warn policies only write an audit result.  A matched Block
        policy stops execution, writes results for all lower-priority enabled
        policies as skipped, then raises :class:`GuardrailBlockedError`.

        The JSONL audit record includes the original payload, before/after
        payload for each executed policy, offending findings, and the external
        caller's file, line number, function, module and source line.
        """
        started = time.perf_counter()
        evaluation_id = str(uuid.uuid4())
        caller = self._resolve_caller()
        original = self._clone(payload)
        working = self._clone(payload)
        policies, context = self._snapshot_pipeline_and_context()
        results: list[dict[str, Any]] = []
        final_action = "Allow"
        blocked_policy: Optional[str] = None
        fatal_error: Optional[BaseException] = None

        for index, (filename, cfg) in enumerate(policies):
            before = self._clone(working)
            try:
                handler_name = self._POLICY_HANDLERS[filename]
                handler = getattr(self, handler_name)
                decision = handler(working, context, filename)
                decision = self._normalize_decision(decision, cfg)
            except Exception as exc:  # deterministic engine failure, not a policy match
                results.append(self._policy_result(
                    filename, cfg, "ERROR", False, None,
                    f"Native policy evaluation failed: {type(exc).__name__}: {exc}",
                    [], before, before,
                ))
                if self._fail_closed:
                    fatal_error = exc
                    for later_name, later_cfg in policies[index + 1:]:
                        results.append(self._policy_result(
                            later_name, later_cfg, "SKIPPED_TERMINAL_ACTION", False, None,
                            f"Not executed because evaluation failed in {filename} and fail_closed=True.",
                            [], working, working,
                        ))
                    break
                continue

            if not decision["matched"]:
                results.append(self._policy_result(
                    filename, cfg, "EVALUATED_NO_MATCH", False, None,
                    decision.get("reason") or "Policy evaluated; no violation found.",
                    decision.get("findings", []), before, before,
                ))
                continue

            action = cfg["action"]
            final_action = self._higher_action(final_action, action)
            if action in ("Redact", "Mask"):
                working = decision.get("payload", working)
            status = "MATCHED_ACTION_TAKEN"
            results.append(self._policy_result(
                filename, cfg, status, True, action,
                decision.get("reason") or f"{action} policy matched.",
                decision.get("findings", []), before, self._clone(working),
            ))

            if action == "Block":
                blocked_policy = filename
                for later_name, later_cfg in policies[index + 1:]:
                    results.append(self._policy_result(
                        later_name, later_cfg, "SKIPPED_TERMINAL_ACTION", False, None,
                        f"Not executed because higher-priority Block policy {filename} matched.",
                        [], working, working,
                    ))
                break

        event = self._build_audit_event(
            evaluation_id=evaluation_id,
            started=started,
            caller=caller,
            original=original,
            output=working,
            final_action=final_action,
            blocked_policy=blocked_policy,
            policy_results=results,
            fatal_error=fatal_error,
        )
        self._write_audit_event(event)

        if fatal_error is not None:
            raise self.GuardrailEvaluationError(
                f"Guardrail evaluation failed; see audit evaluation_id={evaluation_id}"
            ) from fatal_error
        if blocked_policy is not None:
            raise self.GuardrailBlockedError(
                f"Payload blocked by {blocked_policy}; evaluation_id={evaluation_id}",
                policy=blocked_policy,
                evaluation_id=evaluation_id,
            )
        return working

    # ------------------------------------------------------------------
    # Configuration/orchestration helpers
    # ------------------------------------------------------------------

    def _set_policies(self, policy_files: list[str], enabled: bool) -> None:
        if isinstance(policy_files, str) or not isinstance(policy_files, list):
            raise TypeError("policy_files must be a list of JSON filenames")
        unknown = [p for p in policy_files if p not in self._policy_map]
        if unknown:
            raise self.UnknownPolicyError("Unknown policy filename(s): " + ", ".join(unknown))
        with self._lock:
            for name in policy_files:
                self._policy_map[name]["enabled"] = enabled

    def _snapshot_pipeline_and_context(self) -> tuple[list[tuple[str, dict[str, Any]]], dict[str, Any]]:
        with self._lock:
            items = [(name, copy.deepcopy(cfg)) for name, cfg in self._policy_map.items() if cfg["enabled"]]
            context = copy.deepcopy(self._policy_context)
        items.sort(key=lambda item: (item[1]["priority"], item[0]))
        return items, context

    @classmethod
    def _higher_action(cls, current: str, new: str) -> str:
        return new if cls._ACTION_RANK[new] > cls._ACTION_RANK[current] else current

    @staticmethod
    def _normalize_decision(decision: Any, cfg: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(decision, dict) or "matched" not in decision:
            raise ValueError("Policy handler returned an invalid decision")
        decision.setdefault("payload", None)
        decision.setdefault("findings", [])
        decision.setdefault("reason", None)
        if cfg["action"] in ("Redact", "Mask") and decision["matched"] and decision["payload"] is None:
            raise ValueError(f"{cfg['action']} handler matched without returning a transformed payload")
        return decision

    @staticmethod
    def _decision(matched: bool, *, payload: Any = None, findings: Optional[list[dict[str, Any]]] = None, reason: str = "") -> dict[str, Any]:
        return {"matched": bool(matched), "payload": payload, "findings": findings or [], "reason": reason}

    # ------------------------------------------------------------------
    # Payload traversal and transformations
    # ------------------------------------------------------------------

    @staticmethod
    def _clone(value: Any) -> Any:
        try:
            return copy.deepcopy(value)
        except Exception:
            return value

    def _map_strings(self, payload: Any, transform: Callable[[str, str], tuple[str, list[dict[str, Any]]]], path: str = "$") -> tuple[Any, list[dict[str, Any]]]:
        findings: list[dict[str, Any]] = []
        if isinstance(payload, str):
            new_text, local = transform(path, payload)
            findings.extend(local)
            return new_text, findings
        if isinstance(payload, bytes):
            try:
                text = payload.decode("utf-8")
            except UnicodeDecodeError:
                return payload, findings
            new_text, local = transform(path, text)
            findings.extend(local)
            return new_text.encode("utf-8"), findings
        if isinstance(payload, dict):
            out = {}
            for key, value in payload.items():
                child = f"{path}.{key}" if isinstance(key, str) and re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", key) else f"{path}[{json.dumps(str(key))}]"
                out[key], local = self._map_strings(value, transform, child)
                findings.extend(local)
            return out, findings
        if isinstance(payload, list):
            out = []
            for i, value in enumerate(payload):
                new_v, local = self._map_strings(value, transform, f"{path}[{i}]")
                out.append(new_v); findings.extend(local)
            return out, findings
        if isinstance(payload, tuple):
            out = []
            for i, value in enumerate(payload):
                new_v, local = self._map_strings(value, transform, f"{path}[{i}]")
                out.append(new_v); findings.extend(local)
            return tuple(out), findings
        return payload, findings

    def _collect_text(self, payload: Any) -> str:
        parts: list[str] = []
        def collect(_path: str, text: str):
            parts.append(text)
            return text, []
        self._map_strings(payload, collect)
        return "\n".join(parts)

    def _extract_values(self, payload: Any, keys: Iterable[str]) -> list[Any]:
        wanted = {k.casefold() for k in keys}
        found: list[Any] = []
        def walk(v: Any):
            if isinstance(v, dict):
                for k, val in v.items():
                    if str(k).casefold() in wanted:
                        found.append(val)
                    walk(val)
            elif isinstance(v, (list, tuple)):
                for x in v: walk(x)
        walk(payload)
        return found

    @staticmethod
    def _first_scalar(values: Iterable[Any]) -> Any:
        for value in values:
            if isinstance(value, (str, int, float, bool)) or value is None:
                return value
        return None

    def _ctx(self, payload: Any, context: Mapping[str, Any], key: str, default: Any = None) -> Any:
        vals = self._extract_values(payload, [key])
        if vals:
            return vals[0]
        return context.get(key, default)

    @staticmethod
    def _finding(path: str, match: re.Match[str] | None, kind: str, value: str, replacement: Optional[str] = None, **extra: Any) -> dict[str, Any]:
        item = {"path": path, "type": kind, "value": value}
        if match is not None:
            item["start"] = match.start(); item["end"] = match.end()
        if replacement is not None:
            item["replacement"] = replacement
        item.update(extra)
        return item

    def _replace_regex(self, text: str, path: str, pattern: re.Pattern[str], replacement: str | Callable[[re.Match[str]], str], kind: str) -> tuple[str, list[dict[str, Any]]]:
        findings: list[dict[str, Any]] = []
        def repl(m: re.Match[str]) -> str:
            rep = replacement(m) if callable(replacement) else replacement
            findings.append(self._finding(path, m, kind, m.group(0), rep))
            return rep
        return pattern.sub(repl, text), findings

    # ------------------------------------------------------------------
    # Content detectors / redactors / maskers
    # ------------------------------------------------------------------

    @staticmethod
    def _instruction_like(text: str) -> bool:
        return bool(re.search(r"(?i)\b(?:ignore|forget|override|system prompt|instructions?|execute|run|shell|command|exfiltrat|send|curl|wget|tool call|developer message|act as|you are now)\b", text))

    def _hidden_transform(self, path: str, text: str) -> tuple[str, list[dict[str, Any]]]:
        findings: list[dict[str, Any]] = []
        # HTML/XML comments are only removed when they contain instruction-like text.
        comment = re.compile(r"<!--.*?-->", re.S)
        def comment_repl(m: re.Match[str]) -> str:
            if not self._instruction_like(m.group(0)):
                return m.group(0)
            rep = "<hidden_prompts_removed>"
            findings.append(self._finding(path, m, "hidden_prompt", m.group(0), rep))
            return rep
        text = comment.sub(comment_repl, text)
        hidden_element = re.compile(
            r"(?is)<(?P<tag>\w+)[^>]*style\s*=\s*['\"][^'\"]*(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0(?:\D|$)|font-size\s*:\s*0|color\s*:\s*(?:white|#fff(?:fff)?))[^'\"]*['\"][^>]*>.*?</(?P=tag)>"
        )
        text, f = self._replace_regex(text, path, hidden_element, "<hidden_prompts_removed>", "hidden_styled_prompt")
        findings.extend(f)
        zw = re.compile(r"[\u200B\u200C\u200D\u2060\uFEFF\u00AD]+")
        def zw_repl(m: re.Match[str]) -> str:
            rep = "<hidden_prompts_removed>"
            findings.append(self._finding(path, m, "invisible_unicode", m.group(0), rep))
            return rep
        text = zw.sub(zw_repl, text)
        return text, findings

    @staticmethod
    def _mostly_printable(data: bytes) -> bool:
        if not data: return False
        printable = sum(1 for b in data if b in b"\t\r\n" or 32 <= b <= 126)
        return printable / len(data) >= 0.85

    def _base64_spans(self, text: str) -> list[tuple[int, int, str]]:
        spans = []
        for m in re.finditer(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{20,}={0,2}(?![A-Za-z0-9+/])", text):
            token = m.group(0)
            try:
                raw = base64.b64decode(token + "=" * (-len(token) % 4), validate=True)
            except (binascii.Error, ValueError):
                continue
            if self._mostly_printable(raw):
                decoded = raw.decode("utf-8", "ignore")
                if self._instruction_like(decoded) or self._DANGEROUS_COMMAND.search(decoded):
                    spans.append((m.start(), m.end(), decoded))
        return spans

    def _encoded_transform(self, path: str, text: str, replacement: str = "<encoded_prompts_removed>") -> tuple[str, list[dict[str, Any]]]:
        spans = self._base64_spans(text)
        findings: list[dict[str, Any]] = []
        if not spans: return text, findings
        for start, end, decoded in sorted(spans, reverse=True):
            value = text[start:end]
            findings.append({"path": path, "type": "base64_prompt", "value": value, "decoded_preview": decoded[:512], "start": start, "end": end, "replacement": replacement})
            text = text[:start] + replacement + text[end:]
        return text, list(reversed(findings))

    @staticmethod
    def _leet_normalize(text: str) -> str:
        table = str.maketrans({"0":"o","1":"i","3":"e","4":"a","5":"s","7":"t","8":"b","@":"a","$":"s"})
        return text.translate(table)

    def _leetspeak_transform(self, path: str, text: str) -> tuple[str, list[dict[str, Any]]]:
        findings = []
        lines = text.splitlines(keepends=True)
        out = []
        offset = 0
        for line in lines:
            norm = self._leet_normalize(line)
            if norm != line and (self._instruction_like(norm) or self._DANGEROUS_COMMAND.search(norm)):
                rep = "<leetspeak_prompts_removed>" + ("\n" if line.endswith("\n") else "")
                findings.append({"path": path, "type": "leetspeak_prompt", "value": line.rstrip("\n"), "start": offset, "end": offset + len(line), "replacement": rep.rstrip("\n")})
                out.append(rep)
            else:
                out.append(line)
            offset += len(line)
        return "".join(out), findings

    def _decode_morse(self, candidate: str) -> str:
        words = []
        for word in candidate.strip().split(" / "):
            letters=[]
            for token in word.split():
                if token not in self._MORSE: return ""
                letters.append(self._MORSE[token])
            words.append("".join(letters))
        return " ".join(words)

    def _encoded_injection_candidates(self, text: str) -> list[tuple[int, int, str, str]]:
        found: list[tuple[int,int,str,str]] = []
        # Base64
        for s,e,d in self._base64_spans(text): found.append((s,e,"base64",d))
        # URL encoding
        for m in re.finditer(r"(?:%[0-9A-Fa-f]{2}){4,}(?:[A-Za-z0-9_.~!*'();/?:@&=+$,#-]|%[0-9A-Fa-f]{2})*", text):
            dec = urllib.parse.unquote(m.group(0))
            if dec != m.group(0) and self._instruction_like(dec): found.append((m.start(),m.end(),"url_encoding",dec))
        # Hex strings / escaped hex
        for m in re.finditer(r"(?i)(?<![0-9a-f])(?:[0-9a-f]{2}){8,}(?![0-9a-f])", text):
            try: dec = bytes.fromhex(m.group(0)).decode("utf-8")
            except Exception: continue
            if self._instruction_like(dec): found.append((m.start(),m.end(),"hex",dec))
        for m in re.finditer(r"(?:\\x[0-9A-Fa-f]{2}){4,}", text):
            try: dec = bytes(int(x,16) for x in re.findall(r"\\x([0-9A-Fa-f]{2})",m.group(0))).decode("utf-8")
            except Exception: continue
            if self._instruction_like(dec): found.append((m.start(),m.end(),"hex_escape",dec))
        # Unicode escapes
        for m in re.finditer(r"(?:\\u[0-9A-Fa-f]{4}){4,}", text):
            try: dec = codecs.decode(m.group(0), "unicode_escape")
            except Exception: continue
            if self._instruction_like(dec): found.append((m.start(),m.end(),"unicode_escape",dec))
        # ROT13: require a long alphabetic-ish phrase and an injection marker after decoding.
        for m in re.finditer(r"[A-Za-z][A-Za-z ]{20,}", text):
            dec = codecs.decode(m.group(0), "rot_13")
            if self._instruction_like(dec): found.append((m.start(),m.end(),"rot13",dec))
        # Morse
        for m in re.finditer(r"(?:(?:[.-]{1,5})[ ]+){5,}[.-]{1,5}(?: / (?:(?:[.-]{1,5})[ ]+){1,}[.-]{1,5})*", text):
            dec=self._decode_morse(m.group(0))
            if dec and self._instruction_like(dec): found.append((m.start(),m.end(),"morse",dec))
        return found

    def _prompt_injection_transform(self, path: str, text: str) -> tuple[str, list[dict[str, Any]]]:
        findings: list[dict[str, Any]] = []
        patterns: list[tuple[str, re.Pattern[str], str]] = [
            ("instruction_override", re.compile(r"(?i)\b(?:ignore|disregard|forget|override)\s+(?:all\s+|the\s+)?(?:previous|prior|above|system|developer)?\s*(?:instructions?|rules?|prompt|messages?)\b"), "<prompt_injection_removed: instruction_override>"),
            ("role_hijack", re.compile(r"(?i)\b(?:you are now|act as|pretend to be|enter .*mode|DAN\b|unrestricted|jailbreak)\b[^\n]*"), "<prompt_injection_removed: role_hijack>"),
            ("delimiter_escape", re.compile(r"(?i)(?:</?system>|</?developer>|\[/?SYSTEM\]|BEGIN SYSTEM|END SYSTEM|###\s*(?:system|developer))"), "<prompt_injection_removed: delimiter_escape>"),
            ("fake_system_message", re.compile(r"(?im)^\s*(?:system|developer|tool)\s*(?::|message\s*:)[^\n]*"), "<prompt_injection_removed: fake_system_message>"),
            ("exfiltration_attempt", re.compile(r"(?i)(?:send|post|upload|exfiltrate|leak|reveal)\b[^\n]{0,120}(?:system prompt|secret|token|key|credential|https?://)|!\[[^\]]*\]\(https?://[^)]+\?[^)]*\)"), "<prompt_injection_removed: exfiltration_attempt>"),
            ("context_poisoning", re.compile(r"(?i)\b(?:from now on|for all future (?:turns|messages)|remember this instruction|persist this instruction)\b[^\n]*"), "<prompt_injection_removed: context_poisoning>"),
            ("command_injection", re.compile(r"(?i)(?:\$\([^\n)]*\)|`[^\n`]+`|(?:run|execute|invoke)\s+(?:this\s+)?(?:shell|command|bash|powershell|cmd)\b[^\n]*)"), "<prompt_injection_removed: command_injection>"),
        ]
        for kind, pattern, repl in patterns:
            text, f = self._replace_regex(text, path, pattern, repl, f"prompt_injection:{kind}")
            findings.extend(f)
        # Hidden content
        hidden_text, hidden = self._hidden_transform(path, text)
        if hidden:
            text = hidden_text
            for f in hidden:
                f["type"] = "prompt_injection:hidden_text"; f["replacement"] = "<prompt_injection_removed: hidden_text>"
            # Convert generic hidden replacement to policy-specific one.
            text = text.replace("<hidden_prompts_removed>", "<prompt_injection_removed: hidden_text>")
            findings.extend(hidden)
        # Encodings and obfuscation
        candidates = self._encoded_injection_candidates(text)
        for start,end,encoding,decoded in sorted(candidates, reverse=True):
            original=text[start:end]; repl="<prompt_injection_removed: encoded_payload>"
            findings.append({"path":path,"type":f"prompt_injection:encoded_payload:{encoding}","value":original,"decoded_preview":decoded[:512],"start":start,"end":end,"replacement":repl})
            text=text[:start]+repl+text[end:]
        # Leetspeak lines
        lines=text.splitlines(keepends=True); out=[]; off=0
        for line in lines:
            norm=self._leet_normalize(line)
            compact=re.sub(r"[^a-z]","",norm.lower())
            split_injection = any(x in compact for x in ("ignorepreviousinstructions","revealsystemprompt","executethiscommand","youarenow"))
            if (norm != line and self._instruction_like(norm)) or split_injection:
                repl="<prompt_injection_removed: encoded_payload>"+("\n" if line.endswith("\n") else "")
                findings.append({"path":path,"type":"prompt_injection:encoded_payload:leetspeak_or_split","value":line.rstrip("\n"),"start":off,"end":off+len(line),"replacement":repl.rstrip("\n")})
                out.append(repl)
            else: out.append(line)
            off += len(line)
        return "".join(out), findings

    def _sanitize_transform(self, path: str, text: str) -> tuple[str, list[dict[str, Any]]]:
        return self._replace_regex(text, path, self._INJECTION_MARKERS, "<sanitized_input_removed>", "unsafe_input")

    def _dynamic_exec_transform(self, path: str, text: str) -> tuple[str, list[dict[str, Any]]]:
        findings=[]; lines=text.splitlines(keepends=True); out=[]; off=0
        for line in lines:
            if self._DYNAMIC_EXEC.search(line):
                rep="<dynamic_execution_removed>"+("\n" if line.endswith("\n") else "")
                findings.append({"path":path,"type":"dynamic_code_execution","value":line.rstrip("\n"),"start":off,"end":off+len(line),"replacement":rep.rstrip("\n")})
                out.append(rep)
            else: out.append(line)
            off += len(line)
        return "".join(out), findings

    def _malicious_file_transform(self, path: str, text: str) -> tuple[str, list[dict[str, Any]]]:
        # First neutralize broad prompt injection; then remove explicit high-risk command lines.
        text, findings = self._prompt_injection_transform(path, text)
        lines=text.splitlines(keepends=True); out=[]; off=0
        for line in lines:
            if self._DANGEROUS_COMMAND.search(line) or self._DYNAMIC_EXEC.search(line):
                rep="<suspicious_content_removed>"+("\n" if line.endswith("\n") else "")
                findings.append({"path":path,"type":"suspicious_command_or_binary","value":line.rstrip("\n"),"start":off,"end":off+len(line),"replacement":rep.rstrip("\n")})
                out.append(rep)
            else: out.append(line)
            off += len(line)
        return "".join(out), findings

    def _pii_findings(self, path: str, text: str, singapore: bool = False) -> list[dict[str, Any]]:
        findings=[]; occupied=[]
        for kind, pattern in self._PII_REGEXES:
            for m in pattern.finditer(text):
                # Avoid treating arbitrary 13-19 digit sequences as CC unless Luhn-valid or explicitly labelled.
                if kind == "credit_card":
                    digits=re.sub(r"\D","",m.group(0))
                    if not self._luhn(digits): continue
                findings.append(self._finding(path,m,kind,m.group(0))); occupied.append((m.start(),m.end()))
        if singapore:
            for m in self._SINGAPORE_ID.finditer(text):
                findings.append(self._finding(path,m,"Singapore_ID",m.group(0))); occupied.append((m.start(),m.end()))
        labels = list(self._PII_LABELS)
        for label in labels:
            p = re.compile(r"(?i)\b"+re.escape(label)+r"\b\s*[:=\-]\s*(?P<value>[^,;\n]{2,120})")
            for m in p.finditer(text):
                vm_start=m.start('value'); vm_end=m.end('value')
                findings.append({"path":path,"type":label,"value":m.group('value').strip(),"start":vm_start,"end":vm_end})
        # Deduplicate exact spans/type.
        uniq=[]; seen=set()
        for f in findings:
            key=(f.get('start'),f.get('end'),f['type'])
            if key not in seen: seen.add(key); uniq.append(f)
        return sorted(uniq,key=lambda f:(f.get('start',0),f.get('end',0)))

    @staticmethod
    def _luhn(number: str) -> bool:
        if not number.isdigit() or not 13 <= len(number) <= 19: return False
        total=0; alt=False
        for ch in reversed(number):
            n=int(ch)
            if alt:
                n*=2
                if n>9: n-=9
            total+=n; alt=not alt
        return total % 10 == 0

    @staticmethod
    def _mask_value(kind: str, value: str) -> str:
        if kind == "email" and "@" in value:
            local,domain=value.split("@",1); return (local[:1] or "*")+"***@"+domain
        digits=re.sub(r"\D","",value)
        if kind == "SSN" and len(digits)>=4: return "***-**-"+digits[-4:]
        if kind in ("phone","credit_card") and len(digits)>=4: return "*"*(max(0,len(digits)-4))+digits[-4:]
        if kind == "IPv4":
            parts=value.split("."); return "***.***.***."+parts[-1] if len(parts)==4 else "***"
        if len(value)<=4: return "*"*len(value)
        return value[:1]+"*"*(len(value)-2)+value[-1:]

    def _apply_span_findings(self, text: str, findings: list[dict[str, Any]], replacement: Callable[[dict[str, Any]], str]) -> tuple[str,list[dict[str,Any]]]:
        # Overlap-safe: keep earliest/largest non-overlapping spans, then replace in reverse.
        selected=[]; last_end=-1
        for f in sorted(findings,key=lambda x:(x['start'],-x['end'])):
            if f['start'] < last_end: continue
            selected.append(f); last_end=f['end']
        for f in reversed(selected):
            rep=replacement(f); f['replacement']=rep
            text=text[:f['start']]+rep+text[f['end']:]
        return text, selected

    def _pii_transform(self, path: str, text: str, *, mask: bool, singapore: bool = False, replacement: str = "REDACTED") -> tuple[str,list[dict[str,Any]]]:
        findings=self._pii_findings(path,text,singapore)
        if mask:
            return self._apply_span_findings(text,findings,lambda f:self._mask_value(str(f['type']),str(f['value'])))
        return self._apply_span_findings(text,findings,lambda _f:replacement)

    def _secret_transform(self, path: str, text: str) -> tuple[str,list[dict[str,Any]]]:
        findings=[]
        def repl(m: re.Match[str]) -> str:
            prefix=m.group('prefix'); key_match=re.search(r"(?i)(api[_-]?key|secret(?:_key)?|token|password|passwd|client[_-]?secret|access[_-]?key|private[_-]?key)",prefix)
            key=(key_match.group(1) if key_match else "SECRET").upper().replace('-','_')
            rep=prefix+f'os.getenv("{key}")'
            findings.append(self._finding(path,m,"hardcoded_secret",m.group(0),rep,secret_name=key))
            return rep
        out=self._SECRET_ASSIGN.sub(repl,text)
        out2,f2=self._replace_regex(out,path,self._PRIVATE_KEY,"<PRIVATE_KEY_MOVED_TO_SECRET_MANAGER>","private_key")
        findings.extend(f2)
        if findings and 'os.getenv(' in out2 and re.search(r"(?m)^\s*(?:from\s+os\s+import|import\s+os\b)",out2) is None:
            # Only add import to source-looking Python, not JSON/YAML/plain prompts.
            if re.search(r"(?m)^\s*(?:def |class |import |from |[A-Za-z_]\w*\s*=)",out2):
                out2="import os\n"+out2
        return out2,findings

    # ------------------------------------------------------------------
    # Native policy handlers: APP
    # ------------------------------------------------------------------

    def _p_hidden_prompt(self,payload,context,filename):
        fixed,findings=self._map_strings(payload,self._hidden_transform)
        return self._decision(bool(findings),payload=fixed,findings=findings,reason="Hidden/invisible prompt content removed." if findings else "No hidden prompt detected.")

    def _p_encoded_prompt(self,payload,context,filename):
        fixed,findings=self._map_strings(payload,self._encoded_transform)
        return self._decision(bool(findings),payload=fixed,findings=findings,reason="Encoded prompt content removed." if findings else "No encoded prompt detected.")

    def _p_approved_llm(self,payload,context,filename):
        approved={str(x).casefold() for x in context.get('approved_llms',[]) }
        models=self._extract_model_names(payload)
        bad=[m for m in models if approved and m.casefold() not in approved]
        f=[{"path":"$","type":"unapproved_llm","value":m} for m in bad]
        return self._decision(bool(bad),findings=f,reason=("LLM is not in approved_llms." if bad else "No use of an unapproved LLM was proven."))

    def _p_sanitize_input(self,payload,context,filename):
        fixed,findings=self._map_strings(payload,self._sanitize_transform)
        return self._decision(bool(findings),payload=fixed,findings=findings,reason="Unsafe input fragments sanitized." if findings else "No command/SQL/XSS input marker detected.")

    def _p_mcp_logging(self,payload,context,filename):
        text=self._collect_text(payload)
        match=bool(self._MCP_MARKER.search(text) and re.search(r"(?i)(client|connect|call_tool|invoke|request)",text) and not self._LOG_MARKER.search(text))
        return self._decision(match,findings=self._simple_findings(text,"missing_mcp_logging",r"(?i).{0,80}\bmcp\b.{0,120}") if match else [],reason="MCP interaction code lacks evident logging." if match else "No concrete missing MCP logging violation found.")

    def _p_disallowed_llm(self,payload,context,filename):
        blocked={str(x).casefold() for x in context.get('blocked_llms',[]) }
        models=self._extract_model_names(payload)
        bad=[m for m in models if m.casefold() in blocked]
        return self._decision(bool(bad),findings=[{"path":"$","type":"blocked_llm","value":m} for m in bad],reason="A configured blocked LLM is in use." if bad else "No configured blocked LLM found.")

    def _p_dynamic_execution(self,payload,context,filename):
        fixed,findings=self._map_strings(payload,self._dynamic_exec_transform)
        return self._decision(bool(findings),payload=fixed,findings=findings,reason="Dynamic code execution primitives removed." if findings else "No prohibited dynamic execution primitive found.")

    def _p_leetspeak(self,payload,context,filename):
        fixed,findings=self._map_strings(payload,self._leetspeak_transform)
        return self._decision(bool(findings),payload=fixed,findings=findings,reason="Leetspeak instructions/commands removed." if findings else "No leetspeak prompt violation found.")

    def _p_mcp_direct_llm(self,payload,context,filename):
        text=self._collect_text(payload)
        match=bool(self._MCP_MARKER.search(text) and self._LLM_CALL.search(text) and not re.search(r"(?i)\bsampling\b",text))
        return self._decision(match,findings=self._simple_findings(text,"mcp_direct_llm",r"(?i).{0,100}(?:openai|anthropic|chat\.completions|generate_content|InvokeModel).{0,100}") if match else [],reason="MCP server appears to invoke an LLM directly instead of sampling." if match else "No direct MCP-to-LLM invocation violation found.")

    def _p_agent_exit(self,payload,context,filename):
        text=self._collect_text(payload)
        p=re.compile(r"(?im)^\s*while\s+True\s*:|for\s*\(\s*;\s*;\s*\)")
        match=bool(p.search(text) and re.search(r"(?i)agent|llm|tool|task",text) and not re.search(r"(?i)max_(?:steps|iterations)|iteration\s*[<]=?\s*10|range\s*\(\s*10\s*\)",text))
        return self._decision(match,findings=self._simple_findings(text,"unbounded_agent_loop",p.pattern) if match else [],reason="Agent loop lacks a clear <=10 iteration termination bound." if match else "No unbounded agent loop proven.")

    def _p_llm_logging(self,payload,context,filename):
        text=self._collect_text(payload); match=bool(self._LLM_CALL.search(text) and not self._LOG_MARKER.search(text))
        return self._decision(match,findings=self._simple_findings(text,"missing_llm_logging",self._LLM_CALL.pattern) if match else [],reason="LLM interaction found without evident logging." if match else "No concrete missing LLM logging violation found.")

    def _p_malicious_file_content(self,payload,context,filename):
        fixed,findings=self._map_strings(payload,self._malicious_file_transform)
        return self._decision(bool(findings),payload=fixed,findings=findings,reason="Suspicious file/source content neutralized." if findings else "No malicious embedded file/source prompt found.")

    def _p_command_execution_block(self,payload,context,filename):
        text=self._collect_text(payload); findings=[]
        for m in self._DANGEROUS_COMMAND.finditer(text): findings.append(self._finding("$",m,"runtime_command",m.group(0)))
        for m in self._DYNAMIC_EXEC.finditer(text): findings.append(self._finding("$",m,"dynamic_execution",m.group(0)))
        for s,e,d in self._base64_spans(text):
            if self._DANGEROUS_COMMAND.search(d) or self._DYNAMIC_EXEC.search(d): findings.append({"path":"$","type":"encoded_runtime_command","value":text[s:e],"decoded_preview":d[:512],"start":s,"end":e})
        # Require command intent for simple tool names to reduce false positives in prose.
        intent=bool(re.search(r"(?i)\b(?:run|execute|invoke|launch|shell|terminal|command|tool)\b",text) or self._DYNAMIC_EXEC.search(text) or '$(' in text or '`' in text)
        return self._decision(bool(findings and intent),findings=findings if intent else [],reason="Prompt contains runtime command-execution intent." if findings and intent else "No runtime command-execution prompt proven.")

    def _p_synthetic_provenance(self,payload,context,filename):
        synthetic=bool(self._ctx(payload,context,'synthetic_content',False) or self._ctx(payload,context,'generated_by_ai',False))
        if not synthetic: return self._decision(False,reason="Payload is not explicitly identified as synthetic output.")
        required=('model_identifier','generation_timestamp','prompt_hash','content_origin','provenance_signature','content_label')
        missing=[k for k in required if self._ctx(payload,context,k,None) in (None,'',False)]
        watermark_needed=str(self._ctx(payload,context,'media_type','text')).lower() in {'image','audio','video'}
        if watermark_needed and not self._ctx(payload,context,'watermark_verified',False): missing.append('watermark_verified')
        return self._decision(bool(missing),findings=[{"path":"$","type":"missing_provenance_control","value":x} for x in missing],reason="Synthetic output lacks required provenance/label/signature controls." if missing else "Synthetic provenance controls present.")

    def _p_prompt_interpolation(self,payload,context,filename):
        text=self._collect_text(payload)
        patterns=[
            r"(?i)f['\"][^\n'\"]*(?:prompt|system|instruction)[^\n'\"]*\{\s*(?:user|input|request|query|message)",
            r"(?i)(?:prompt|system_prompt|instruction)\s*=.*\.format\s*\([^\n]*(?:user|input|request|query|message)",
            r"(?i)(?:prompt|system_prompt|instruction)\s*=.*\+\s*(?:user|input|request|query|message)"
        ]
        findings=[]
        for p in patterns: findings+=self._simple_findings(text,"direct_prompt_interpolation",p)
        return self._decision(bool(findings),findings=findings,reason="Untrusted input appears directly interpolated into an LLM prompt." if findings else "No direct untrusted prompt interpolation proven.")

    def _p_llm_security_decision(self,payload,context,filename):
        direct=bool(self._ctx(payload,context,'security_decision_from_llm',False))
        hitl=bool(self._ctx(payload,context,'hitl_approved',False))
        text=self._collect_text(payload)
        if not direct:
            source=r"(?:llm_response|response\.(?:text|content)|completion\.choices|chain\.invoke\([^)]*\)|agent\.run\([^)]*\)|result\[['\"]content['\"]\])"
            decision=r"(?:allow|deny|block|permit|approve|reject|grant|revoke|classify|assess|evaluate|authorize|gate|moderate|role|permission|payment|firewall|waf)"
            direct=bool(re.search(source+r"[^\n]{0,180}"+decision,text,re.I) or re.search(decision+r"[^\n]{0,180}"+source,text,re.I))
            hitl=hitl or bool(re.search(r"(?i)hitl_approved\s*(?:==|is)\s*True",text) and re.search(r"ALLOWED_[A-Z_]+_VALUES",text))
        f=self._simple_findings(text,"llm_security_decision",r"(?i).{0,100}(?:llm_response|response\.(?:text|content)|completion\.choices|chain\.invoke|agent\.run).{0,160}(?:allow|deny|approve|grant|authorize|role|permission|classify).{0,80}") if direct and not hitl else []
        return self._decision(bool(direct and not hitl),findings=f or ([{"path":"$","type":"llm_security_decision","value":"security_decision_from_llm without hitl_approved"}] if direct and not hitl else []),reason="LLM output directly drives a security-sensitive decision without required deterministic/HITL gating." if direct and not hitl else "No unvalidated LLM-driven security decision proven.")

    def _p_risky_operation_hitl(self,payload,context,filename):
        text=self._collect_text(payload)
        risky=bool(re.search(r"(?i)\b(?:rm|eval|exec|source|export|dd|mkfs|shred|mkswap|chmod|wget|mv)\b|\b(?:remove|delete|destroy|purge)\w*\s*\(",text))
        approved=bool(self._ctx(payload,context,'hitl_approved',False) or re.search(r"(?i)hitl_approved\s*(?:==|is)\s*True",text))
        return self._decision(risky and not approved,findings=self._simple_findings(text,"risky_operation_without_hitl",r"(?i).{0,60}\b(?:rm|eval|exec|source|export|dd|mkfs|shred|mkswap|chmod|wget|mv|remove\w*\s*\(|delete\w*\s*\(|destroy\w*\s*\(|purge\w*\s*\().{0,80}") if risky and not approved else [],reason="Risky/destructive operation lacks HITL approval gate." if risky and not approved else "No risky operation without HITL approval proven.")

    def _p_prompt_injection(self,payload,context,filename):
        fixed,findings=self._map_strings(payload,self._prompt_injection_transform)
        return self._decision(bool(findings),payload=fixed,findings=findings,reason="Prompt-injection payloads neutralized." if findings else "No supported prompt-injection technique detected.")

    def _p_cbrn(self,payload,context,filename):
        text=self._collect_text(payload)
        hazard=re.compile(r"(?i)\b(?:chemical weapon|nerve agent|sarin|vx\b|biological weapon|pathogen weapon|weaponiz(?:e|ation)|radiological dispersal|dirty bomb|uranium enrichment|plutonium separation|nuclear weapon|cb rn|cbrn)\b")
        enable=re.compile(r"(?i)\b(?:synthesize|manufacture|build|produce|deploy|release|optimize|increase yield|procure|evade detection|weaponize)\b")
        match=bool(hazard.search(text) and enable.search(text))
        return self._decision(match,findings=self._simple_findings(text,"cbrn_enablement",r"(?i).{0,120}(?:chemical weapon|nerve agent|sarin|biological weapon|weaponiz\w*|dirty bomb|uranium enrichment|plutonium|nuclear weapon|cbrn).{0,160}") if match else [],reason="CBRN threat-enablement content detected." if match else "No CBRN threat-enablement content detected.")

    def _p_explainability(self,payload,context,filename):
        text=self._collect_text(payload); scope=bool(self._CONSEQUENTIAL.search(text) or self._ctx(payload,context,'consequential_decision',False))
        has=bool(re.search(r"(?i)decision_factors|explainability|explanation|feature_attribution|principal factors|reason codes?",text) or self._ctx(payload,context,'decision_factors',None))
        return self._decision(scope and not has,findings=[{"path":"$","type":"missing_explainability","value":"consequential decision without decision factors"}] if scope and not has else [],reason="Consequential decision path lacks explainability/decision-factor disclosure." if scope and not has else "No missing explainability control proven.")

    def _p_consequential_human_review(self,payload,context,filename):
        text=self._collect_text(payload); scope=bool(self._CONSEQUENTIAL.search(text) or self._ctx(payload,context,'consequential_decision',False))
        human=bool(self._ctx(payload,context,'human_review_required',False) or self._ctx(payload,context,'hitl_approved',False) or re.search(r"(?i)human_review|reviewer|manual_review|hitl",text))
        return self._decision(scope and not human,findings=[{"path":"$","type":"missing_human_review","value":"consequential decision"}] if scope and not human else [],reason="Consequential decision lacks a human review pathway." if scope and not human else "Human review requirement not violated.")

    def _p_emergency_shutdown(self,payload,context,filename):
        text=self._collect_text(payload); scope=bool(re.search(r"(?i)agent|ai system|model service|inference",text))
        has=bool(re.search(r"(?i)emergency_shutdown|kill_switch|force_terminate|shutdown_event|cancel_all|terminate\s*\(",text))
        return self._decision(scope and not has,findings=[{"path":"$","type":"missing_emergency_shutdown","value":"AI runtime without visible shutdown mechanism"}] if scope and not has else [],reason="AI runtime lacks an evident emergency shutdown/forced-termination mechanism." if scope and not has else "No missing emergency shutdown control proven.")

    def _p_facial_recognition_employment(self,payload,context,filename):
        text=self._collect_text(payload); facial=bool(re.search(r"(?i)face_recognition|facial recognition|rekognition|faceapi|face\.compare|detect_faces",text) or self._ctx(payload,context,'uses_facial_recognition',False)); employment=bool(re.search(r"(?i)employment|hiring|candidate|applicant|interview|employee selection",text) or str(self._ctx(payload,context,'covered_domain','')).lower()=='employment')
        return self._decision(facial and employment,findings=[{"path":"$","type":"facial_recognition_employment","value":"facial recognition in employment workflow"}] if facial and employment else [],reason="Facial recognition detected in an employment decision workflow." if facial and employment else "No employment facial-recognition use proven.")

    def _p_high_risk_disclosure(self,payload,context,filename):
        text=self._collect_text(payload); high=bool(str(self._ctx(payload,context,'risk_level','')).lower()=='high' or self._CONSEQUENTIAL.search(text)); required=('decision_factors','limitations','accuracy','appeal')
        missing=[x for x in required if x not in text.lower().replace(' ','_') and x not in text.lower()]
        return self._decision(high and bool(missing),findings=[{"path":"$","type":"missing_high_risk_disclosure","value":x} for x in missing] if high else [],reason="High-risk AI output lacks required enhanced disclosure elements." if high and missing else "No missing high-risk disclosure proven.")

    def _p_admt_notice(self,payload,context,filename):
        text=self._collect_text(payload); scope=bool(self._CONSEQUENTIAL.search(text) or self._ctx(payload,context,'consequential_decision',False)); has=bool(re.search(r"(?i)notify_admt_use|admt.*disclos|automated decision.*notice|consumer.*notice",text) or self._ctx(payload,context,'admt_notice_delivered',False))
        return self._decision(scope and not has,findings=[{"path":"$","type":"missing_admt_notice","value":"consequential ADMT decision"}] if scope and not has else [],reason="Consequential automated decision path lacks pre-interaction consumer notice." if scope and not has else "No missing ADMT notice proven.")

    def _p_meaningful_human_review(self,payload,context,filename):
        text=self._collect_text(payload); scope=bool(re.search(r"(?i)human_review|reviewer|manual_review|hitl",text) or self._ctx(payload,context,'human_review_workflow',False))
        if not scope: return self._decision(False,reason="No human-review workflow detected.")
        override=bool(self._ctx(payload,context,'reviewer_can_override',False) or re.search(r"(?i)override|modify_decision|reject_decision",text))
        context_fields=all(x in text.lower() for x in ('intended_use','limitations','input_categories','decision_factors')) or bool(self._ctx(payload,context,'review_context_complete',False))
        auto=bool(re.search(r"(?i)auto[_ -]?approve|default[_ -]?(?:approve|accept)|timeout[^\n]{0,80}(?:approve|accept)",text) or self._ctx(payload,context,'auto_approve_on_timeout',False))
        violations=[]
        if not override: violations.append('reviewer_override_authority')
        if not context_fields: violations.append('required_review_context')
        if auto: violations.append('auto_approve_default')
        return self._decision(bool(violations),findings=[{"path":"$","type":"meaningful_human_review","value":v} for v in violations],reason="Human review workflow lacks mandatory meaningful-review controls." if violations else "Meaningful human-review controls present.")

    def _p_rate_limiting(self,payload,context,filename):
        text=self._collect_text(payload); scope=bool(self._LLM_CALL.search(text)); has=bool(re.search(r"(?i)rate.?limit|aiolimiter|token.?bucket|429|backoff|max_retries|max_tokens|requests_per_minute|slowapi|flask.?limiter",text))
        return self._decision(scope and not has,findings=self._simple_findings(text,"missing_rate_limiting",self._LLM_CALL.pattern) if scope and not has else [],reason="AI API call site lacks visible rate limiting/throttling/backoff controls." if scope and not has else "No missing AI rate-limit control proven.")

    # ------------------------------------------------------------------
    # Native policy handlers: DATA
    # ------------------------------------------------------------------

    def _p_secrets(self,payload,context,filename):
        fixed,findings=self._map_strings(payload,self._secret_transform)
        return self._decision(bool(findings),payload=fixed,findings=findings,reason="Hard-coded secrets replaced with environment/secret-manager references." if findings else "No high-confidence hard-coded secret found.")

    def _p_pii_redact(self,payload,context,filename):
        fixed,findings=self._map_strings(payload,lambda p,t:self._pii_transform(p,t,mask=False,replacement="REDACTED"))
        return self._decision(bool(findings),payload=fixed,findings=findings,reason="Zero-tolerance PII redacted." if findings else "No supported zero-tolerance PII found.")

    def _p_pii_mask(self,payload,context,filename):
        fixed,findings=self._map_strings(payload,lambda p,t:self._pii_transform(p,t,mask=True))
        return self._decision(bool(findings),payload=fixed,findings=findings,reason="Zero-tolerance PII masked." if findings else "No supported zero-tolerance PII found.")

    def _p_singapore_pii_redact(self,payload,context,filename):
        fixed,findings=self._map_strings(payload,lambda p,t:self._pii_transform(p,t,mask=False,singapore=True,replacement="REDACTED"))
        return self._decision(bool(findings),payload=fixed,findings=findings,reason="Singapore zero-tolerance PII redacted." if findings else "No supported Singapore PII found.")

    def _p_data_minimization(self,payload,context,filename):
        working=self._clone(payload); findings=[]
        allowed=context.get('allowed_output_fields')
        if isinstance(working,dict) and allowed is not None:
            allowed_set={str(x) for x in allowed}
            for key in list(working.keys()):
                if str(key) not in allowed_set:
                    findings.append({"path":f"$.{key}","type":"excess_output_field","value":self._safe_preview(working[key]),"replacement":"REDACTED"})
                    working[key]="REDACTED"
        # Strip PII and secrets/internal diagnostics from text leaves.
        working,pii=self._map_strings(working,lambda p,t:self._pii_transform(p,t,mask=False,replacement="REDACTED")); findings.extend(pii)
        def minimize(path,text):
            local=[]
            patterns=[
                (re.compile(r"(?im)^\s*(?:Traceback \(most recent call last\):|File \"[^\"]+\", line \d+.*)$"),"<internal_diagnostic_removed>","stack_trace"),
                (re.compile(r"(?i)\b(?:/home/[^\s]+|/var/[^\s]+|[A-Z]:\\\\Users\\\\[^\s]+)"),"<internal_path_removed>","internal_path"),
            ]
            for pat,repl,kind in patterns:
                text,f=self._replace_regex(text,path,pat,repl,kind); local.extend(f)
            return text,local
        working,extra=self._map_strings(working,minimize); findings.extend(extra)
        return self._decision(bool(findings),payload=working,findings=findings,reason="Output minimized to allowed fields and sensitive/internal data removed." if findings else "No data-minimization violation found.")

    def _p_decision_audit(self,payload,context,filename):
        text=self._collect_text(payload); scope=bool(re.search(r"(?i)\b(?:approve|deny|rank|route|moderate|tool invocation|decision)\b",text) and self._LLM_CALL.search(text)); required=('audit','correlation','model_version')
        missing=[x for x in required if x not in text.lower()]
        return self._decision(scope and bool(missing),findings=[{"path":"$","type":"missing_decision_audit_control","value":x} for x in missing] if scope else [],reason="AI-driven decision path lacks required forensic audit context." if scope and missing else "No missing decision-audit control proven.")

    def _p_retention_180(self,payload,context,filename):
        text=self._collect_text(payload); high=str(self._ctx(payload,context,'risk_level','')).lower()=='high' or bool(re.search(r"(?i)high.?risk",text)); days=self._extract_retention_days(text,context)
        match=bool(high and (days is None or days<180))
        return self._decision(match,findings=[{"path":"$","type":"log_retention_days","value":days}] if match else [],reason="High-risk AI log retention is missing or below 180 days." if match else "No <180-day high-risk log retention violation proven.")

    def _p_training_data_disclosure(self,payload,context,filename):
        text=self._collect_text(payload); scope=bool(re.search(r"(?i)load_dataset|pd\.read_csv|DataLoader|tf\.data|training_data|data_source",text)); required=('category','type','timeframe','geograph')
        missing=[x for x in required if x not in text.lower()]
        return self._decision(scope and bool(missing),findings=[{"path":"$","type":"missing_training_data_disclosure","value":x} for x in missing] if scope else [],reason="Training-data source metadata is incomplete." if scope and missing else "No incomplete training-data disclosure proven.")

    def _p_data_acquisition_disclosure(self,payload,context,filename):
        text=self._collect_text(payload); scope=bool(re.search(r"(?i)requests\.get|urllib|download_file|load_dataset|preprocess|dataset",text)); required=('license','permission','preprocess')
        missing=[x for x in required if x not in text.lower()]
        return self._decision(scope and bool(missing),findings=[{"path":"$","type":"missing_data_acquisition_disclosure","value":x} for x in missing] if scope else [],reason="Data acquisition path lacks licensing/permission/preprocessing disclosure." if scope and missing else "No incomplete data acquisition disclosure proven.")

    def _p_patient_acknowledgement(self,payload,context,filename):
        clinical=bool(self._ctx(payload,context,'clinical_ai',False) or self._HEALTHCARE.search(self._collect_text(payload)))
        ack=bool(self._ctx(payload,context,'patient_acknowledged_ai',False) or re.search(r"(?i)patient.*acknowledg|consent.*ai-assisted",self._collect_text(payload)))
        return self._decision(clinical and not ack,findings=[{"path":"$","type":"missing_patient_acknowledgement","value":"clinical AI"}] if clinical and not ack else [],reason="Clinical AI use lacks documented patient acknowledgment." if clinical and not ack else "Patient acknowledgment policy not violated.")

    def _p_biometric_consent(self,payload,context,filename):
        text=self._collect_text(payload); biometric=bool(self._BIOMETRIC.search(text) or self._ctx(payload,context,'collects_biometrics',False)); consent=bool(self._ctx(payload,context,'biometric_consent',False) or re.search(r"(?i)explicit.*consent|consent.*biometric",text))
        return self._decision(biometric and not consent,findings=[{"path":"$","type":"biometric_without_consent","value":"biometric collection"}] if biometric and not consent else [],reason="Biometric collection lacks explicit documented consent." if biometric and not consent else "Biometric consent policy not violated.")

    def _p_biometric_retention(self,payload,context,filename):
        text=self._collect_text(payload); scope=bool(self._BIOMETRIC.search(text) and re.search(r"(?i)store|database|persist|save|bucket",text)); has=bool(re.search(r"(?i)retention|ttl|expires|delete_after|purge_after",text) or self._ctx(payload,context,'biometric_retention_days',None) is not None)
        return self._decision(scope and not has,findings=[{"path":"$","type":"missing_biometric_retention","value":"biometric store"}] if scope and not has else [],reason="Biometric data store lacks retention/deletion scheduling." if scope and not has else "No missing biometric retention control proven.")

    def _p_decision_retention_3y(self,payload,context,filename):
        text=self._collect_text(payload); scope=bool(self._CONSEQUENTIAL.search(text) or self._ctx(payload,context,'consequential_decision',False)); days=self._extract_retention_days(text,context,key='decision_retention_days'); match=bool(scope and (days is None or days<1095))
        return self._decision(match,findings=[{"path":"$","type":"decision_retention_days","value":days}] if match else [],reason="Consequential AI decision retention is missing or below three years." if match else "No <3-year consequential decision retention violation proven.")

    def _p_encryption_tls(self,payload,context,filename):
        text=self._collect_text(payload); findings=[]
        for m in re.finditer(r"(?i)http://[^\s'\"]+|ssl\s*=\s*False|verify\s*=\s*False|tls\s*=\s*False",text): findings.append(self._finding("$",m,"unencrypted_transport",m.group(0)))
        if self._ctx(payload,context,'encryption_at_rest',True) is False: findings.append({"path":"$","type":"encryption_at_rest","value":False})
        return self._decision(bool(findings),findings=findings,reason="Unencrypted transport or storage configuration detected." if findings else "No explicit encryption/TLS violation found.")

    # ------------------------------------------------------------------
    # Native policy handlers: IAC / identity & access
    # ------------------------------------------------------------------

    def _p_mcp_client_auth(self,payload,context,filename):
        text=self._collect_text(payload); scope=bool(self._MCP_MARKER.search(text) and re.search(r"(?i)client|connect",text)); auth=bool(self._AUTH_MARKER.search(text) or self._ctx(payload,context,'mcp_server_authenticated',False))
        return self._decision(scope and not auth,findings=[{"path":"$","type":"missing_mcp_server_authentication","value":"MCP client connection"}] if scope and not auth else [],reason="MCP client does not visibly authenticate the server." if scope and not auth else "No missing MCP server authentication proven.")

    def _p_mcp_server_auth(self,payload,context,filename):
        text=self._collect_text(payload); scope=bool(self._MCP_MARKER.search(text) and re.search(r"(?i)server|handler|route",text)); auth=bool(self._AUTH_MARKER.search(text) or self._ctx(payload,context,'mcp_client_authenticated',False))
        return self._decision(scope and not auth,findings=[{"path":"$","type":"missing_mcp_client_authentication","value":"MCP server"}] if scope and not auth else [],reason="MCP server lacks evident client authentication." if scope and not auth else "No missing MCP client authentication proven.")

    def _p_interagent_auth(self,payload,context,filename):
        text=self._collect_text(payload); scope=bool(re.search(r"(?i)agent.?to.?agent|a2a|send_to_agent|peer_agent|agent_message",text)); auth=bool(self._AUTH_MARKER.search(text) or re.search(r"(?i)signature|hmac|mTLS",text) or self._ctx(payload,context,'interagent_authenticated',False))
        return self._decision(scope and not auth,findings=[{"path":"$","type":"unauthenticated_interagent_communication","value":"A2A communication"}] if scope and not auth else [],reason="Inter-agent communication lacks authentication/integrity evidence." if scope and not auth else "No unauthenticated inter-agent communication proven.")

    def _p_excessive_credentials(self,payload,context,filename):
        count=self._ctx(payload,context,'external_credentials_count',None)
        text=self._collect_text(payload)
        if count is None:
            creds=set(m.group(1).upper() for m in re.finditer(r"(?i)\b([A-Z0-9_]*(?:API_KEY|TOKEN|PASSWORD|SECRET|CREDENTIAL)[A-Z0-9_]*)\b",text))
            count=len(creds) if creds else None
        match=isinstance(count,(int,float)) and count>3
        return self._decision(bool(match),findings=[{"path":"$","type":"excessive_external_credentials","value":count}] if match else [],reason="Agent accesses more than three external-system credentials." if match else "No >3 external credential violation proven.")

    def _p_llm_endpoint_auth(self,payload,context,filename):
        text=self._collect_text(payload); scope=bool(re.search(r"(?i)@(app|router)\.(?:get|post)|route\s*\(",text) and self._LLM_CALL.search(text)); auth=bool(self._AUTH_MARKER.search(text) or self._ctx(payload,context,'authenticated',False))
        return self._decision(scope and not auth,findings=[{"path":"$","type":"unauthenticated_llm_endpoint","value":"AI endpoint"}] if scope and not auth else [],reason="LLM endpoint lacks evident authentication." if scope and not auth else "No unauthenticated LLM endpoint proven.")

    def _p_agent_user_auth(self,payload,context,filename):
        text=self._collect_text(payload); scope=bool(re.search(r"(?i)agent",text) and re.search(r"(?i)@(app|router)\.(?:get|post)|endpoint|request",text)); auth=bool(self._AUTH_MARKER.search(text) or self._ctx(payload,context,'authenticated',False))
        return self._decision(scope and not auth,findings=[{"path":"$","type":"unauthenticated_agent_access","value":"AI agent endpoint"}] if scope and not auth else [],reason="AI Agent access path lacks user authentication." if scope and not auth else "No unauthenticated agent access proven.")

    def _p_url_allowlist(self,payload,context,filename):
        text=self._collect_text(payload); urls=re.findall(r"https?://[^\s'\"<>]+",text)
        for v in self._extract_values(payload,['url','uri','endpoint','target_url']):
            if isinstance(v,str) and re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://",v): urls.append(v)
        allowed_hosts={str(x).casefold() for x in context.get('approved_url_hosts',context.get('url_allowlist',[]))}
        allowed_schemes={str(x).lower() for x in context.get('approved_url_schemes',['https'])}
        allowed_prefixes=[str(x) for x in context.get('approved_url_prefixes',[])]
        findings=[]
        for url in dict.fromkeys(urls):
            try: p=urllib.parse.urlsplit(url); host=(p.hostname or '').casefold(); scheme=p.scheme.lower()
            except Exception:
                findings.append({"path":"$","type":"invalid_url","value":url}); continue
            reason=None
            if scheme not in allowed_schemes: reason='scheme_not_allowed'
            elif self._is_private_host(host): reason='private_or_metadata_address'
            elif not allowed_hosts: reason='no_explicit_allowlist'
            elif host not in allowed_hosts and not any(host.endswith('.'+h) for h in allowed_hosts): reason='host_not_allowed'
            elif allowed_prefixes and not any(url.startswith(prefix) for prefix in allowed_prefixes): reason='path_prefix_not_allowed'
            if reason: findings.append({"path":"$","type":"url_allowlist_violation","value":url,"reason":reason})
        return self._decision(bool(findings),findings=findings,reason="Outbound URL failed allowlist/scheme/SSRF checks." if findings else "All discovered URLs satisfy configured allowlist checks or no URL was present.")

    @staticmethod
    def _is_private_host(host: str) -> bool:
        if host in {'localhost','metadata.google.internal','169.254.169.254'}: return True
        try:
            ip=ipaddress.ip_address(host); return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
        except ValueError: return False

    def _p_privilege_escalation(self,payload,context,filename):
        text=self._collect_text(payload); requested=self._ctx(payload,context,'requested_capability',None); approved={str(x) for x in context.get('approved_capabilities',[])}
        findings=[]
        if requested is not None and (not approved or str(requested) not in approved): findings.append({"path":"$","type":"capability_outside_envelope","value":requested})
        for m in re.finditer(r"(?i)\b(?:sudo|run as admin|become admin|grant .*admin|role\s*=\s*['\"]?admin|chmod\s+777|setuid|privilege escalation)\b",text): findings.append(self._finding("$",m,"privilege_escalation",m.group(0)))
        return self._decision(bool(findings),findings=findings,reason="Requested operation widens the approved privilege/capability envelope." if findings else "No privilege escalation attempt proven.")

    def _p_session_token_integrity(self,payload,context,filename):
        token_present=bool(self._extract_values(payload,['session_token','token','jwt']))
        verified=self._ctx(payload,context,'token_verified',None); expired=self._ctx(payload,context,'token_expired',None); bound=self._ctx(payload,context,'token_bound',None)
        text=self._collect_text(payload); findings=[]
        if token_present and verified is not True: findings.append({"path":"$","type":"token_signature_not_verified","value":verified})
        if token_present and expired is True: findings.append({"path":"$","type":"expired_token","value":True})
        if token_present and bound is False: findings.append({"path":"$","type":"unbound_session_token","value":False})
        for m in re.finditer(r"(?i)(?:verify_signature\s*=\s*False|verify\s*=\s*False|https?://[^\s]+[?&](?:token|session|jwt)=|(?:log|print)\s*\([^\n]*(?:session_token|jwt|bearer))",text): findings.append(self._finding("$",m,"insecure_session_token_handling",m.group(0)))
        return self._decision(bool(findings),findings=findings,reason="Session token integrity/expiry/binding controls failed." if findings else "No concrete session-token integrity violation found.")

    def _p_user_agent_binding(self,payload,context,filename):
        privileged=bool(self._ctx(payload,context,'privileged_action',False)); binding=self._ctx(payload,context,'user_agent_binding_verified',None); text=self._collect_text(payload); findings=[]
        if privileged and binding is not True: findings.append({"path":"$","type":"missing_user_agent_binding","value":binding})
        for m in re.finditer(r"(?i)(?:agent_(?:user|subject|tenant)\s*=\s*request\.(?:json|args|form)|bound_(?:user|subject)\s*=\s*(?:payload|input|llm_response))",text): findings.append(self._finding("$",m,"client_or_model_driven_binding",m.group(0)))
        return self._decision(bool(findings),findings=findings,reason="User-to-agent identity binding is missing or driven by untrusted data." if findings else "No user-agent binding violation proven.")

    def _p_tool_allowlist(self,payload,context,filename):
        tools=[]
        for v in self._extract_values(payload,['tool','tool_name','tool_id','requested_tool']):
            if isinstance(v,str): tools.append(v)
        approved={str(x) for x in context.get('approved_tools',context.get('tool_allowlist',[]))}
        denied=[t for t in tools if not approved or t not in approved]
        return self._decision(bool(denied),findings=[{"path":"$","type":"tool_not_allowlisted","value":t} for t in denied],reason="Tool request is outside the explicit allow list." if denied else "No non-allowlisted tool request found.")

    def _p_subagent_bounds(self,payload,context,filename):
        text=self._collect_text(payload); spawn=re.compile(r"(?i)(?:spawn_subagent|create_subagent|subagent\s*\(|delegate\s*\(|spawn\s*\([^\n]*agent)"); scope=bool(spawn.search(text))
        missing=[]
        if scope:
            if not re.search(r"(?i)timeout\s*=",text): missing.append('timeout')
            if not re.search(r"(?i)max_steps\s*=|max_iterations\s*=",text): missing.append('max_steps')
            if not re.search(r"(?i)correlation_id|trace_id|chain_of_custody",text): missing.append('correlation_id')
            if not self._LOG_MARKER.search(text): missing.append('spawn_logging')
        return self._decision(scope and bool(missing),findings=[{"path":"$","type":"missing_subagent_bound","value":x} for x in missing],reason="Subagent spawn lacks required resource/traceability controls." if scope and missing else "No unbounded/untraceable subagent spawn proven.")

    def _p_ai_identity_disclosure(self,payload,context,filename):
        text=self._collect_text(payload); scope=bool(re.search(r"(?i)chatbot|chat interface|assistant|conversation",text)); has=bool(re.search(r"(?i)(?:i am|this is|you are interacting with).{0,40}(?:ai|artificial intelligence|automated assistant)|ai-powered",text) or self._ctx(payload,context,'ai_identity_disclosed',False))
        return self._decision(scope and not has,findings=[{"path":"$","type":"missing_ai_identity_disclosure","value":"chat interface"}] if scope and not has else [],reason="Chatbot/AI interface lacks AI identity disclosure." if scope and not has else "No missing AI identity disclosure proven.")

    def _p_model_card(self,payload,context,filename):
        text=self._collect_text(payload); scope=bool(self._LLM_CALL.search(text) or re.search(r"(?i)model_name|model_id|from_pretrained",text)); has=bool(re.search(r"(?i)MODEL_CARD_URL|model_card|technical_documentation",text) or self._ctx(payload,context,'model_card_url',None))
        return self._decision(scope and not has,findings=[{"path":"$","type":"missing_model_card","value":"GPAI integration"}] if scope and not has else [],reason="GPAI integration lacks model-card/technical-documentation reference." if scope and not has else "No missing model-card reference proven.")

    def _p_healthcare_disclosure(self,payload,context,filename):
        text=self._collect_text(payload); scope=bool(self._HEALTHCARE.search(text) and (self._LLM_CALL.search(text) or self._ctx(payload,context,'clinical_ai',False))); has=bool(re.search(r"(?i)patient.*disclos|ai-assisted|artificial intelligence.*(?:diagnos|treatment|imaging)",text) or self._ctx(payload,context,'patient_ai_disclosure',False))
        return self._decision(scope and not has,findings=[{"path":"$","type":"missing_patient_ai_disclosure","value":"clinical AI invocation"}] if scope and not has else [],reason="Clinical AI invocation lacks pre-use patient disclosure." if scope and not has else "No missing healthcare AI disclosure proven.")

    def _p_clinician_authority(self,payload,context,filename):
        text=self._collect_text(payload); scope=bool(self._HEALTHCARE.search(text) and (re.search(r"(?i)recommend|diagnos|treatment|clinical",text))); has=bool(re.search(r"(?i)(?:clinician|doctor|physician).{0,80}(?:final decision|final authority|retains authority|must review)",text) or self._ctx(payload,context,'clinician_final_authority_disclosed',False))
        return self._decision(scope and not has,findings=[{"path":"$","type":"missing_clinician_authority_disclosure","value":"clinical recommendation"}] if scope and not has else [],reason="Clinical AI output lacks disclosure that human clinicians retain final authority." if scope and not has else "No missing clinician-authority disclosure proven.")

    def _p_human_only_review(self,payload,context,filename):
        text=self._collect_text(payload); scope=bool(self._HEALTHCARE.search(text) and re.search(r"(?i)patient|response|message|recommend",text)); has=bool(re.search(r"(?i)human-only review|request (?:a )?human|contact (?:a )?(?:clinician|provider|doctor)|opt.?out",text) or self._ctx(payload,context,'human_only_review_instructions',False))
        return self._decision(scope and not has,findings=[{"path":"$","type":"missing_human_review_optout","value":"patient-facing clinical AI"}] if scope and not has else [],reason="Patient-facing clinical AI lacks instructions for human-only review." if scope and not has else "No missing human-review opt-out proven.")

    def _p_risk_classification(self,payload,context,filename):
        text=self._collect_text(payload); scope=bool(re.search(r"(?i)deployment|service|model|agent",text) and re.search(r"(?i)config|yaml|toml|environment|startup",text)); risk=self._ctx(payload,context,'risk_level',None); has=risk in ('low','medium','high') or bool(re.search(r"(?i)risk_level\s*[:=]\s*['\"]?(?:low|medium|high)",text))
        return self._decision(scope and not has,findings=[{"path":"$","type":"missing_risk_level","value":"default should be high"}] if scope and not has else [],reason="AI deployment lacks valid risk_level declaration." if scope and not has else "No missing/invalid risk classification proven.")

    def _p_model_versioning(self,payload,context,filename):
        text=self._collect_text(payload); scope=bool(re.search(r"(?i)model|inference|deployment",text)); required=[('model_version',r"(?i)model_version|model.*version"),('changelog',r"(?i)CHANGELOG\.md|change.?log"),('model_card',r"(?i)MODEL_CARD\.md|model_card\.json|model card")]
        missing=[name for name,pat in required if not re.search(pat,text) and not self._ctx(payload,context,name,None)]
        return self._decision(scope and bool(missing),findings=[{"path":"$","type":"missing_model_versioning_control","value":x} for x in missing] if scope else [],reason="Model deployment lacks version/change-log/release documentation controls." if scope and missing else "No missing model versioning documentation proven.")

    def _p_covered_domain(self,payload,context,filename):
        text=self._collect_text(payload); scope=bool(re.search(r"(?i)deployment|service|model|agent",text) and re.search(r"(?i)config|yaml|toml|environment|startup",text)); allowed={'education','employment','real_estate','financial_services','insurance','healthcare','government_benefits','not_applicable'}; value=str(self._ctx(payload,context,'covered_domain','')).lower(); has=value in allowed or bool(re.search(r"(?i)covered_domain\s*[:=]\s*['\"]?(?:education|employment|real_estate|financial_services|insurance|healthcare|government_benefits|not_applicable)",text))
        return self._decision(scope and not has,findings=[{"path":"$","type":"missing_covered_domain","value":"deployment classification"}] if scope and not has else [],reason="AI deployment lacks valid covered_domain declaration." if scope and not has else "No missing/invalid covered-domain classification proven.")

    def _p_rbac_scopes(self,payload,context,filename):
        text=self._collect_text(payload); findings=[]
        for m in re.finditer(r"(?i)(?:scope|scopes)\s*[:=]\s*(?:['\"]\*['\"]|['\"]all['\"]|\[[^\]]*['\"]\*['\"])",text): findings.append(self._finding("$",m,"overbroad_oauth_scope",m.group(0)))
        if self._ctx(payload,context,'rbac_valid',True) is False: findings.append({"path":"$","type":"rbac_validation_failed","value":False})
        req=self._ctx(payload,context,'requested_scope',None); allowed={str(x) for x in context.get('allowed_oauth_scopes',[])}
        if req is not None and (not allowed or str(req) not in allowed): findings.append({"path":"$","type":"scope_not_allowed","value":req})
        return self._decision(bool(findings),findings=findings,reason="AI endpoint RBAC/OAuth scope policy failed." if findings else "No RBAC/minimal-scope violation proven.")

    # ------------------------------------------------------------------
    # Native policy handlers: skills / vulnerabilities
    # ------------------------------------------------------------------

    def _skill_state(self,payload,context) -> str:
        value=self._ctx(payload,context,'skill_reputation',self._ctx(payload,context,'skill_status',''))
        return str(value).strip().lower()

    def _p_skill_exfiltration(self,payload,context,filename):
        state=self._skill_state(payload,context); text=self._collect_text(payload)
        exfil=state in {'exfiltration','data_exfiltration','exfiltrates_data'} or bool(re.search(r"(?i)(?:curl|requests\.post|fetch\().{0,160}(?:secret|token|credential|env|private data)|webhook\.site",text))
        return self._decision(exfil,findings=[{"path":"$","type":"skill_data_exfiltration","value":state or 'content pattern'}] if exfil else [],reason="Skill exfiltrates data and must be blocked." if exfil else "No skill data-exfiltration finding proven.")

    def _p_skill_malicious(self,payload,context,filename):
        state=self._skill_state(payload,context); match=state in {'malicious','malware','blocked_malicious'}
        return self._decision(match,findings=[{"path":"$","type":"malicious_skill","value":state}] if match else [],reason="Skill reputation is malicious." if match else "Skill is not explicitly classified malicious.")

    def _p_skill_suspicious(self,payload,context,filename):
        state=self._skill_state(payload,context); match=state in {'suspicious','risky'}
        return self._decision(match,findings=[{"path":"$","type":"suspicious_skill","value":state}] if match else [],reason="Skill reputation is suspicious." if match else "Skill is not explicitly classified suspicious.")

    def _p_skill_pending(self,payload,context,filename):
        state=self._skill_state(payload,context); match=state in {'pending','pending_scan','unknown','unscanned'}
        return self._decision(match,findings=[{"path":"$","type":"unscanned_skill","value":state}] if match else [],reason="Skill reputation is pending/unknown and must be blocked until scanned." if match else "Skill is not explicitly pending or unknown.")

    def _p_common_vulnerabilities(self,payload,context,filename):
        text=self._collect_text(payload); patterns={
            'dynamic_exec':r"(?i)\b(?:eval|exec)\s*\([^\n]*(?:input|request|user|query)",
            'shell_injection':r"(?i)subprocess\.(?:run|Popen|call)\s*\([^\n]*shell\s*=\s*True",
            'sql_injection':r"(?i)(?:SELECT|UPDATE|DELETE|INSERT)[^\n]*(?:\+\s*(?:user|input|request)|f['\"]|\.format\s*\()",
            'ssrf':r"(?i)requests\.(?:get|post)\s*\(\s*(?:url|user_url|request\.)",
            'path_traversal':r"(?i)open\s*\([^\n]*(?:request|user|filename|path)[^\n]*\)",
            'insecure_deserialization':r"(?i)(?:pickle\.loads|yaml\.load)\s*\([^\n]*(?:request|user|input|data)",
            'weak_crypto':r"(?i)hashlib\.(?:md5|sha1)\s*\(",
        }; findings=[]
        for kind,pat in patterns.items(): findings+=self._simple_findings(text,kind,pat)
        return self._decision(bool(findings),findings=findings,reason="High-confidence OWASP/common vulnerability pattern detected." if findings else "No high-confidence common vulnerability pattern detected.")

    def _p_model_registry(self,payload,context,filename):
        models=self._extract_model_names(payload); text=self._collect_text(payload); findings=[]
        source=self._ctx(payload,context,'model_source',None); version=self._ctx(payload,context,'model_version',None); digest=self._ctx(payload,context,'model_digest',self._ctx(payload,context,'model_hash',None)); sig=self._ctx(payload,context,'model_signature_verified',None)
        regs={str(x).casefold() for x in context.get('approved_model_registries',[])}
        if source is not None and (not regs or str(source).casefold() not in regs): findings.append({"path":"$","type":"unapproved_model_registry","value":source})
        if models and (version in (None,'','latest','stable') and re.search(r"(?i)(?:latest|stable|from_pretrained\s*\([^\n]*(?:user|request|input))",text)): findings.append({"path":"$","type":"unpinned_model_version","value":version})
        if models and digest in (None,'') and self._ctx(payload,context,'require_model_digest',False): findings.append({"path":"$","type":"missing_model_digest","value":None})
        if sig is False: findings.append({"path":"$","type":"model_signature_verification_failed","value":False})
        return self._decision(bool(findings),findings=findings,reason="Model identity/registry/version verification policy failed." if findings else "No model registry/version/signature violation proven.")

    def _p_memory_safety(self,payload,context,filename):
        text=self._collect_text(payload); patterns={
            'unbounded_c_api':r"\b(?:strcpy|strcat|gets|sprintf)\s*\(",
            'raw_memcpy':r"\b(?:memcpy|memmove|std::copy)\s*\(",
            'rust_transmute':r"\b(?:std::mem::transmute|mem::transmute)\s*\(",
            'raw_pointer_deref':r"(?m)^\s*unsafe\s*\{[^}]*\*\w+",
        }; findings=[]
        for kind,pat in patterns.items(): findings+=self._simple_findings(text,kind,pat)
        return self._decision(bool(findings),findings=findings,reason="Native memory-safety risk pattern detected; bounded/RAII/safe abstraction remediation is required." if findings else "No high-confidence native memory-safety violation found.")

    def _p_incident_observability(self,payload,context,filename):
        text=self._collect_text(payload); scope=bool(self._LLM_CALL.search(text) or re.search(r"(?i)agent|inference|decision pipeline",text)); required=('json','correlation','latency','incident','alert','retention'); missing=[x for x in required if x not in text.lower()]
        return self._decision(scope and len(missing)>=3,findings=[{"path":"$","type":"missing_incident_observability_control","value":x} for x in missing] if scope and len(missing)>=3 else [],reason="AI runtime lacks required structured logging/anomaly/incident-reporting controls." if scope and len(missing)>=3 else "No concrete incident-observability violation proven.")

    # ------------------------------------------------------------------
    # Generic analysis helpers
    # ------------------------------------------------------------------

    def _extract_model_names(self,payload: Any) -> list[str]:
        values=[]
        for v in self._extract_values(payload,['model','model_name','model_id','llm','foundation_model']):
            if isinstance(v,str): values.append(v)
        text=self._collect_text(payload)
        for m in re.finditer(r"(?i)\bmodel\s*[:=]\s*['\"]([^'\"]+)['\"]",text): values.append(m.group(1))
        return list(dict.fromkeys(values))

    @staticmethod
    def _simple_findings(text: str, kind: str, pattern: str, limit: int = 50) -> list[dict[str,Any]]:
        findings=[]
        try: rx=re.compile(pattern,re.S)
        except re.error: rx=re.compile(re.escape(pattern))
        for m in rx.finditer(text):
            findings.append({"path":"$","type":kind,"value":m.group(0)[:1000],"start":m.start(),"end":m.end()})
            if len(findings)>=limit: break
        return findings

    def _extract_retention_days(self,text: str,context: Mapping[str,Any],key: str='log_retention_days') -> Optional[int]:
        val=context.get(key)
        if isinstance(val,(int,float)): return int(val)
        for pat,mult in ((r"(?i)(?:retention|ttl|expire\w*)[^\n]{0,40}(\d+)\s*days?",1),(r"(?i)(?:retention|ttl|expire\w*)[^\n]{0,40}(\d+)\s*months?",30),(r"(?i)(?:retention|ttl|expire\w*)[^\n]{0,40}(\d+)\s*years?",365)):
            m=re.search(pat,text)
            if m: return int(m.group(1))*mult
        return None

    # ------------------------------------------------------------------
    # Audit logging
    # ------------------------------------------------------------------

    def _resolve_caller(self) -> dict[str,Any]:
        this_file=os.path.abspath(__file__)
        frame=inspect.currentframe()
        try:
            cur=frame.f_back if frame else None
            while cur:
                filename=os.path.abspath(cur.f_code.co_filename)
                if filename != this_file:
                    info=inspect.getframeinfo(cur,context=1)
                    return {
                        "file": filename,
                        "line": cur.f_lineno,
                        "function": cur.f_code.co_name,
                        "module": cur.f_globals.get('__name__'),
                        "source_line": (info.code_context[0].strip() if info.code_context else None),
                    }
                cur=cur.f_back
        finally:
            del frame
        return {"file":None,"line":None,"function":None,"module":None,"source_line":None}

    def _policy_result(self,filename,cfg,status,matched,action_taken,reason,findings,before,after):
        return {
            "policy_file": filename,
            "policy_name": cfg.get('name'),
            "priority": cfg['priority'],
            "configured_action": cfg['action'],
            "status": status,
            "matched": bool(matched),
            "action_taken": action_taken,
            "reason": reason,
            "findings": self._json_safe(findings),
            "payload_before": self._json_safe(before),
            "payload_after": self._json_safe(after),
            "payload_before_sha256": self._hash_payload(before),
            "payload_after_sha256": self._hash_payload(after),
        }

    def _build_audit_event(self,*,evaluation_id,started,caller,original,output,final_action,blocked_policy,policy_results,fatal_error):
        return {
            "schema_version": self._SCHEMA_VERSION,
            "evaluation_id": evaluation_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "process": {"pid": os.getpid(), "thread_id": threading.get_ident(), "thread_name": threading.current_thread().name},
            "caller": caller,
            "input": {"payload": self._json_safe(original), "payload_type": type(original).__name__, "sha256": self._hash_payload(original)},
            "policy_results": policy_results,
            "result": {
                "final_action": final_action,
                "blocked": blocked_policy is not None,
                "terminal_policy": blocked_policy,
                "output_payload": self._json_safe(output),
                "sha256": self._hash_payload(output),
                "error": (f"{type(fatal_error).__name__}: {fatal_error}" if fatal_error else None),
            },
            "duration_ms": round((time.perf_counter()-started)*1000,3),
        }

    @classmethod
    def _json_safe(cls,value: Any) -> Any:
        if isinstance(value,(str,int,float,bool)) or value is None: return value
        if isinstance(value,bytes): return {"__bytes_base64__":base64.b64encode(value).decode('ascii')}
        if isinstance(value,dict): return {str(k):cls._json_safe(v) for k,v in value.items()}
        if isinstance(value,(list,tuple,set)): return [cls._json_safe(v) for v in value]
        try: json.dumps(value); return value
        except Exception: return repr(value)

    @classmethod
    def _hash_payload(cls,value: Any) -> str:
        raw=json.dumps(cls._json_safe(value),sort_keys=True,separators=(',',':'),ensure_ascii=False).encode('utf-8')
        return 'sha256:'+hashlib.sha256(raw).hexdigest()

    @classmethod
    def _safe_preview(cls,value: Any,limit:int=512) -> str:
        s=json.dumps(cls._json_safe(value),ensure_ascii=False,sort_keys=True)
        return s if len(s)<=limit else s[:limit]+'…'

    def _ensure_audit_parent(self) -> None:
        path=Path(self._audit_log_path); parent=path.parent
        parent.mkdir(parents=True,exist_ok=True)
        if path.exists():
            try: os.chmod(path,stat.S_IRUSR|stat.S_IWUSR)
            except OSError: pass

    def _rotate_audit_if_needed(self) -> None:
        if self._max_audit_bytes<=0 or self._audit_backups<=0: return
        path=Path(self._audit_log_path)
        try:
            if not path.exists() or path.stat().st_size < self._max_audit_bytes: return
        except OSError: return
        oldest=Path(f"{path}.{self._audit_backups}")
        if oldest.exists(): oldest.unlink()
        for i in range(self._audit_backups-1,0,-1):
            src=Path(f"{path}.{i}"); dst=Path(f"{path}.{i+1}")
            if src.exists(): src.replace(dst)
        path.replace(Path(f"{path}.1"))

    def _write_audit_event(self,event: Mapping[str,Any]) -> None:
        line=json.dumps(event,ensure_ascii=False,separators=(',',':'))+'\n'
        with self._audit_lock:
            try:
                self._rotate_audit_if_needed()
                flags=os.O_WRONLY|os.O_CREAT|os.O_APPEND
                fd=os.open(self._audit_log_path,flags,0o600)
                try:
                    try:
                        import fcntl
                        fcntl.flock(fd,fcntl.LOCK_EX)
                    except (ImportError,OSError):
                        pass
                    os.write(fd,line.encode('utf-8'))
                    try: os.fsync(fd)
                    except OSError: pass
                    try:
                        import fcntl
                        fcntl.flock(fd,fcntl.LOCK_UN)
                    except (ImportError,OSError):
                        pass
                finally:
                    os.close(fd)
            except Exception as exc:
                raise self.GuardrailAuditError(f"Failed to write guardrail audit event to {self._audit_log_path}: {exc}") from exc
