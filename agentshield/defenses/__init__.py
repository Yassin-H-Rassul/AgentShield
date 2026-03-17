"""
AgentShield Defense Layers
==========================
Three defense layers that plug into AgentDojo's pipeline:

Layer 1: HoneytoolDetector  — fake tools that only a compromised agent would call
Layer 2: HoneytokenMonitor  — fake sensitive data monitored for exfiltration
Layer 3: ParameterValidator — allowlisting rules for tool parameters
"""

from agentshield.defenses.honeytools import HoneytoolDetector, HONEYTOOLS, HONEYTOOL_NAMES
from agentshield.defenses.honeytokens import HoneytokenMonitor, DEFAULT_HONEYTOKENS
from agentshield.defenses.parameter_validator import ParameterValidator
from agentshield.defenses.pipeline import build_agentshield_pipeline

__all__ = [
    "HoneytoolDetector",
    "HoneytokenMonitor",
    "ParameterValidator",
    "build_agentshield_pipeline",
    "HONEYTOOLS",
    "HONEYTOOL_NAMES",
    "DEFAULT_HONEYTOKENS",
]
