"""
AgentShield Pipeline Builder
==============================
Constructs an AgentDojo pipeline with AgentShield defense layers
inserted at the correct positions.

Usage:
    pipeline, detectors = build_agentshield_pipeline(
        llm="gpt-4o-mini-2024-07-18",
        layers=["honeytools", "honeytokens", "parameter_validator"],
    )
"""

from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, PipelineConfig
from agentdojo.agent_pipeline.tool_execution import ToolsExecutionLoop, ToolsExecutor
from agentdojo.agent_pipeline.llms.openai_llm import OpenAILLM
from agentdojo.agent_pipeline.basic_elements import InitQuery, SystemMessage
from agentdojo.functions_runtime import FunctionsRuntime

from agentshield.defenses.honeytools import HoneytoolDetector, HONEYTOOLS
from agentshield.defenses.honeytokens import HoneytokenMonitor
from agentshield.defenses.parameter_validator import ParameterValidator


def build_agentshield_pipeline(
    llm: str = "gpt-4o-mini-2024-07-18",
    layers: list[str] | None = None,
    system_message: str | None = None,
    honeytokens: dict | None = None,
    parameter_rules: dict | None = None,
) -> tuple[AgentPipeline, dict]:
    """Build an AgentDojo pipeline with AgentShield defense layers.

    Args:
        llm: Model name (e.g., "gpt-4o-mini-2024-07-18").
        layers: Which defense layers to enable.
                Options: "honeytools", "honeytokens", "parameter_validator".
                Default: all three.
        system_message: Custom system message. None for AgentDojo default.
        honeytokens: Custom honeytoken definitions. None for defaults.
        parameter_rules: Custom parameter rules. None for defaults.

    Returns:
        Tuple of (pipeline, detectors) where detectors is a dict of
        layer_name -> detector instance for reading results after a run.
    """
    if layers is None:
        layers = ["honeytools", "honeytokens", "parameter_validator"]

    # Build the base pipeline config to get the LLM and system message
    config = PipelineConfig(
        llm=llm,
        model_id=None,
        defense=None,
        system_message_name=None,
        system_message=system_message,
    )
    base_pipeline = AgentPipeline.from_config(config)

    # Extract the LLM and system message elements from the base pipeline
    # The base pipeline is: [SystemMessage, InitQuery, LLM, ToolsExecutionLoop]
    elements = list(base_pipeline.elements)
    system_msg_element = elements[0]
    init_query_element = elements[1]
    llm_element = elements[2]

    # Build the inner loop elements (run inside ToolsExecutionLoop)
    inner_elements = []
    detectors = {}

    # Defense layers go BEFORE ToolsExecutor so they can inspect/block tool calls
    if "honeytools" in layers:
        detector = HoneytoolDetector()
        inner_elements.append(detector)
        detectors["honeytools"] = detector

    if "honeytokens" in layers:
        monitor = HoneytokenMonitor(honeytokens=honeytokens)
        inner_elements.append(monitor)
        detectors["honeytokens"] = monitor

    if "parameter_validator" in layers:
        validator = ParameterValidator(rules=parameter_rules)
        inner_elements.append(validator)
        detectors["parameter_validator"] = validator

    # ToolsExecutor runs the actual tool calls
    inner_elements.append(ToolsExecutor())

    # LLM generates next response
    inner_elements.append(llm_element)

    # Build the loop
    tools_loop = ToolsExecutionLoop(inner_elements)

    # Build the full pipeline
    pipeline = AgentPipeline([
        system_msg_element,
        init_query_element,
        llm_element,
        tools_loop,
    ])

    return pipeline, detectors


def get_augmented_tools(suite_tools: list) -> list:
    """Add honeytools to a suite's tool list.

    Args:
        suite_tools: The original list of Function objects from a TaskSuite.

    Returns:
        New list with honeytools appended.
    """
    return list(suite_tools) + HONEYTOOLS


def reset_all_detectors(detectors: dict):
    """Reset all detector states for a fresh run."""
    for detector in detectors.values():
        detector.reset()


def get_all_detections(detectors: dict) -> list[dict]:
    """Collect all detections from all layers into a single list."""
    all_detections = []
    for layer_name, detector in detectors.items():
        all_detections.extend(detector.detections)
    return all_detections
