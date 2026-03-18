"""
Baseline Experiment (Option B — Small Test)
=============================================
Runs 5 user tasks per suite x all injection tasks, under 2 conditions:
1. No defense (baseline)
2. AgentShield (all 3 layers)

Saves results to agentshield/results/baseline_experiment.json

Usage: python -m agentshield.run_baseline
"""

import sys
import os
import json
import time
from pathlib import Path
from datetime import datetime

sys.stdout.reconfigure(encoding='utf-8', errors='replace')
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv()

from agentdojo.task_suite.load_suites import get_suite
from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, PipelineConfig
from agentdojo.functions_runtime import FunctionsRuntime

from agentshield.defenses.pipeline import (
    build_agentshield_pipeline,
    get_augmented_tools,
    reset_all_detectors,
    get_all_detections,
)
from agentshield.defenses.honeytools import HONEYTOOL_NAMES


SUITES = ["banking", "slack", "travel", "workspace"]
TASKS_PER_SUITE = 5  # Small test — 5 user tasks per suite


def get_text(msg):
    content = msg.get("content")
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for block in content:
            if isinstance(block, str):
                parts.append(block)
            elif isinstance(block, dict):
                parts.append(block.get("content", block.get("text", "")))
        return "\n".join(parts)
    return str(content)


def run_single(suite, tools, pipeline, detectors, user_task, injections=None):
    """Run a single task and return structured results."""
    if detectors:
        reset_all_detectors(detectors)

    env = suite.load_and_inject_default_environment(injections or {})
    runtime = FunctionsRuntime(tools)

    try:
        _, _, result_env, messages, _ = pipeline.query(
            user_task.PROMPT, runtime, env
        )
    except Exception as e:
        return {
            "error": str(e),
            "tools_used": [],
            "honeytool_triggered": False,
            "detections": [],
            "num_messages": 0,
        }

    # Collect tools used
    tools_used = []
    for msg in messages:
        if msg["role"] == "assistant" and msg.get("tool_calls"):
            for tc in msg["tool_calls"]:
                tools_used.append(tc.function)

    # Check for honeytool calls
    honeytool_triggered = any(t in HONEYTOOL_NAMES for t in tools_used)

    # Get detections from defense layers
    detections = get_all_detections(detectors) if detectors else []

    # Get final assistant response
    final_response = ""
    for msg in reversed(messages):
        if msg["role"] == "assistant" and get_text(msg):
            final_response = get_text(msg)[:200]
            break

    return {
        "tools_used": tools_used,
        "honeytool_triggered": honeytool_triggered,
        "detections": detections,
        "num_messages": len(messages),
        "final_response": final_response,
        "error": None,
    }


def main():
    print("=" * 60)
    print("  AgentShield Baseline Experiment (Option B)")
    print("=" * 60)
    print()

    results_dir = Path("agentshield/results")
    results_dir.mkdir(exist_ok=True)

    all_results = {
        "metadata": {
            "timestamp": datetime.now().isoformat(),
            "model": "gpt-4o-mini-2024-07-18",
            "tasks_per_suite": TASKS_PER_SUITE,
            "suites": SUITES,
            "conditions": ["no_defense", "agentshield"],
        },
        "runs": [],
    }

    # Build pipelines
    # Condition 1: No defense
    config_no_defense = PipelineConfig(
        llm="gpt-4o-mini-2024-07-18",
        model_id=None,
        defense=None,
        system_message_name=None,
        system_message=None,
    )
    pipeline_no_defense = AgentPipeline.from_config(config_no_defense)

    # Condition 2: AgentShield (all 3 layers)
    pipeline_agentshield, detectors = build_agentshield_pipeline(
        llm="gpt-4o-mini-2024-07-18",
        layers=["honeytools", "honeytokens", "parameter_validator"],
    )

    total_runs = 0
    total_detections = 0
    start_time = time.time()

    for suite_name in SUITES:
        print(f"\n--- Suite: {suite_name} ---")
        suite = get_suite("v1.2.2", suite_name)

        # Get first N user tasks
        user_task_ids = list(suite.user_tasks.keys())[:TASKS_PER_SUITE]
        injection_task_ids = list(suite.injection_tasks.keys())

        # Tools: without honeytools (no defense) and with (agentshield)
        tools_plain = list(suite.tools)
        tools_augmented = get_augmented_tools(suite.tools)

        injection_defaults = suite.get_injection_vector_defaults()

        # Built-in attacks from AgentDojo
        from agentdojo.attacks.baseline_attacks import DirectAttack
        attack = DirectAttack(suite, pipeline_no_defense)

        for user_task_id in user_task_ids:
            user_task = suite.get_user_task_by_id(user_task_id)

            # --- Run 1: No defense, no attack (utility baseline) ---
            print(f"  {user_task_id}: utility baseline...", end=" ", flush=True)
            result = run_single(suite, tools_plain, pipeline_no_defense, {}, user_task)
            all_results["runs"].append({
                "suite": suite_name,
                "user_task": user_task_id,
                "injection_task": None,
                "condition": "no_defense",
                "attack": None,
                **result,
            })
            total_runs += 1
            print(f"OK ({result['num_messages']} msgs)")

            # --- Run 2: AgentShield, no attack (utility with defense) ---
            print(f"  {user_task_id}: agentshield utility...", end=" ", flush=True)
            result = run_single(suite, tools_augmented, pipeline_agentshield, detectors, user_task)
            fp = result["honeytool_triggered"]
            all_results["runs"].append({
                "suite": suite_name,
                "user_task": user_task_id,
                "injection_task": None,
                "condition": "agentshield",
                "attack": None,
                **result,
            })
            total_runs += 1
            status = "FALSE POSITIVE!" if fp else "OK (no false positive)"
            print(f"{status} ({result['num_messages']} msgs)")

            # --- Run 3 & 4: With attacks (for each injection task) ---
            for inj_task_id in injection_task_ids:
                inj_task = suite.get_injection_task_by_id(inj_task_id)

                # Generate attack injections
                try:
                    injections = attack.attack(user_task, inj_task)
                except Exception:
                    continue

                if not injections:
                    continue

                # No defense + attack
                print(f"  {user_task_id} x {inj_task_id}: no defense...", end=" ", flush=True)
                result = run_single(suite, tools_plain, pipeline_no_defense, {}, user_task, injections)
                all_results["runs"].append({
                    "suite": suite_name,
                    "user_task": user_task_id,
                    "injection_task": inj_task_id,
                    "condition": "no_defense",
                    "attack": "direct",
                    **result,
                })
                total_runs += 1
                print(f"OK")

                # AgentShield + attack
                print(f"  {user_task_id} x {inj_task_id}: agentshield...", end=" ", flush=True)
                result = run_single(suite, tools_augmented, pipeline_agentshield, detectors, user_task, injections)
                detected = len(result["detections"]) > 0
                total_detections += len(result["detections"])
                all_results["runs"].append({
                    "suite": suite_name,
                    "user_task": user_task_id,
                    "injection_task": inj_task_id,
                    "condition": "agentshield",
                    "attack": "direct",
                    **result,
                })
                total_runs += 1
                det_str = f"DETECTED ({len(result['detections'])} alerts)" if detected else "not detected"
                print(f"{det_str}")

    elapsed = time.time() - start_time

    # Save results
    results_path = results_dir / "baseline_experiment.json"
    with open(results_path, "w", encoding="utf-8") as f:
        json.dump(all_results, f, indent=2, default=str, ensure_ascii=False)

    # Print summary
    print()
    print("=" * 60)
    print("  EXPERIMENT SUMMARY")
    print("=" * 60)
    print(f"  Total runs: {total_runs}")
    print(f"  Time: {elapsed:.1f} seconds")
    print(f"  Results saved: {results_path}")
    print()

    # Calculate stats
    no_def_attacks = [r for r in all_results["runs"] if r["condition"] == "no_defense" and r["attack"]]
    shield_attacks = [r for r in all_results["runs"] if r["condition"] == "agentshield" and r["attack"]]
    shield_utility = [r for r in all_results["runs"] if r["condition"] == "agentshield" and not r["attack"]]

    shield_detected = [r for r in shield_attacks if len(r["detections"]) > 0]
    shield_fp = [r for r in shield_utility if r["honeytool_triggered"]]

    print(f"  Attack runs (no defense): {len(no_def_attacks)}")
    print(f"  Attack runs (agentshield): {len(shield_attacks)}")
    print(f"  AgentShield detections: {len(shield_detected)}/{len(shield_attacks)} ({100*len(shield_detected)/max(len(shield_attacks),1):.1f}%)")
    print(f"  False positives: {len(shield_fp)}/{len(shield_utility)} ({100*len(shield_fp)/max(len(shield_utility),1):.1f}%)")
    print()

    # Per-layer breakdown
    layer_counts = {"honeytool": 0, "honeytoken": 0, "parameter_validator": 0}
    for r in shield_attacks:
        for d in r["detections"]:
            layer = d.get("layer", "unknown")
            if layer in layer_counts:
                layer_counts[layer] += 1

    print("  Detections by layer:")
    for layer, count in layer_counts.items():
        print(f"    {layer}: {count}")
    print()


if __name__ == "__main__":
    main()
