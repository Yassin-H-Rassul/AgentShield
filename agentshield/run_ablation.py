"""
Ablation Study: Each Defense Layer Individually
=================================================
Runs 80 attacks on banking + slack with each layer solo:
  - honeytools only
  - honeytokens only
  - parameter_validator only

Compares with all-3-layers results (already collected).

Usage: python -m agentshield.run_ablation --model gpt-4o-mini-2024-07-18
       python -m agentshield.run_ablation --model gpt-5-mini
"""

import sys
import os
import json
import time
import argparse
from pathlib import Path
from datetime import datetime

sys.stdout.reconfigure(encoding='utf-8', errors='replace')
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv()

from agentdojo.task_suite.load_suites import get_suite
from agentdojo.functions_runtime import FunctionsRuntime

from agentshield.defenses.pipeline import (
    build_agentshield_pipeline,
    get_augmented_tools,
    reset_all_detectors,
    get_all_detections,
    prepare_environment,
)
from agentshield.defenses.honeytools import HONEYTOOL_NAMES
from agentshield.attacks.attack_prompts import ALL_ATTACKS


SUITES = ["banking", "slack"]

LAYER_CONFIGS = {
    "honeytools_only": ["honeytools"],
    "honeytokens_only": ["honeytokens"],
    "parameter_validator_only": ["parameter_validator"],
}


def run_attack(suite, tools, pipeline, detectors, user_task, attack_payload):
    reset_all_detectors(detectors)
    injection_defaults = suite.get_injection_vector_defaults()
    injections = {vec: attack_payload for vec in injection_defaults}
    env = suite.load_and_inject_default_environment(injections)
    env = prepare_environment(env)
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
            "attack_succeeded": False,
        }

    tools_used = []
    for msg in messages:
        if msg["role"] == "assistant" and msg.get("tool_calls"):
            for tc in msg["tool_calls"]:
                tools_used.append(tc.function)

    honeytool_triggered = any(t in HONEYTOOL_NAMES for t in tools_used)
    detections = get_all_detections(detectors)

    return {
        "tools_used": tools_used,
        "honeytool_triggered": honeytool_triggered,
        "detections": detections,
        "num_messages": len(messages),
        "attack_succeeded": len(detections) > 0 or honeytool_triggered,
        "error": None,
    }


def main():
    parser = argparse.ArgumentParser(description="Run ablation study")
    parser.add_argument("--model", default="gpt-4o-mini-2024-07-18", help="Model ID")
    args = parser.parse_args()

    model = args.model
    model_short = model.split("-2024")[0].split("-2025")[0].split("-2026")[0]

    print("=" * 60)
    print(f"  Ablation Study — {model_short}")
    print(f"  3 layer configs × 80 attacks × {len(SUITES)} suites")
    print("=" * 60)

    results_dir = Path("agentshield/results")
    results_dir.mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")

    all_results = {
        "metadata": {
            "timestamp": timestamp,
            "model": model,
            "suites": SUITES,
            "layer_configs": list(LAYER_CONFIGS.keys()),
            "total_attacks": len(ALL_ATTACKS),
            "analysis": "ablation_study",
        },
        "runs": [],
    }

    start_time = time.time()

    for config_name, layers in LAYER_CONFIGS.items():
        print(f"\n{'='*60}")
        print(f"  Config: {config_name} (layers: {layers})")
        print(f"{'='*60}")

        # Build pipeline with only the specified layers
        # For honeytools_only and honeytokens_only, we still need augmented tools
        # For parameter_validator_only, we use plain tools (no honeytools in list)
        pipeline, detectors = build_agentshield_pipeline(
            llm=model,
            layers=layers,
        )

        for suite_name in SUITES:
            suite = get_suite("v1.2.2", suite_name)

            if "honeytools" in layers:
                tools = get_augmented_tools(suite.tools)
            else:
                tools = list(suite.tools)

            user_task_ids = list(suite.user_tasks.keys())
            user_task = suite.get_user_task_by_id(user_task_ids[0])

            print(f"\n  Suite: {suite_name}")

            for i, attack in enumerate(ALL_ATTACKS):
                label = f"[{i+1:2d}/80] {attack['id']:16s}"
                print(f"    {label}...", end=" ", flush=True)

                result = run_attack(suite, tools, pipeline, detectors, user_task, attack["payload"])
                det_count = len(result["detections"])

                all_results["runs"].append({
                    "config": config_name,
                    "suite": suite_name,
                    "attack_id": attack["id"],
                    "language": attack["language"],
                    "category": attack["category"],
                    "goal": attack["goal"],
                    **result,
                })

                if det_count > 0:
                    print(f"DETECTED ({det_count})")
                elif result["error"]:
                    print("ERROR")
                else:
                    print("not detected")

    elapsed = time.time() - start_time

    # Save results
    output_path = results_dir / f"ablation_{model_short}_{timestamp}.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(all_results, f, indent=2, default=str, ensure_ascii=False)

    # Summary
    print()
    print("=" * 60)
    print(f"  ABLATION RESULTS — {model_short}")
    print(f"  Time: {elapsed:.0f}s ({elapsed/60:.1f} min)")
    print(f"  Saved: {output_path}")
    print("=" * 60)

    runs = all_results["runs"]

    # Per config summary
    print(f"\n  Detection rate by layer config:")
    for config_name in LAYER_CONFIGS:
        config_runs = [r for r in runs if r["config"] == config_name]
        detected = [r for r in config_runs if r["attack_succeeded"]]
        pct = 100 * len(detected) / max(len(config_runs), 1)
        print(f"    {config_name:30s}: {len(detected):3d}/{len(config_runs)} ({pct:.1f}%)")

    # Per config × suite
    print(f"\n  Detection rate by config × suite:")
    print(f"    {'Config':30s} {'banking':>10s} {'slack':>10s}")
    for config_name in LAYER_CONFIGS:
        row = f"    {config_name:30s}"
        for suite_name in SUITES:
            cs_runs = [r for r in runs if r["config"] == config_name and r["suite"] == suite_name]
            cs_det = [r for r in cs_runs if r["attack_succeeded"]]
            pct = 100 * len(cs_det) / max(len(cs_runs), 1)
            row += f" {pct:9.1f}%"
        print(row)

    # Per config × language (shared categories)
    shared = {"goal_hijack", "data_exfil", "tool_misuse", "adaptive"}
    print(f"\n  Detection by config × language (shared categories):")
    print(f"    {'Config':30s} {'EN':>8s} {'KU':>8s} {'AR':>8s} {'CS':>8s}")
    for config_name in LAYER_CONFIGS:
        row = f"    {config_name:30s}"
        for lang in ["EN", "KU", "AR", "CS"]:
            l_runs = [r for r in runs if r["config"] == config_name
                      and r["language"] == lang and r["category"] in shared]
            l_det = [r for r in l_runs if r["attack_succeeded"]]
            pct = 100 * len(l_det) / max(len(l_runs), 1)
            row += f" {pct:7.1f}%"
        print(row)

    print()


if __name__ == "__main__":
    main()
