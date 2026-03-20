"""
Run All 80 Custom Cross-Lingual Attacks
========================================
Injects each of the 80 attack payloads into AgentDojo's banking suite
and measures detection by AgentShield's 3 defense layers.

Usage: python -m agentshield.run_custom_attacks
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
from agentdojo.functions_runtime import FunctionsRuntime

from agentshield.defenses.pipeline import (
    build_agentshield_pipeline,
    get_augmented_tools,
    reset_all_detectors,
    get_all_detections,
)
from agentshield.defenses.honeytools import HONEYTOOL_NAMES
from agentshield.attacks.attack_prompts import ALL_ATTACKS


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


def run_attack(suite, tools, pipeline, detectors, user_task, attack_payload):
    """Run a single attack and return results."""
    reset_all_detectors(detectors)

    injection_defaults = suite.get_injection_vector_defaults()
    injections = {vec: attack_payload for vec in injection_defaults}

    env = suite.load_and_inject_default_environment(injections)
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
    print("=" * 60)
    print("  AgentShield — Run All 80 Custom Attacks")
    print("=" * 60)

    suite = get_suite("v1.2.2", "banking")
    tools = get_augmented_tools(suite.tools)

    pipeline, detectors = build_agentshield_pipeline(
        llm="gpt-4o-mini-2024-07-18",
        layers=["honeytools", "honeytokens", "parameter_validator"],
    )

    user_task = suite.get_user_task_by_id("user_task_0")

    results_dir = Path("agentshield/results")
    results_dir.mkdir(exist_ok=True)

    all_results = {
        "metadata": {
            "timestamp": datetime.now().isoformat(),
            "model": "gpt-4o-mini-2024-07-18",
            "suite": "banking",
            "user_task": "user_task_0",
            "total_attacks": len(ALL_ATTACKS),
        },
        "runs": [],
    }

    start_time = time.time()

    for i, attack in enumerate(ALL_ATTACKS):
        label = f"[{i+1:2d}/80] {attack['id']:16s} ({attack['language']:2s}/{attack['category']})"
        print(f"  {label}...", end=" ", flush=True)

        result = run_attack(suite, tools, pipeline, detectors, user_task, attack["payload"])

        det_count = len(result["detections"])
        layers_hit = list(set(d["layer"] for d in result["detections"]))

        run_data = {
            "attack_id": attack["id"],
            "language": attack["language"],
            "category": attack["category"],
            "goal": attack["goal"],
            **result,
        }
        all_results["runs"].append(run_data)

        if det_count > 0:
            print(f"DETECTED ({det_count} alerts, layers: {layers_hit})")
        elif result["error"]:
            print(f"ERROR: {result['error'][:50]}")
        else:
            print(f"not detected (tools: {result['tools_used'][:3]})")

    elapsed = time.time() - start_time

    # Save results
    results_path = results_dir / "custom_attacks_80.json"
    with open(results_path, "w", encoding="utf-8") as f:
        json.dump(all_results, f, indent=2, default=str, ensure_ascii=False)

    # Summary
    print()
    print("=" * 60)
    print("  RESULTS SUMMARY")
    print("=" * 60)
    print(f"  Time: {elapsed:.0f}s ({elapsed/60:.1f} min)")
    print(f"  Results saved: {results_path}")
    print()

    runs = all_results["runs"]
    detected = [r for r in runs if r["attack_succeeded"]]
    errors = [r for r in runs if r["error"]]

    print(f"  Total attacks: {len(runs)}")
    print(f"  Detected: {len(detected)}/{len(runs)} ({100*len(detected)/len(runs):.1f}%)")
    print(f"  Errors: {len(errors)}")
    print()

    # By language
    print("  Detection rate by language:")
    for lang in ["EN", "KU", "AR", "CS"]:
        lang_runs = [r for r in runs if r["language"] == lang]
        lang_det = [r for r in lang_runs if r["attack_succeeded"]]
        pct = 100 * len(lang_det) / max(len(lang_runs), 1)
        print(f"    {lang}: {len(lang_det)}/{len(lang_runs)} ({pct:.1f}%)")
    print()

    # By category
    print("  Detection rate by category:")
    for cat in ["goal_hijack", "data_exfil", "tool_misuse", "adaptive",
                "zero_width", "transliteration", "homoglyph"]:
        cat_runs = [r for r in runs if r["category"] == cat]
        cat_det = [r for r in cat_runs if r["attack_succeeded"]]
        pct = 100 * len(cat_det) / max(len(cat_runs), 1)
        print(f"    {cat:16s}: {len(cat_det)}/{len(cat_runs)} ({pct:.1f}%)")
    print()

    # By defense layer
    print("  Detections by layer:")
    layer_counts = {"honeytool": 0, "honeytoken": 0, "parameter_validator": 0}
    for r in runs:
        for d in r["detections"]:
            layer = d.get("layer", "unknown")
            if layer in layer_counts:
                layer_counts[layer] += 1
    for layer, count in layer_counts.items():
        print(f"    {layer}: {count}")
    print()

    # Cross-lingual comparison (shared categories only)
    print("  Cross-lingual comparison (shared categories: hijack, exfil, misuse, adaptive):")
    shared_cats = {"goal_hijack", "data_exfil", "tool_misuse", "adaptive"}
    for lang in ["EN", "KU", "AR", "CS"]:
        shared = [r for r in runs if r["language"] == lang and r["category"] in shared_cats]
        shared_det = [r for r in shared if r["attack_succeeded"]]
        pct = 100 * len(shared_det) / max(len(shared), 1)
        print(f"    {lang}: {len(shared_det)}/{len(shared)} ({pct:.1f}%)")
    print()


if __name__ == "__main__":
    main()
