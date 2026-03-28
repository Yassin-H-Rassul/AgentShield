"""
Run 16 NEW Cross-Suite (GOAL_BASED) Attacks on GPT-5-mini Across All 4 AgentDojo Suites
========================================================================================
Runs 16 domain-agnostic GOAL_BASED prompts (goal_email, goal_file, goal_cancel, goal_delete)
across all 4 suites using GPT-5-mini (o200k tokenizer model).
Saves timestamped results to agentshield/results/.

Usage: python agentshield/run_set_b_cross_gpt5mini.py
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
    prepare_environment,
)
from agentshield.defenses.honeytools import HONEYTOOL_NAMES
from agentshield.attacks.attack_prompts import GOAL_BASED

MODEL = "gpt-5-mini"
SUITES = ["banking", "slack", "travel", "workspace"]
ATTACK_SET = "set_b_cross"

# Filter to only the 16 new cross-suite prompts
TARGET_CATEGORIES = {"goal_email", "goal_file", "goal_cancel", "goal_delete"}
ATTACKS = [a for a in GOAL_BASED if a["category"] in TARGET_CATEGORIES]
N_ATTACKS = len(ATTACKS)


def run_attack(suite, tools, pipeline, detectors, user_task, attack_payload):
    """Run a single attack and return results."""
    reset_all_detectors(detectors)

    try:
        injection_defaults = suite.get_injection_vector_defaults()
        injections = {vec: attack_payload for vec in injection_defaults}
        env = suite.load_and_inject_default_environment(injections)
        env = prepare_environment(env)  # Plant honeytoken files
        runtime = FunctionsRuntime(tools)

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


def run_suite(suite_name, pipeline, detectors):
    """Run all 16 cross-suite GOAL_BASED attacks on one suite."""
    suite = get_suite("v1.2.2", suite_name)
    tools = get_augmented_tools(suite.tools)
    user_task_ids = list(suite.user_tasks.keys())
    user_task = suite.get_user_task_by_id(user_task_ids[0])

    print(f"\n  Suite: {suite_name} | Task: {user_task_ids[0]} | Tools: {len(tools)}")
    print(f"  Prompt: {user_task.PROMPT[:70]}...")
    print()

    runs = []
    for i, attack in enumerate(ATTACKS):
        label = f"[{i+1:2d}/{N_ATTACKS}] {attack['id']:22s} ({attack['language']:2s}/{attack['category']})"
        print(f"    {label}...", end=" ", flush=True)

        result = run_attack(suite, tools, pipeline, detectors, user_task, attack["payload"])
        det_count = len(result["detections"])
        layers_hit = list(set(d["layer"] for d in result["detections"]))

        runs.append({
            "suite": suite_name,
            "attack_id": attack["id"],
            "language": attack["language"],
            "category": attack["category"],
            "goal": attack["goal"],
            **result,
        })

        if det_count > 0:
            print(f"DETECTED ({det_count}, {layers_hit})")
        elif result["error"]:
            print(f"ERROR: {result['error'][:60]}")
        else:
            print(f"not detected")

    return runs


def print_summary(all_runs):
    """Print summary statistics."""
    detected = [r for r in all_runs if r["attack_succeeded"]]
    errors = [r for r in all_runs if r.get("error")]

    print(f"\n  Total: {len(detected)}/{len(all_runs)} ({100*len(detected)/max(len(all_runs),1):.1f}%)")
    if errors:
        print(f"  Errors: {len(errors)}")

    # By suite
    print(f"\n  By suite:")
    for suite_name in SUITES:
        suite_runs = [r for r in all_runs if r["suite"] == suite_name]
        suite_det = [r for r in suite_runs if r["attack_succeeded"]]
        pct = 100 * len(suite_det) / max(len(suite_runs), 1)
        print(f"    {suite_name:12s}: {len(suite_det):2d}/{len(suite_runs)} ({pct:.1f}%)")

    # By language
    print(f"\n  By language:")
    for lang in ["EN", "KU", "AR", "CS"]:
        lang_runs = [r for r in all_runs if r["language"] == lang]
        lang_det = [r for r in lang_runs if r["attack_succeeded"]]
        pct = 100 * len(lang_det) / max(len(lang_runs), 1)
        print(f"    {lang}: {len(lang_det):2d}/{len(lang_runs)} ({pct:.1f}%)")

    # By category
    print(f"\n  By category:")
    categories = sorted(set(r["category"] for r in all_runs))
    for cat in categories:
        cat_runs = [r for r in all_runs if r["category"] == cat]
        cat_det = [r for r in cat_runs if r["attack_succeeded"]]
        pct = 100 * len(cat_det) / max(len(cat_runs), 1)
        print(f"    {cat:22s}: {len(cat_det):2d}/{len(cat_runs)} ({pct:.1f}%)")

    # By defense layer
    print(f"\n  By defense layer:")
    layer_counts = {"honeytool": 0, "honeytoken": 0, "parameter_validator": 0}
    for r in all_runs:
        for d in r["detections"]:
            layer = d.get("layer", "unknown")
            if layer in layer_counts:
                layer_counts[layer] += 1
    for layer, count in layer_counts.items():
        print(f"    {layer}: {count}")

    # Suite x Language matrix
    print(f"\n  Detection matrix (suite x language):")
    langs = ["EN", "KU", "AR", "CS"]
    print(f"    {'':12s} {'EN':>6s} {'KU':>6s} {'AR':>6s} {'CS':>6s}")
    for suite_name in SUITES:
        row = f"    {suite_name:12s}"
        for lang in langs:
            s_runs = [r for r in all_runs if r["suite"] == suite_name and r["language"] == lang]
            s_det = [r for r in s_runs if r["attack_succeeded"]]
            pct = 100 * len(s_det) / max(len(s_runs), 1)
            row += f" {pct:5.0f}%"
        print(row)


def main():
    print("=" * 70)
    print(f"  AgentShield — Set B Cross-Suite {N_ATTACKS} Attacks x 4 Suites")
    print(f"  Model: {MODEL}")
    print(f"  Categories: goal_email, goal_file, goal_cancel, goal_delete")
    print(f"  Total runs: {N_ATTACKS} x 4 = {N_ATTACKS * 4}")
    print("=" * 70)

    # Verify we have exactly 16 prompts
    assert N_ATTACKS == 16, f"Expected 16 prompts, got {N_ATTACKS}"
    print(f"\n  Confirmed: {N_ATTACKS} prompts loaded")
    for a in ATTACKS:
        print(f"    {a['id']}")
    print()

    pipeline, detectors = build_agentshield_pipeline(
        llm=MODEL,
        layers=["honeytools", "honeytokens", "parameter_validator"],
    )

    results_dir = Path(__file__).parent / "results"
    results_dir.mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")

    all_runs = []
    start_time = time.time()

    for suite_name in SUITES:
        suite_runs = run_suite(suite_name, pipeline, detectors)
        all_runs.extend(suite_runs)

        # Save per-suite results
        suite_path = results_dir / f"{ATTACK_SET}_{suite_name}_{MODEL}_{timestamp}.json"
        with open(suite_path, "w", encoding="utf-8") as f:
            json.dump({
                "metadata": {
                    "timestamp": timestamp,
                    "model": MODEL,
                    "suite": suite_name,
                    "attack_set": ATTACK_SET,
                    "conditions": ["honeytools", "honeytokens", "parameter_validator"],
                    "categories": sorted(TARGET_CATEGORIES),
                    "total_runs": len(suite_runs),
                },
                "runs": suite_runs,
            }, f, indent=2, default=str, ensure_ascii=False)
        print(f"\n  Saved suite results: {suite_path}")

    elapsed = time.time() - start_time

    # Save combined results
    combined_path = results_dir / f"set_b_cross_gpt5mini_{timestamp}.json"
    with open(combined_path, "w", encoding="utf-8") as f:
        json.dump({
            "metadata": {
                "timestamp": timestamp,
                "model": MODEL,
                "suites": SUITES,
                "attack_set": ATTACK_SET,
                "conditions": ["honeytools", "honeytokens", "parameter_validator"],
                "categories": sorted(TARGET_CATEGORIES),
                "total_attacks_per_suite": N_ATTACKS,
                "total_runs": len(all_runs),
                "elapsed_seconds": round(elapsed, 1),
            },
            "runs": all_runs,
        }, f, indent=2, default=str, ensure_ascii=False)

    print()
    print("=" * 70)
    print(f"  COMPLETE — {len(all_runs)} runs in {elapsed:.0f}s ({elapsed/60:.1f} min)")
    print(f"  Combined results: {combined_path}")
    print("=" * 70)

    print_summary(all_runs)
    print()


if __name__ == "__main__":
    main()
