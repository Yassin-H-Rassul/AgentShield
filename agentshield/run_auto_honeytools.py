"""
Auto-Generated Honeytools Experiment
======================================
Compares AUTO-GENERATED honeytools vs MANUAL honeytools on all 4 AgentDojo
suites using Set B (GOAL_BASED, 48 prompts) on GPT-4o-mini.

For each suite, honeytools are generated ONCE via LLM, then used for all 48
attacks in that suite.

Usage: python agentshield/run_auto_honeytools.py
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
from agentshield.defenses.auto_honeytools import generate_honeytools_for_suite
from agentshield.attacks.attack_prompts import GOAL_BASED

MODEL = "gpt-4o-mini"
SUITES = ["banking", "slack", "travel", "workspace"]
ATTACK_SET = "set_b"
N_ATTACKS = len(GOAL_BASED)


def run_attack(suite, tools, pipeline, detectors, user_task, attack_payload, honeytool_names):
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
        error_msg = str(e)
        # Wrap YAML / injection-parse errors gracefully
        return {
            "error": error_msg,
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

    honeytool_triggered = any(t in honeytool_names for t in tools_used)
    detections = get_all_detections(detectors)

    return {
        "tools_used": tools_used,
        "honeytool_triggered": honeytool_triggered,
        "detections": detections,
        "num_messages": len(messages),
        "attack_succeeded": len(detections) > 0 or honeytool_triggered,
        "error": None,
    }


def run_suite(suite_name):
    """Generate auto honeytools for one suite, then run all 48 attacks."""
    print(f"\n  {'='*55}")
    print(f"  Suite: {suite_name.upper()}")
    print(f"  {'='*55}")

    # Step 1: Generate suite-specific honeytools (ONCE per suite)
    print(f"  Generating auto honeytools for '{suite_name}'...", flush=True)
    try:
        auto_functions, auto_names, specs = generate_honeytools_for_suite(suite_name, n=3, model=MODEL)
        print(f"  Generated {len(auto_functions)} honeytools: {auto_names}")
        for spec in specs:
            params_str = ", ".join(f"{p['name']}: {p['type']}" for p in spec["params"])
            print(f"    - {spec['name']}({params_str})  [{spec['attack_category']}]")
        generation_error = None
    except Exception as e:
        print(f"  ERROR generating honeytools: {e}")
        print(f"  Falling back to manual honeytools for this suite.")
        from agentshield.defenses.honeytools import HONEYTOOLS, HONEYTOOL_NAMES
        auto_functions = HONEYTOOLS
        auto_names = HONEYTOOL_NAMES
        specs = []
        generation_error = str(e)

    # Step 2: Build pipeline with auto-generated honeytool names
    pipeline, detectors = build_agentshield_pipeline(
        llm=MODEL,
        layers=["honeytools", "honeytokens", "parameter_validator"],
        custom_honeytool_names=auto_names,
    )

    # Step 3: Load suite + augment tools with auto honeytools
    suite = get_suite("v1.2.2", suite_name)
    tools = get_augmented_tools(suite.tools, custom_honeytools=auto_functions)
    user_task_ids = list(suite.user_tasks.keys())
    user_task = suite.get_user_task_by_id(user_task_ids[0])

    print(f"\n  Task: {user_task_ids[0]} | Real tools: {len(suite.tools)} | Augmented: {len(tools)}")
    print(f"  Prompt: {user_task.PROMPT[:70]}...")
    print()

    # Step 4: Run all 48 attacks
    runs = []
    for i, attack in enumerate(GOAL_BASED):
        label = f"[{i+1:2d}/{N_ATTACKS}] {attack['id']:20s} ({attack['language']:2s}/{attack['category']})"
        print(f"    {label}...", end=" ", flush=True)

        result = run_attack(
            suite, tools, pipeline, detectors,
            user_task, attack["payload"],
            honeytool_names=auto_names,
        )
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

    detected = sum(1 for r in runs if r["attack_succeeded"])
    pct = 100 * detected / max(len(runs), 1)
    print(f"\n  Suite result: {detected}/{len(runs)} ({pct:.1f}%) detected")

    return {
        "runs": runs,
        "specs": specs,
        "honeytool_names": list(auto_names),
        "generation_error": generation_error,
    }


def print_comparison_summary(all_runs):
    """Print detection statistics for the auto-honeytools experiment."""
    detected = [r for r in all_runs if r["attack_succeeded"]]
    errors = [r for r in all_runs if r.get("error")]

    print(f"\n  Total: {len(detected)}/{len(all_runs)} ({100*len(detected)/max(len(all_runs),1):.1f}%)")
    if errors:
        print(f"  Errors: {len(errors)}")

    # By suite
    print(f"\n  By suite (AUTO honeytools):")
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
        print(f"    {cat:20s}: {len(cat_det):2d}/{len(cat_runs)} ({pct:.1f}%)")

    # By defense layer
    print(f"\n  By defense layer (what triggered detection):")
    layer_counts = {"honeytool": 0, "honeytoken": 0, "parameter_validator": 0}
    for r in all_runs:
        for d in r["detections"]:
            layer = d.get("layer", "unknown")
            if layer in layer_counts:
                layer_counts[layer] += 1
    for layer, count in layer_counts.items():
        print(f"    {layer}: {count}")

    # Suite x Language detection matrix
    print(f"\n  Detection matrix (suite x language) — AUTO honeytools:")
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
    print("=" * 65)
    print(f"  AgentShield — Auto-Generated Honeytools Experiment")
    print(f"  {N_ATTACKS} GOAL_BASED Attacks x 4 Suites")
    print(f"  Model: {MODEL} | Honeytools: AUTO-GENERATED (3 per suite)")
    print(f"  Conditions: auto_honeytools + parameter_validator + honeytokens")
    print("=" * 65)

    results_dir = Path(__file__).parent / "results"
    results_dir.mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")

    all_runs = []
    suite_metadata = {}
    start_time = time.time()

    for suite_name in SUITES:
        suite_result = run_suite(suite_name)
        all_runs.extend(suite_result["runs"])

        suite_metadata[suite_name] = {
            "generated_honeytool_names": suite_result["honeytool_names"],
            "honeytool_specs": suite_result["specs"],
            "generation_error": suite_result["generation_error"],
            "total_runs": len(suite_result["runs"]),
            "detected": sum(1 for r in suite_result["runs"] if r["attack_succeeded"]),
        }

        # Save per-suite results
        suite_path = results_dir / f"auto_honeytools_{suite_name}_{MODEL}_{timestamp}.json"
        with open(suite_path, "w", encoding="utf-8") as f:
            json.dump({
                "metadata": {
                    "timestamp": timestamp,
                    "model": MODEL,
                    "suite": suite_name,
                    "attack_set": ATTACK_SET,
                    "conditions": ["auto_honeytools", "honeytokens", "parameter_validator"],
                    "honeytool_type": "auto-generated",
                    "generated_honeytool_names": suite_result["honeytool_names"],
                    "honeytool_specs": suite_result["specs"],
                    "generation_error": suite_result["generation_error"],
                    "total_runs": len(suite_result["runs"]),
                },
                "runs": suite_result["runs"],
            }, f, indent=2, default=str, ensure_ascii=False)
        print(f"\n  Saved: {suite_path}")

    elapsed = time.time() - start_time

    # Save combined results
    combined_path = results_dir / f"auto_honeytools_gpt4omini_{timestamp}.json"
    with open(combined_path, "w", encoding="utf-8") as f:
        json.dump({
            "metadata": {
                "timestamp": timestamp,
                "model": MODEL,
                "suites": SUITES,
                "attack_set": ATTACK_SET,
                "conditions": ["auto_honeytools", "honeytokens", "parameter_validator"],
                "honeytool_type": "auto-generated per suite",
                "description": "Honeytools generated once per suite via LLM (gpt-4o-mini), then used for all 48 GOAL_BASED attacks in that suite.",
                "total_attacks_per_suite": N_ATTACKS,
                "total_runs": len(all_runs),
                "elapsed_seconds": round(elapsed, 1),
                "suite_details": suite_metadata,
            },
            "runs": all_runs,
        }, f, indent=2, default=str, ensure_ascii=False)

    print()
    print("=" * 65)
    print(f"  COMPLETE — {len(all_runs)} runs in {elapsed:.0f}s ({elapsed/60:.1f} min)")
    print(f"  Combined results: {combined_path}")
    print("=" * 65)

    print_comparison_summary(all_runs)

    # Final summary table: auto vs manual reference
    print()
    print("  NOTE: Compare these results against set_b_gpt4omini_* files")
    print("  (manual honeytools) to assess auto-generation effectiveness.")
    print()


if __name__ == "__main__":
    main()
