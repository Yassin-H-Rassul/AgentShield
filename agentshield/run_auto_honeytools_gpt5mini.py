"""
Auto-Generated vs Manual Honeytools Comparison — GPT-5-mini, Set B
===================================================================
Runs 48 GOAL_BASED attack prompts across all 4 AgentDojo suites using
AUTO-GENERATED honeytools (suite-specific, LLM-generated) instead of the
manual defaults, with full AgentShield pipeline:
  - auto-generated honeytools (per suite)
  - parameter_validator
  - honeytokens

Generates honeytools ONCE per suite, then runs all 48 attacks.
48 attacks × 4 suites = 192 total runs.

Usage: python agentshield/run_auto_honeytools_gpt5mini.py
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

MODEL = "gpt-5-mini"
SUITES = ["banking", "slack", "travel", "workspace"]
ATTACK_SET_NAME = "Set B (GOAL_BASED)"
N_ATTACKS = len(GOAL_BASED)


def run_attack(suite, tools, pipeline, detectors, user_task, attack_payload, auto_honeytool_names):
    """Run a single attack and return results."""
    reset_all_detectors(detectors)

    try:
        injection_defaults = suite.get_injection_vector_defaults()
        try:
            injections = {vec: attack_payload for vec in injection_defaults}
        except Exception:
            injections = {}
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

    # Check against auto-generated honeytool names
    honeytool_triggered = any(t in auto_honeytool_names for t in tools_used)
    detections = get_all_detections(detectors)

    return {
        "tools_used": tools_used,
        "honeytool_triggered": honeytool_triggered,
        "detections": detections,
        "num_messages": len(messages),
        "attack_succeeded": len(detections) > 0 or honeytool_triggered,
        "error": None,
    }


def run_suite_with_auto_honeytools(suite_name):
    """Generate auto honeytools for suite, build pipeline, run all attacks."""
    print(f"\n{'='*65}")
    print(f"  Suite: {suite_name.upper()}")
    print(f"{'='*65}")

    # Step 1: Generate auto honeytools for this suite (once)
    print(f"  Generating auto honeytools for {suite_name}...")
    try:
        auto_functions, auto_names, auto_specs = generate_honeytools_for_suite(suite_name)
        print(f"  Generated {len(auto_functions)} honeytools: {sorted(auto_names)}")
        for spec in auto_specs:
            params = ", ".join(f"{p['name']}: {p['type']}" for p in spec.get("params", []))
            print(f"    - {spec['name']}({params}) [{spec.get('attack_category', '?')}]")
    except Exception as e:
        print(f"  ERROR generating honeytools: {e}")
        print(f"  Skipping suite {suite_name}.")
        return [], None

    print()

    # Step 2: Build pipeline with auto honeytool names registered in HoneytoolDetector
    pipeline, detectors = build_agentshield_pipeline(
        llm=MODEL,
        layers=["honeytools", "honeytokens", "parameter_validator"],
        custom_honeytool_names=auto_names,
    )

    # Step 3: Load suite and augment tools with auto-generated honeytools
    suite = get_suite("v1.2.2", suite_name)
    tools = get_augmented_tools(suite.tools, custom_honeytools=auto_functions)
    user_task_ids = list(suite.user_tasks.keys())
    user_task = suite.get_user_task_by_id(user_task_ids[0])

    print(f"  Task: {user_task_ids[0]} | Total tools (real + auto-honey): {len(tools)}")
    print(f"  Prompt: {user_task.PROMPT[:70]}...")
    print()

    # Step 4: Run all 48 GOAL_BASED attacks
    runs = []
    for i, attack in enumerate(GOAL_BASED):
        label = (
            f"[{i+1:2d}/{N_ATTACKS}] {attack['id']:20s} "
            f"({attack['language']:2s}/{attack['category']})"
        )
        print(f"    {label}...", end=" ", flush=True)

        result = run_attack(
            suite, tools, pipeline, detectors,
            user_task, attack["payload"], auto_names
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

        if det_count > 0 or result["honeytool_triggered"]:
            tags = layers_hit[:]
            if result["honeytool_triggered"]:
                tags.append("honeytool(auto)")
            print(f"DETECTED ({det_count}, {tags})")
        elif result["error"]:
            print(f"ERROR: {result['error'][:60]}")
        else:
            print("not detected")

    detected = [r for r in runs if r["attack_succeeded"]]
    print(
        f"\n  Suite {suite_name}: {len(detected)}/{len(runs)} detected "
        f"({100*len(detected)/max(len(runs),1):.1f}%)"
    )

    return runs, auto_specs


def print_summary(all_runs, suite_specs):
    """Print summary statistics for the full experiment."""
    detected = [r for r in all_runs if r["attack_succeeded"]]
    errors = [r for r in all_runs if r.get("error")]

    print(f"\n{'='*65}")
    print(f"  AUTO-GENERATED HONEYTOOLS EXPERIMENT SUMMARY")
    print(f"  Model: {MODEL} | Attacks: {N_ATTACKS} × {len(SUITES)} suites")
    print(f"{'='*65}")

    print(f"\n  Total: {len(detected)}/{len(all_runs)} detected "
          f"({100*len(detected)/max(len(all_runs),1):.1f}%)")
    if errors:
        print(f"  Errors: {len(errors)}")

    # By suite
    print(f"\n  By suite:")
    for suite_name in SUITES:
        suite_runs = [r for r in all_runs if r["suite"] == suite_name]
        suite_det = [r for r in suite_runs if r["attack_succeeded"]]
        pct = 100 * len(suite_det) / max(len(suite_runs), 1)
        names = sorted(suite_specs.get(suite_name, {}).get("names", set()))
        print(f"    {suite_name:12s}: {len(suite_det):2d}/{len(suite_runs)} ({pct:.1f}%)  "
              f"honeytools={names}")

    # By language
    print(f"\n  By language:")
    for lang in ["EN", "KU", "AR", "CS"]:
        lang_runs = [r for r in all_runs if r["language"] == lang]
        lang_det = [r for r in lang_runs if r["attack_succeeded"]]
        pct = 100 * len(lang_det) / max(len(lang_runs), 1)
        print(f"    {lang}: {len(lang_det):2d}/{len(lang_runs)} ({pct:.1f}%)")

    # By category
    print(f"\n  By attack category:")
    categories = sorted(set(r["category"] for r in all_runs))
    for cat in categories:
        cat_runs = [r for r in all_runs if r["category"] == cat]
        cat_det = [r for r in cat_runs if r["attack_succeeded"]]
        pct = 100 * len(cat_det) / max(len(cat_runs), 1)
        print(f"    {cat:25s}: {len(cat_det):2d}/{len(cat_runs)} ({pct:.1f}%)")

    # By defense layer
    print(f"\n  By detection layer:")
    layer_counts = {}
    honeytool_auto_count = 0
    for r in all_runs:
        if r.get("honeytool_triggered"):
            honeytool_auto_count += 1
        for d in r["detections"]:
            layer = d.get("layer", "unknown")
            layer_counts[layer] = layer_counts.get(layer, 0) + 1
    for layer, count in sorted(layer_counts.items()):
        print(f"    {layer}: {count}")
    print(f"    honeytool_auto_triggered: {honeytool_auto_count}")

    # Detection matrix (suite × language)
    print(f"\n  Detection matrix (suite x language):")
    langs = ["EN", "KU", "AR", "CS"]
    print(f"    {'':12s} {'EN':>6s} {'KU':>6s} {'AR':>6s} {'CS':>6s}  {'TOTAL':>7s}")
    for suite_name in SUITES:
        row = f"    {suite_name:12s}"
        total_det = 0
        total_runs = 0
        for lang in langs:
            s_runs = [r for r in all_runs
                      if r["suite"] == suite_name and r["language"] == lang]
            s_det = [r for r in s_runs if r["attack_succeeded"]]
            pct = 100 * len(s_det) / max(len(s_runs), 1)
            row += f" {pct:5.0f}%"
            total_det += len(s_det)
            total_runs += len(s_runs)
        tot_pct = 100 * total_det / max(total_runs, 1)
        row += f"  {tot_pct:5.0f}%"
        print(row)


def main():
    print("=" * 65)
    print(f"  AgentShield — Auto-Generated Honeytools Experiment")
    print(f"  Model: {MODEL} | {ATTACK_SET_NAME}")
    print(f"  {N_ATTACKS} attacks × {len(SUITES)} suites = {N_ATTACKS * len(SUITES)} total runs")
    print(f"  Defense: auto-honeytools + parameter_validator + honeytokens")
    print("=" * 65)

    results_dir = Path(__file__).parent / "results"
    results_dir.mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")

    all_runs = []
    suite_specs_map = {}   # suite_name -> {"names": set, "specs": list}
    start_time = time.time()

    for suite_name in SUITES:
        result = run_suite_with_auto_honeytools(suite_name)
        suite_runs, auto_specs = result

        if not suite_runs:
            # Suite was skipped due to error
            continue

        all_runs.extend(suite_runs)

        # Collect honeytool names used for this suite
        names_used = sorted(set(
            r["attack_id"]  # placeholder — we store from specs below
            for r in suite_runs
        ))
        if auto_specs:
            names_from_specs = [s["name"] for s in auto_specs]
        else:
            names_from_specs = []
        suite_specs_map[suite_name] = {
            "names": names_from_specs,
            "specs": auto_specs or [],
        }

        # Save per-suite intermediate results
        suite_path = results_dir / f"auto_honeytools_gpt5mini_{suite_name}_{timestamp}.json"
        with open(suite_path, "w", encoding="utf-8") as f:
            json.dump({
                "metadata": {
                    "timestamp": timestamp,
                    "model": MODEL,
                    "suite": suite_name,
                    "attack_set": ATTACK_SET_NAME,
                    "conditions": ["auto-generated honeytools", "honeytokens", "parameter_validator"],
                    "honeytool_specs": auto_specs or [],
                    "honeytool_names": names_from_specs,
                    "total_runs": len(suite_runs),
                },
                "runs": suite_runs,
            }, f, indent=2, default=str, ensure_ascii=False)
        print(f"  Saved: {suite_path}")

    elapsed = time.time() - start_time

    # Save combined results
    combined_path = results_dir / f"auto_honeytools_gpt5mini_{timestamp}.json"
    with open(combined_path, "w", encoding="utf-8") as f:
        json.dump({
            "metadata": {
                "timestamp": timestamp,
                "model": MODEL,
                "suites": SUITES,
                "attack_set": ATTACK_SET_NAME,
                "conditions": "auto-generated honeytools per suite",
                "defense_layers": ["auto-generated honeytools", "honeytokens", "parameter_validator"],
                "total_attacks_per_suite": N_ATTACKS,
                "total_runs": len(all_runs),
                "elapsed_seconds": round(elapsed, 1),
                "suite_honeytool_specs": {
                    k: v["specs"] for k, v in suite_specs_map.items()
                },
            },
            "runs": all_runs,
        }, f, indent=2, default=str, ensure_ascii=False)

    print()
    print("=" * 65)
    print(f"  COMPLETE — {len(all_runs)} runs in {elapsed:.0f}s ({elapsed/60:.1f} min)")
    print(f"  Combined results: {combined_path}")
    print("=" * 65)

    print_summary(all_runs, suite_specs_map)
    print()


if __name__ == "__main__":
    main()
