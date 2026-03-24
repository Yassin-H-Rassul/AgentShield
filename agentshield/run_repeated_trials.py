"""
Repeated Trials for Statistical Validity
==========================================
Runs 80 attacks × N trials on banking + slack for both models.
Saves per-trial results and computes mean, std, 95% CI.

Usage:
  python -m agentshield.run_repeated_trials --model gpt-4o-mini-2024-07-18 --trials 3
  python -m agentshield.run_repeated_trials --model gpt-5-mini --trials 3
"""

import sys
import os
import json
import time
import argparse
import math
from pathlib import Path
from datetime import datetime
from collections import defaultdict

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


def run_attack(suite, tools, pipeline, detectors, user_task, attack_payload):
    reset_all_detectors(detectors)
    injection_defaults = suite.get_injection_vector_defaults()
    injections = {vec: attack_payload for vec in injection_defaults}
    env = suite.load_and_inject_default_environment(injections)
    env = prepare_environment(env)
    runtime = FunctionsRuntime(tools)

    try:
        _, _, _, messages, _ = pipeline.query(user_task.PROMPT, runtime, env)
    except Exception as e:
        return {"error": str(e), "tools_used": [], "honeytool_triggered": False,
                "detections": [], "num_messages": 0, "attack_succeeded": False}

    tools_used = [tc.function for msg in messages
                  if msg["role"] == "assistant" and msg.get("tool_calls")
                  for tc in msg["tool_calls"]]
    honeytool_triggered = any(t in HONEYTOOL_NAMES for t in tools_used)
    detections = get_all_detections(detectors)

    return {"tools_used": tools_used, "honeytool_triggered": honeytool_triggered,
            "detections": detections, "num_messages": len(messages),
            "attack_succeeded": len(detections) > 0 or honeytool_triggered, "error": None}


def compute_ci(values, confidence=0.95):
    """Compute mean, std, and 95% CI for a list of values."""
    n = len(values)
    if n == 0:
        return 0, 0, (0, 0)
    mean = sum(values) / n
    if n == 1:
        return mean, 0, (mean, mean)
    variance = sum((x - mean) ** 2 for x in values) / (n - 1)
    std = math.sqrt(variance)
    # t-value for 95% CI with n-1 df (approximate for small n)
    t_values = {1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571}
    t = t_values.get(n - 1, 1.96)
    margin = t * std / math.sqrt(n)
    return mean, std, (mean - margin, mean + margin)


def main():
    parser = argparse.ArgumentParser(description="Run repeated trials")
    parser.add_argument("--model", default="gpt-4o-mini-2024-07-18")
    parser.add_argument("--trials", type=int, default=3)
    args = parser.parse_args()

    model = args.model
    num_trials = args.trials
    model_short = model.split("-2024")[0].split("-2025")[0].split("-2026")[0]

    print("=" * 60)
    print(f"  Repeated Trials — {model_short} × {num_trials} trials")
    print(f"  Suites: {SUITES}")
    print("=" * 60)

    pipeline, detectors = build_agentshield_pipeline(
        llm=model, layers=["honeytools", "honeytokens", "parameter_validator"])

    results_dir = Path("agentshield/results")
    results_dir.mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")

    all_trials = {"metadata": {"timestamp": timestamp, "model": model,
                                "suites": SUITES, "num_trials": num_trials,
                                "total_attacks": len(ALL_ATTACKS)},
                  "trials": []}

    start_time = time.time()

    for trial_num in range(1, num_trials + 1):
        print(f"\n{'='*60}")
        print(f"  TRIAL {trial_num}/{num_trials}")
        print(f"{'='*60}")

        trial_runs = []
        for suite_name in SUITES:
            suite = get_suite("v1.2.2", suite_name)
            tools = get_augmented_tools(suite.tools)
            user_task = suite.get_user_task_by_id(list(suite.user_tasks.keys())[0])

            print(f"\n  Suite: {suite_name}")
            for i, attack in enumerate(ALL_ATTACKS):
                print(f"    [{i+1:2d}/80] {attack['id']:16s}...", end=" ", flush=True)
                result = run_attack(suite, tools, pipeline, detectors, user_task, attack["payload"])
                det = len(result["detections"])
                trial_runs.append({"trial": trial_num, "suite": suite_name,
                                    "attack_id": attack["id"], "language": attack["language"],
                                    "category": attack["category"], **result})
                print(f"{'DETECTED' if det > 0 else 'not detected'}")

        all_trials["trials"].append({"trial_num": trial_num, "runs": trial_runs})

    elapsed = time.time() - start_time

    # Save raw results
    output_path = results_dir / f"repeated_trials_{model_short}_{num_trials}x_{timestamp}.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(all_trials, f, indent=2, default=str, ensure_ascii=False)

    # Compute statistics
    print(f"\n{'='*60}")
    print(f"  STATISTICAL SUMMARY — {model_short} × {num_trials} trials")
    print(f"  Time: {elapsed:.0f}s ({elapsed/60:.1f} min)")
    print(f"  Saved: {output_path}")
    print(f"{'='*60}")

    # Per-trial detection rates
    trial_rates = []
    for trial_data in all_trials["trials"]:
        runs = trial_data["runs"]
        detected = sum(1 for r in runs if r["attack_succeeded"])
        rate = 100 * detected / len(runs)
        trial_rates.append(rate)
        print(f"\n  Trial {trial_data['trial_num']}: {detected}/{len(runs)} ({rate:.1f}%)")

    mean, std, ci = compute_ci(trial_rates)
    print(f"\n  Overall: {mean:.1f}% +/- {std:.1f}% (95% CI: [{ci[0]:.1f}%, {ci[1]:.1f}%])")

    # Per-language with CIs
    print(f"\n  By language (95% CI):")
    shared = {"goal_hijack", "data_exfil", "tool_misuse", "adaptive"}
    for lang in ["EN", "KU", "AR", "CS"]:
        lang_rates = []
        for trial_data in all_trials["trials"]:
            runs = trial_data["runs"]
            l_runs = [r for r in runs if r["language"] == lang and r["category"] in shared]
            l_det = sum(1 for r in l_runs if r["attack_succeeded"])
            lang_rates.append(100 * l_det / max(len(l_runs), 1))
        mean, std, ci = compute_ci(lang_rates)
        print(f"    {lang}: {mean:.1f}% +/- {std:.1f}% (CI: [{ci[0]:.1f}%, {ci[1]:.1f}%])")

    # Per-suite with CIs
    print(f"\n  By suite (95% CI):")
    for suite_name in SUITES:
        suite_rates = []
        for trial_data in all_trials["trials"]:
            runs = trial_data["runs"]
            s_runs = [r for r in runs if r["suite"] == suite_name]
            s_det = sum(1 for r in s_runs if r["attack_succeeded"])
            suite_rates.append(100 * s_det / max(len(s_runs), 1))
        mean, std, ci = compute_ci(suite_rates)
        print(f"    {suite_name:12s}: {mean:.1f}% +/- {std:.1f}% (CI: [{ci[0]:.1f}%, {ci[1]:.1f}%])")

    # Save summary
    summary_path = results_dir / f"repeated_trials_summary_{model_short}_{num_trials}x_{timestamp}.json"
    summary = {
        "model": model, "trials": num_trials, "suites": SUITES,
        "overall_rates": trial_rates,
        "overall_mean": mean, "overall_std": std, "overall_ci": ci,
    }
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print(f"\n  Summary saved: {summary_path}")
    print()


if __name__ == "__main__":
    main()
