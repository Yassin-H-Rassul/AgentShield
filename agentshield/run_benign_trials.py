"""
Run Benign Trials for False Positive Rate Estimation
=====================================================
Runs ALL user tasks across all 4 suites with AgentShield active
but NO attack injection. Repeated N trials per task.

Purpose: Compute Wilson CI on 0/N_benign for FPR claim.
Target: 400+ benign runs (20 tasks × 4 models × 5 trials).

Usage:
  python -m agentshield.run_benign_trials --model gpt-4o-mini --trials 5
  python -m agentshield.run_benign_trials --model gpt-4o-mini --trials 5 --limit 5
"""

import sys
import os
import json
import argparse
from pathlib import Path
from datetime import datetime

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
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

SUITES = ["banking", "slack", "travel", "workspace"]


def run_benign_task(suite, tools, pipeline, detectors, user_task):
    """Run a single benign user task (no attack) and check for false positives."""
    reset_all_detectors(detectors)
    env = suite.load_and_inject_default_environment({})
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
            "false_positive": False,
        }

    tools_used = []
    for msg in messages:
        if msg["role"] == "assistant" and msg.get("tool_calls"):
            for tc in msg["tool_calls"]:
                tools_used.append(tc.function)

    honeytool_triggered = any(t in HONEYTOOL_NAMES for t in tools_used)
    detections = get_all_detections(detectors)
    false_positive = len(detections) > 0 or honeytool_triggered

    return {
        "tools_used": tools_used,
        "honeytool_triggered": honeytool_triggered,
        "detections": detections,
        "false_positive": false_positive,
        "error": None,
    }


def main():
    parser = argparse.ArgumentParser(description="Benign trials for FPR estimation")
    parser.add_argument("--model", default="gpt-4o-mini", help="Model name")
    parser.add_argument("--trials", type=int, default=5, help="Number of trials per task")
    parser.add_argument("--limit", type=int, default=None, help="Limit tasks per suite (debug)")
    args = parser.parse_args()

    model_arg = args.model
    if model_arg.startswith("together:"):
        actual_model = model_arg.replace("together:", "")
        pipeline, detectors = build_agentshield_pipeline(llm=actual_model)
    else:
        pipeline, detectors = build_agentshield_pipeline(llm=model_arg)

    results_dir = Path("agentshield/results")
    results_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    safe_model = args.model.replace("/", "_").replace(":", "_")

    all_results = []
    total_runs = 0
    total_fp = 0
    fp_by_layer = {"honeytool": 0, "honeytoken": 0, "parameter_validator": 0}

    for suite_name in SUITES:
        suite = get_suite("v1.2.2", suite_name)
        tools = get_augmented_tools(suite.tools)

        task_ids = list(suite.user_tasks.keys())
        if args.limit:
            task_ids = task_ids[:args.limit]

        print(f"\n{'='*50}")
        print(f"  Suite: {suite_name} ({len(task_ids)} tasks × {args.trials} trials)")
        print(f"{'='*50}")

        for task_id in task_ids:
            user_task = suite.user_tasks[task_id]
            for trial in range(1, args.trials + 1):
                total_runs += 1
                result = run_benign_task(suite, tools, pipeline, detectors, user_task)

                if result["false_positive"]:
                    total_fp += 1
                    for d in result["detections"]:
                        layer = d.get("layer", "unknown")
                        if layer in fp_by_layer:
                            fp_by_layer[layer] += 1
                    if result["honeytool_triggered"]:
                        fp_by_layer["honeytool"] += 1
                    print(f"  !! FP: {suite_name}/{task_id} trial {trial}: {[d.get('layer') for d in result['detections']]}")

                all_results.append({
                    "suite": suite_name,
                    "task_id": task_id,
                    "trial": trial,
                    "false_positive": result["false_positive"],
                    "honeytool_triggered": result["honeytool_triggered"],
                    "detections": result["detections"],
                    "tools_used": result["tools_used"],
                    "error": result.get("error"),
                })

                if total_runs % 20 == 0:
                    print(f"  [{total_runs} runs, {total_fp} FP so far]")

    # Compute Wilson CI
    import math
    n = total_runs
    k = total_fp
    z = 1.96
    if n > 0:
        p_hat = k / n
        denom = 1 + z**2 / n
        centre = (p_hat + z**2 / (2 * n)) / denom
        spread = z * math.sqrt((p_hat * (1 - p_hat) + z**2 / (4 * n)) / n) / denom
        ci_lower = max(0, centre - spread)
        ci_upper = min(1, centre + spread)
    else:
        ci_lower, ci_upper = 0, 0

    output = {
        "metadata": {
            "timestamp": timestamp,
            "model": args.model,
            "trials_per_task": args.trials,
            "total_benign_runs": total_runs,
            "total_false_positives": total_fp,
            "fp_by_layer": fp_by_layer,
            "fpr": total_fp / total_runs if total_runs > 0 else 0,
            "wilson_ci_95": [round(ci_lower * 100, 3), round(ci_upper * 100, 3)],
        },
        "results": all_results,
    }

    result_file = results_dir / f"benign_trials_{safe_model}_{timestamp}.json"
    with open(result_file, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(f"\n{'='*60}")
    print(f"  Benign Trial Results")
    print(f"{'='*60}")
    print(f"  Model: {args.model}")
    print(f"  Total benign runs: {total_runs}")
    print(f"  False positives: {total_fp}")
    print(f"  FPR (any layer): {total_fp}/{total_runs} = {total_fp/total_runs*100:.2f}%")
    print(f"  95% Wilson CI: [{ci_lower*100:.3f}%, {ci_upper*100:.3f}%]")
    print(f"\n  Per-layer FP:")
    for layer, count in fp_by_layer.items():
        print(f"    {layer}: {count}/{total_runs} = {count/total_runs*100:.2f}%")
    print(f"\n  Saved: {result_file}")


if __name__ == "__main__":
    main()
