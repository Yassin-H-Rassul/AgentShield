"""
JISA Paper: Analyze Baseline Results
=====================================
Loads baseline experiment results and AgentShield experiment results,
generates the comparison table for the paper.

Usage:
  python paper/scripts/analyze_baseline.py
  python paper/scripts/analyze_baseline.py --latex
"""

import sys
import os
import json
import argparse
from pathlib import Path
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

RESULTS_DIR = Path("agentshield/results")
BASELINE_DIR = RESULTS_DIR / "jisa_baseline"

MODELS = ["gpt-4o-mini", "gpt-5-mini", "llama3.3-70b", "deepseek-v3"]
SUITES = ["banking", "slack", "travel", "workspace"]


def load_latest_baseline(model_short, defense):
    """Load the most recent baseline result for a model+defense combo."""
    pattern = f"baseline_{model_short}_{defense}_*.json"
    files = sorted(BASELINE_DIR.glob(pattern))
    if not files:
        return None
    with open(files[-1], encoding="utf-8") as f:
        return json.load(f)


def load_latest_agentshield(model_short):
    """Load the most recent AgentShield result for a model."""
    # Try different naming patterns used in existing results
    patterns = [
        f"all_suites_80attacks_{model_short}_*.json",
        f"all_suites_80attacks_*{model_short}*_*.json",
    ]

    # Map shorthands to result file names
    name_map = {
        "gpt-4o-mini": ["gpt-4o-mini", "2026-03-21"],
        "gpt-5-mini": ["gpt-5-mini"],
        "llama3.3-70b": ["Llama-3.3-70B-Instruct-Turbo"],
        "deepseek-v3": ["DeepSeek-V3"],
    }

    for pattern in patterns:
        files = sorted(RESULTS_DIR.glob(pattern))
        if files:
            # Filter to files matching this model
            for f in reversed(files):
                if any(n in f.name for n in name_map.get(model_short, [model_short])):
                    with open(f, encoding="utf-8") as fh:
                        return json.load(fh)
    return None


def compute_asr(runs):
    """Compute attack success rate from baseline runs."""
    if not runs:
        return None
    total = len(runs)
    succeeded = sum(1 for r in runs if r.get("attack_succeeded"))
    return {"total": total, "succeeded": succeeded, "asr": 100 * succeeded / total}


def compute_detection_rate(runs):
    """Compute detection rate from AgentShield runs."""
    if not runs:
        return None
    total = len(runs)
    detected = sum(1 for r in runs if r.get("attack_succeeded") or len(r.get("detections", [])) > 0)
    return {"total": total, "detected": detected, "rate": 100 * detected / total}


def print_comparison_table(results, latex=False):
    """Print the comparison table."""
    if latex:
        print(r"\begin{table}[ht]")
        print(r"\centering")
        print(r"\caption{Attack success rate (ASR) under different defenses vs.\ AgentShield detection rate.}")
        print(r"\label{tab:baseline_comparison}")
        print(r"\begin{tabular}{lcccc}")
        print(r"\hline")
        print(r"Model & No Defense ASR & Spotlighting ASR & AgentShield Det. & FP \\")
        print(r"\hline")
        for model in MODELS:
            nd = results.get(model, {}).get("no_defense")
            sp = results.get(model, {}).get("spotlighting")
            ag = results.get(model, {}).get("agentshield")
            nd_str = f"{nd['asr']:.1f}\\%" if nd else "---"
            sp_str = f"{sp['asr']:.1f}\\%" if sp else "---"
            ag_str = f"{ag['rate']:.1f}\\%" if ag else "---"
            model_display = model.replace("gpt-4o-mini", "GPT-4o-mini").replace(
                "gpt-5-mini", "GPT-5-mini"
            ).replace("llama3.3-70b", "Llama 3.3 70B").replace("deepseek-v3", "DeepSeek-V3")
            print(f"{model_display} & {nd_str} & {sp_str} & {ag_str} & 0\\% \\\\")
        print(r"\hline")
        print(r"\end{tabular}")
        print(r"\end{table}")
    else:
        header = f"{'Model':16s} | {'No Defense ASR':>15s} | {'Spotlighting ASR':>17s} | {'AgentShield Det.':>17s} | {'FP':>4s}"
        print(header)
        print("-" * len(header))
        for model in MODELS:
            nd = results.get(model, {}).get("no_defense")
            sp = results.get(model, {}).get("spotlighting")
            ag = results.get(model, {}).get("agentshield")
            nd_str = f"{nd['succeeded']}/{nd['total']} ({nd['asr']:.1f}%)" if nd else "---"
            sp_str = f"{sp['succeeded']}/{sp['total']} ({sp['asr']:.1f}%)" if sp else "---"
            ag_str = f"{ag['detected']}/{ag['total']} ({ag['rate']:.1f}%)" if ag else "---"
            print(f"{model:16s} | {nd_str:>15s} | {sp_str:>17s} | {ag_str:>17s} | {'0%':>4s}")


def main():
    parser = argparse.ArgumentParser(description="Analyze baseline comparison results")
    parser.add_argument("--latex", action="store_true", help="Output LaTeX table")
    parser.add_argument("--by-suite", action="store_true", help="Breakdown by suite")
    parser.add_argument("--by-language", action="store_true", help="Breakdown by language")
    args = parser.parse_args()

    print("Loading results...\n")

    results = {}
    for model in MODELS:
        results[model] = {}

        # Baseline results
        for defense in ["no_defense", "spotlighting"]:
            data = load_latest_baseline(model, defense)
            if data:
                results[model][defense] = compute_asr(data["runs"])
                print(f"  Loaded: {model} / {defense} ({len(data['runs'])} runs)")
            else:
                print(f"  Missing: {model} / {defense}")

        # AgentShield results
        data = load_latest_agentshield(model)
        if data:
            results[model]["agentshield"] = compute_detection_rate(data["runs"])
            print(f"  Loaded: {model} / agentshield ({len(data['runs'])} runs)")
        else:
            print(f"  Missing: {model} / agentshield")

    print()
    print("=" * 80)
    print("  COMPARISON TABLE")
    print("=" * 80)
    print()
    print_comparison_table(results, latex=args.latex)

    if args.by_suite:
        print()
        print("=" * 80)
        print("  BREAKDOWN BY SUITE")
        print("=" * 80)
        for model in MODELS:
            for defense in ["no_defense", "spotlighting"]:
                data = load_latest_baseline(model, defense)
                if not data:
                    continue
                print(f"\n  {model} / {defense}:")
                for suite in SUITES:
                    s_runs = [r for r in data["runs"] if r["suite"] == suite]
                    stats = compute_asr(s_runs)
                    if stats:
                        print(f"    {suite:12s}: {stats['succeeded']:3d}/{stats['total']} ({stats['asr']:.1f}%)")

    if args.by_language:
        print()
        print("=" * 80)
        print("  BREAKDOWN BY LANGUAGE")
        print("=" * 80)
        for model in MODELS:
            for defense in ["no_defense", "spotlighting"]:
                data = load_latest_baseline(model, defense)
                if not data:
                    continue
                print(f"\n  {model} / {defense}:")
                for lang in ["EN", "KU", "AR", "CS"]:
                    l_runs = [r for r in data["runs"] if r["language"] == lang]
                    stats = compute_asr(l_runs)
                    if stats:
                        print(f"    {lang}: {stats['succeeded']:3d}/{stats['total']} ({stats['asr']:.1f}%)")


if __name__ == "__main__":
    main()
