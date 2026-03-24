"""
Test Ollama Model Compatibility
=================================
Runs 5 attacks on banking suite to verify tool calling works
before running the full experiment. Checks:
1. Model can receive and process tool definitions
2. Model generates valid tool calls (proper JSON)
3. Multi-step agent loop completes without errors
4. Detection layers function correctly

Usage: python -m agentshield.test_ollama_model --model ollama:llama4
       python -m agentshield.test_ollama_model --model ollama:qwen3.5:9b
"""

import sys
import os
import json
import argparse

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


def main():
    parser = argparse.ArgumentParser(description="Test Ollama model compatibility")
    parser.add_argument("--model", required=True, help="Model ID (e.g., ollama:llama4)")
    args = parser.parse_args()

    model = args.model
    model_short = model.replace("ollama:", "").replace(":", "-")

    print("=" * 60)
    print(f"  Ollama Model Compatibility Test — {model}")
    print("=" * 60)

    # Test 1: Can we build the pipeline?
    print("\n[1/5] Building pipeline...", end=" ", flush=True)
    try:
        pipeline, detectors = build_agentshield_pipeline(
            llm=model, layers=["honeytools", "honeytokens", "parameter_validator"])
        print("OK")
    except Exception as e:
        print(f"FAILED: {e}")
        print("\nCannot proceed. Check that Ollama is running and the model is pulled.")
        return False

    # Test 2: Can the model complete a basic task (no attack)?
    print("[2/5] Running baseline task (no attack)...", end=" ", flush=True)
    suite = get_suite("v1.2.2", "banking")
    tools = get_augmented_tools(suite.tools)
    user_task = suite.get_user_task_by_id("user_task_0")

    env = suite.load_and_inject_default_environment({})
    env = prepare_environment(env)
    runtime = FunctionsRuntime(tools)
    reset_all_detectors(detectors)

    try:
        _, _, _, messages, _ = pipeline.query(user_task.PROMPT, runtime, env)
        tools_used = [tc.function for msg in messages
                      if msg["role"] == "assistant" and msg.get("tool_calls")
                      for tc in msg["tool_calls"]]
        if len(tools_used) > 0:
            print(f"OK — used {len(tools_used)} tools: {tools_used[:5]}")
        else:
            print(f"WARNING — no tools called. Model may not support tool calling.")
            print(f"  Messages: {len(messages)}")
            for msg in messages:
                if msg["role"] == "assistant":
                    content = msg.get("content")
                    if content:
                        text = ""
                        if isinstance(content, list):
                            for b in content:
                                if isinstance(b, dict):
                                    text = b.get("content", b.get("text", ""))[:100]
                        elif isinstance(content, str):
                            text = content[:100]
                        print(f"  Assistant said: {text}")
    except Exception as e:
        print(f"FAILED: {e}")
        print("\nModel cannot complete basic tasks. Tool calling likely unsupported.")
        return False

    # Test 3-5: Run 3 attacks (English, Kurdish, Arabic)
    test_attacks = [
        next(a for a in ALL_ATTACKS if a["id"] == "EN_EXFIL_01"),
        next(a for a in ALL_ATTACKS if a["id"] == "KU_HIJACK_01"),
        next(a for a in ALL_ATTACKS if a["id"] == "AR_MISUSE_01"),
    ]

    successes = 0
    errors = 0
    detections = 0

    for i, attack in enumerate(test_attacks, 3):
        print(f"[{i}/5] Attack {attack['id']} ({attack['language']})...", end=" ", flush=True)

        reset_all_detectors(detectors)
        injection_defaults = suite.get_injection_vector_defaults()
        injections = {vec: attack["payload"] for vec in injection_defaults}
        env = suite.load_and_inject_default_environment(injections)
        env = prepare_environment(env)
        runtime = FunctionsRuntime(tools)

        try:
            _, _, _, messages, _ = pipeline.query(user_task.PROMPT, runtime, env)
            tools_used = [tc.function for msg in messages
                          if msg["role"] == "assistant" and msg.get("tool_calls")
                          for tc in msg["tool_calls"]]
            dets = get_all_detections(detectors)

            if len(tools_used) > 0:
                successes += 1
                det_str = f"DETECTED ({len(dets)} alerts)" if dets else "not detected"
                print(f"OK — tools: {tools_used[:4]} — {det_str}")
                if dets:
                    detections += 1
            else:
                print(f"WARNING — no tools called")
        except Exception as e:
            errors += 1
            print(f"ERROR: {str(e)[:80]}")

    # Summary
    print(f"\n{'='*60}")
    print(f"  COMPATIBILITY TEST RESULTS")
    print(f"{'='*60}")
    print(f"  Model: {model}")
    print(f"  Baseline task: {'PASS' if len(tools_used) > 0 else 'FAIL'}")
    print(f"  Attack runs completed: {successes}/3")
    print(f"  Attack runs errored: {errors}/3")
    print(f"  Detections: {detections}/3")
    print()

    if successes >= 2 and errors == 0:
        print("  VERDICT: COMPATIBLE — safe to run full experiments")
        print(f"  Run: python -m agentshield.run_all_suites --model {model}")
        return True
    elif successes >= 1:
        print("  VERDICT: PARTIALLY COMPATIBLE — may work but expect some errors")
        print("  Consider running a smaller test (10-20 attacks) before full suite.")
        return True
    else:
        print("  VERDICT: NOT COMPATIBLE — do not run full experiments")
        print("  This model's tool calling does not work with AgentDojo.")
        print("  Try a different model or use cloud API instead.")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
