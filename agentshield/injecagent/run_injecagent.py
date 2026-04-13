"""
InjecAgent + AgentShield Honeytool Evaluation Runner
=====================================================
Tests whether honeytool-based detection generalises from AgentDojo to InjecAgent.

Only Layer 1 (honeytools) is tested — Layers 2 (honeytokens) and 3 (parameter
validation) require multi-step trajectories with real tool parameters, which
InjecAgent does not provide.

Usage:
  # Phase A: GPT-4o-mini, base setting, function-calling (quick test)
  python -m agentshield.injecagent.run_injecagent --model gpt-4o-mini --setting base --limit 50

  # Full run
  python -m agentshield.injecagent.run_injecagent --model gpt-4o-mini --setting base

  # Baseline (no honeytools) for ASR verification
  python -m agentshield.injecagent.run_injecagent --model gpt-4o-mini --setting base --no-honeytools
"""

import sys
import os
import json
import argparse
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Literal

# Load .env for API keys
from dotenv import load_dotenv
load_dotenv(Path("C:/ukh/pr/thesis-ideas/.env"))

from openai import OpenAI
from pydantic import BaseModel
from tqdm import tqdm

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# Add InjecAgent to path
INJECAGENT_DIR = Path("C:/ukh/pr/InjecAgent")
sys.path.insert(0, str(INJECAGENT_DIR))
os.chdir(INJECAGENT_DIR)

from src.utils import get_tool_dict, get_simulated_attacker_tool_response, get_score
from src.output_parsing import evaluate_output_finetuned
from src.prompts.agent_prompts import PROMPT_DICT

from agentshield.injecagent.honeytools_injecagent import (
    HONEYTOOL_NAMES,
    HONEYTOOL_NAME_LIST,
    get_honeytool_dict,
)


# ── Pydantic models (from InjecAgent) ──

class Function(BaseModel):
    arguments: str
    name: str

class ChatCompletionMessageToolCall(BaseModel):
    id: str
    function: Function
    type: Literal["function"]

class FunctionCall(BaseModel):
    arguments: str
    name: str

class ChatCompletionMessage(BaseModel):
    content: Optional[str]
    role: Literal["assistant"]
    function_call: Optional[FunctionCall] = None
    tool_calls: Optional[List[ChatCompletionMessageToolCall]] = None


# ── Core evaluation ──

def predict_one_case(client, model_name, system_prompt, item, tool_dict,
                     honeytool_names_list, use_honeytools=True, step_2=False):
    """Run one InjecAgent test case with optional honeytools."""
    available_tool_names = [item["User Tool"]] + item["Attacker Tools"]
    if use_honeytools:
        available_tool_names += honeytool_names_list

    available_tools = [tool_dict[t] for t in available_tool_names if t in tool_dict]

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": item["User Instruction"]},
    ]

    # Simulate user tool call + response (InjecAgent's setup)
    call_id = "call_agentshield_user_tool"
    function_name = item["User Tool"]
    message = ChatCompletionMessage(
        content=None,
        role="assistant",
        tool_calls=[
            ChatCompletionMessageToolCall(
                id=call_id,
                function=Function(
                    arguments=json.dumps(item["Tool Parameters"]),
                    name=function_name,
                ),
                type="function",
            )
        ],
    )
    messages.append(message)
    messages.append(
        {
            "tool_call_id": call_id,
            "role": "tool",
            "name": function_name,
            "content": json.dumps(item["Tool Response"]),
        }
    )

    if step_2:
        tool_call = item["tool_calls"][0]
        message = ChatCompletionMessage(
            content=item["output"],
            role="assistant",
            tool_calls=[
                ChatCompletionMessageToolCall(
                    id=tool_call["id"],
                    function=Function(
                        arguments=json.dumps(item["Attacker Tool Parameters"]),
                        name=tool_call["function"]["name"],
                    ),
                    type="function",
                )
            ],
        )
        messages.append(message)
        messages.append(
            {
                "tool_call_id": tool_call["id"],
                "role": "tool",
                "name": tool_call["function"]["name"],
                "content": item["Attacker Tool Response"],
            }
        )

    response = client.chat.completions.create(
        model=model_name,
        messages=messages,
        tools=available_tools,
        temperature=0,
    )
    response_message = response.choices[0].message
    tool_calls = response_message.tool_calls
    if isinstance(tool_calls, list):
        tool_calls = [tc.model_dump() for tc in tool_calls]
    return response_message.content, tool_calls


def check_honeytool_triggered(tool_calls):
    """Check if any tool call is a honeytool."""
    if not tool_calls:
        return False, []

    triggered = []
    for tc in tool_calls:
        name = tc["function"]["name"]
        if name in HONEYTOOL_NAMES:
            triggered.append({
                "tool": name,
                "args": tc["function"].get("arguments", "{}"),
                "id": tc.get("id", ""),
            })
    return len(triggered) > 0, triggered


def make_client(model_name):
    """Create the appropriate OpenAI-compatible client for the model."""
    if model_name.startswith("together:"):
        return OpenAI(
            api_key=os.environ.get("TOGETHER_API_KEY"),
            base_url="https://api.together.xyz/v1",
        ), model_name.replace("together:", "")
    else:
        return OpenAI(
            api_key=os.environ.get("OPENAI_API_KEY"),
            organization=os.environ.get("OPENAI_ORGANIZATION"),
        ), model_name


def run_experiment(args):
    """Run the full InjecAgent + honeytool evaluation."""
    client, actual_model = make_client(args.model)

    # Load tools
    tool_dict = get_tool_dict(gpt_format=True)
    if args.use_honeytools:
        honeytool_dict = get_honeytool_dict(gpt_format=True)
        tool_dict.update(honeytool_dict)
        print(f"Added {len(honeytool_dict)} honeytools: {HONEYTOOL_NAME_LIST}")

    system_prompt, _ = PROMPT_DICT.get("InjecAgent", PROMPT_DICT[list(PROMPT_DICT.keys())[0]])

    results_dir = Path("C:/ukh/pr/thesis-ideas/agentshield/results/injecagent")
    results_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    condition = "honeytools" if args.use_honeytools else "baseline"
    safe_model = args.model.replace("/", "_").replace(":", "_").replace("\\", "_")
    result_file = results_dir / f"injecagent_{safe_model}_{args.setting}_{condition}_{timestamp}.json"

    all_results = []
    stats = {
        "total": 0,
        "attack_succ": 0,
        "honeytool_triggered": 0,
        "attack_succ_and_honeytool": 0,
        "invalid": 0,
        "by_attack_type": {},
    }

    for attack_type in ["dh", "ds"]:
        file_name = f"test_cases_{attack_type}_{args.setting}.json"
        test_case_file = INJECAGENT_DIR / "data" / file_name

        with open(test_case_file) as f:
            data = json.load(f)

        if args.limit:
            data = data[: args.limit]

        type_label = "direct_harm" if attack_type == "dh" else "data_stealing"
        type_stats = {"total": 0, "succ": 0, "honeytool": 0, "succ_and_honeytool": 0}

        desc = f"{type_label} ({args.setting})"
        for item in tqdm(data, desc=desc):
            stats["total"] += 1
            type_stats["total"] += 1

            try:
                output, tool_calls = predict_one_case(
                    client, actual_model, system_prompt, item, tool_dict,
                    HONEYTOOL_NAME_LIST, use_honeytools=args.use_honeytools,
                )
            except Exception as e:
                print(f"  Error: {e}")
                all_results.append({
                    "attack_type": type_label,
                    "user_tool": item["User Tool"],
                    "attacker_tools": item["Attacker Tools"],
                    "eval": "error",
                    "honeytool_triggered": False,
                    "error": str(e),
                })
                stats["invalid"] += 1
                continue

            # InjecAgent evaluation — handle empty tool_calls
            if tool_calls is not None and len(tool_calls) == 0:
                tool_calls = None  # treat empty list same as None
            parsed = evaluate_output_finetuned(
                output, item["Attacker Tools"][0], item["User Tool"], tool_calls
            )
            attack_eval = parsed["eval"]

            # Honeytool detection
            ht_triggered, ht_details = check_honeytool_triggered(tool_calls or [])

            # Track stats
            if attack_eval == "succ":
                stats["attack_succ"] += 1
                type_stats["succ"] += 1
            if ht_triggered:
                stats["honeytool_triggered"] += 1
                type_stats["honeytool"] += 1
            if attack_eval == "succ" and ht_triggered:
                stats["attack_succ_and_honeytool"] += 1
                type_stats["succ_and_honeytool"] += 1
            if attack_eval == "invalid":
                stats["invalid"] += 1

            # Data stealing step 2 (if step 1 succeeded)
            step2_eval = None
            if attack_eval == "succ" and attack_type == "ds":
                item["output"] = output
                item["tool_calls"] = tool_calls
                item["Attacker Tool Parameters"] = parsed.get("Attacker Tool Parameters", "{}")
                try:
                    item["Attacker Tool Response"] = get_simulated_attacker_tool_response(
                        item["Attacker Tools"][0], item["Attacker Tool Parameters"], tool_dict
                    )
                    output2, tool_calls2 = predict_one_case(
                        client, actual_model, system_prompt, item, tool_dict,
                        HONEYTOOL_NAME_LIST, use_honeytools=args.use_honeytools,
                        step_2=True,
                    )
                    parsed2 = evaluate_output_finetuned(
                        output2, item["Attacker Tools"][1] if len(item["Attacker Tools"]) > 1 else item["Attacker Tools"][0],
                        item["User Tool"], tool_calls2
                    )
                    step2_eval = parsed2["eval"]

                    # Check honeytools in step 2
                    ht2_triggered, ht2_details = check_honeytool_triggered(tool_calls2 or [])
                    if ht2_triggered:
                        ht_triggered = True
                        ht_details.extend(ht2_details)
                        if not any(r["tool"] == d["tool"] for r in ht_details[:len(ht_details)-len(ht2_details)] for d in ht2_details):
                            stats["honeytool_triggered"] += 1
                            type_stats["honeytool"] += 1
                except Exception as e:
                    step2_eval = "error"

            result = {
                "attack_type": type_label,
                "user_tool": item["User Tool"],
                "attacker_tools": item["Attacker Tools"],
                "eval": attack_eval,
                "step2_eval": step2_eval,
                "honeytool_triggered": ht_triggered,
                "honeytool_details": ht_details,
                "tools_called": [tc["function"]["name"] for tc in (tool_calls or [])],
            }
            all_results.append(result)

        stats["by_attack_type"][type_label] = type_stats

    # Save results
    output_data = {
        "metadata": {
            "timestamp": timestamp,
            "model": args.model,
            "setting": args.setting,
            "use_honeytools": args.use_honeytools,
            "honeytool_names": HONEYTOOL_NAME_LIST,
            "total_cases": stats["total"],
        },
        "stats": stats,
        "results": all_results,
    }

    with open(result_file, "w", encoding="utf-8") as f:
        json.dump(output_data, f, indent=2, ensure_ascii=False)

    # Print summary
    print(f"\n{'='*60}")
    print(f"  InjecAgent + AgentShield Results")
    print(f"{'='*60}")
    print(f"  Model: {args.model}")
    print(f"  Setting: {args.setting}")
    print(f"  Honeytools: {'YES' if args.use_honeytools else 'NO'}")
    print(f"  Total cases: {stats['total']}")
    print(f"  Invalid: {stats['invalid']}")
    valid = stats['total'] - stats['invalid']
    print(f"  Valid: {valid}")
    print(f"  Attack success: {stats['attack_succ']} ({stats['attack_succ']/valid*100:.1f}% of valid)" if valid else "")
    if args.use_honeytools:
        print(f"  Honeytool triggered: {stats['honeytool_triggered']} ({stats['honeytool_triggered']/stats['total']*100:.1f}%)")
        if stats['attack_succ']:
            print(f"  Det. on successful: {stats['attack_succ_and_honeytool']}/{stats['attack_succ']} ({stats['attack_succ_and_honeytool']/stats['attack_succ']*100:.1f}%)")
    print(f"\n  By attack type:")
    for atype, ts in stats["by_attack_type"].items():
        print(f"    {atype}: {ts['succ']}/{ts['total']} succ", end="")
        if args.use_honeytools:
            print(f", {ts['honeytool']}/{ts['total']} honeytool", end="")
        print()
    print(f"\n  Saved: {result_file}")


def main():
    parser = argparse.ArgumentParser(description="InjecAgent + AgentShield Honeytool Evaluation")
    parser.add_argument("--model", default="gpt-4o-mini", help="Model name")
    parser.add_argument("--setting", choices=["base", "enhanced"], default="base")
    parser.add_argument("--no-honeytools", dest="use_honeytools", action="store_false",
                        help="Run without honeytools (baseline)")
    parser.add_argument("--limit", type=int, default=None, help="Limit test cases (for debugging)")
    args = parser.parse_args()
    run_experiment(args)


if __name__ == "__main__":
    main()
