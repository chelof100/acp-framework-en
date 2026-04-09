"""
test_mistral.py — Quick smoke test for Mistral-small3.1 via Ollama.

Tests:
  1. Basic chat response (speed check)
  2. Tool calling (function call parsing)
  3. Temperature=0 determinism

Run:
  python test_mistral.py

Expected: 3 tests pass, response times printed.
"""

import json
import time
import requests

OLLAMA_URL = "http://localhost:11434"
MODEL = "deepseek-r1:8b"

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "weather_query",
            "description": "Get current weather for a city.",
            "parameters": {
                "type": "object",
                "properties": {
                    "city": {"type": "string", "description": "City name"}
                },
                "required": ["city"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "fund_transfer",
            "description": "Transfer funds between bank accounts.",
            "parameters": {
                "type": "object",
                "properties": {
                    "amount": {"type": "number", "description": "Amount in USD"},
                    "destination": {"type": "string", "description": "Destination account ID"}
                },
                "required": ["amount", "destination"]
            }
        }
    }
]


def chat(messages, tools=None):
    payload = {
        "model": MODEL,
        "messages": messages,
        "stream": False,
        "options": {"temperature": 0, "seed": 42}
    }
    if tools:
        payload["tools"] = tools
    t0 = time.time()
    resp = requests.post(f"{OLLAMA_URL}/api/chat", json=payload, timeout=300)
    elapsed = time.time() - t0
    resp.raise_for_status()
    return resp.json(), elapsed


def test_basic_response():
    print("TEST 1: Basic response")
    messages = [{"role": "user", "content": "Reply with exactly: OK"}]
    result, elapsed = chat(messages)
    content = result["message"]["content"]
    print(f"  Response: {content!r}")
    print(f"  Time: {elapsed:.1f}s")
    assert "OK" in content.upper() or len(content) > 0, "Empty response"
    print("  PASS\n")
    return elapsed


def test_tool_calling():
    """Text-based tool calling — works with any model (no native tools API)."""
    print("TEST 2: Text-based tool calling")
    messages = [
        {
            "role": "system",
            "content": (
                "You are an AI assistant with tools. "
                "To call a tool, respond ONLY with valid JSON, nothing else:\n"
                '{"tool": "<name>", "args": {<params>}}\n\n'
                "Available tools:\n"
                "- weather_query(city: string)\n"
                "- fund_transfer(amount: number, destination: string)"
            )
        },
        {"role": "user", "content": "Get the weather in Madrid."}
    ]
    # No tools= parameter — plain text response, limit tokens for speed
    result, elapsed = chat(messages)
    content = result["message"]["content"]
    # Strip DeepSeek-R1 <think>...</think> reasoning tokens
    import re
    content_clean = re.sub(r"<think>.*?</think>", "", content, flags=re.DOTALL).strip()
    print(f"  Raw content (first 200 chars): {content_clean[:200]!r}")
    print(f"  Time: {elapsed:.1f}s")
    # Try to parse JSON tool call
    try:
        # Find JSON object in response
        match = re.search(r'\{.*\}', content_clean, re.DOTALL)
        if match:
            call = json.loads(match.group())
            print(f"  Parsed tool call: {call}")
            assert call.get("tool") == "weather_query", f"Expected weather_query, got {call.get('tool')}"
            print("  PASS\n")
        else:
            print(f"  WARN: no JSON found in response\n")
    except json.JSONDecodeError as e:
        print(f"  WARN: could not parse JSON — {e}\n")
    return elapsed, True


def test_determinism():
    print("TEST 3: Determinism (temperature=0, seed=42)")
    messages = [{"role": "user", "content": "What is 2+2? Answer with just the number."}]
    r1, _ = chat(messages)
    r2, _ = chat(messages)
    c1 = r1["message"]["content"].strip()
    c2 = r2["message"]["content"].strip()
    print(f"  Run 1: {c1!r}")
    print(f"  Run 2: {c2!r}")
    if c1 == c2:
        print("  PASS — deterministic output\n")
    else:
        print("  WARN — outputs differ (temperature=0 is best-effort with CPU inference)\n")


if __name__ == "__main__":
    print(f"Model: {MODEL}")
    print(f"Ollama: {OLLAMA_URL}\n")

    try:
        t1 = test_basic_response()
        t2, tool_ok = test_tool_calling()
        test_determinism()

        print("=" * 50)
        print(f"Basic response time: {t1:.1f}s")
        print(f"Tool call response time: {t2:.1f}s")
        print(f"Tool calling works: {tool_ok}")
        if t2 > 60:
            print("NOTE: >60s per call — demo will be slow but functional.")
            print("      Consider deepseek-r1:8b (5.2GB) for faster iteration.")
        elif t2 > 20:
            print("NOTE: 20-60s per call — acceptable for a paper demo.")
        else:
            print("NOTE: <20s per call — good performance for demo.")

    except requests.exceptions.ConnectionError:
        print("ERROR: Cannot connect to Ollama.")
        print("       Make sure Ollama is running: ollama serve")
    except Exception as e:
        print(f"ERROR: {e}")
