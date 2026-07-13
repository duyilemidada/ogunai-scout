# engine/ogunai/agent.py
"""
OgunAI ReAct Agent Loop

The brain of the engine. Implements ReAct (Reasoning + Acting):
1. THINK: LLM reads current state and decides what to do
2. ACT: call a registered tool
3. OBSERVE: feed tool result back to LLM
4. REPEAT until all checks done or max iterations reached

Tools are registered via register_tool() before creating an agent.
The agent loop itself is tool-agnostic — it calls whatever is registered.
"""

import json
import re
import time
from typing import Dict, Any, List, Optional, Tuple

from .llm_adapter import BaseLLMAdapter, get_default_adapter
from .config import ENGINE_CONFIG, get_config
from .memory import load_memory, memory_to_context, record_session
from .prompts import build_system_prompt, ITERATION_PROMPT_TEMPLATE
from .report import generate_markdown_report, save_report

# ═══════════════════════════════════════════════════════════════════
# TOOL IMPORTS (imported here so register_tool() can use them below)
# ═══════════════════════════════════════════════════════════════════

from .tools_passive import (
    check_security_headers,
    scan_sensitive_paths,
    check_ssl_tls,
    check_dns_email_security,
    check_cors_policy,
    check_rate_limiting,
    check_information_disclosure,
    scan_dependencies,
    write_finding,
)




# ── Tool Registry ─────────────────────────────────────────────────────────────

_TOOL_REGISTRY: Dict[str, Any] = {}


def register_tool(name: str, func) -> None:
    """Register a callable tool by name. Called before creating an OgunAIAgent."""
    _TOOL_REGISTRY[name] = func


def list_tools() -> List[str]:
    return list(_TOOL_REGISTRY.keys())


# ── Response Parsing ──────────────────────────────────────────────────────────

def parse_tool_call(text: str) -> Tuple[Optional[str], Optional[Dict]]:
    """
    Extract tool name and args from the LLM's response.

    The LLM is instructed to output:
        <tool_call>{"tool": "name", "args": {"k": "v"}}</tool_call>

    Returns (tool_name, args_dict) or (None, None) if no call found.
    """
    match = re.search(r'<tool_call>\s*(\{.*?\})\s*</tool_call>', text, re.DOTALL)
    if not match:
        return None, None
    try:
        data = json.loads(match.group(1).strip())
        return data.get("tool"), data.get("args", {})
    except json.JSONDecodeError:
        return None, None


def parse_thought(text: str) -> Optional[str]:
    """Extract the <thought>...</thought> block for logging."""
    match = re.search(r'<thought>\s*(.*?)\s*</thought>', text, re.DOTALL)
    return match.group(1).strip() if match else None


# ── The Agent ─────────────────────────────────────────────────────────────────

class OgunAIAgent:
    """
    Single-agent ReAct loop. One LLM, one set of tools, one audit.

    No orchestration. No role specialization. No multi-agent.
    The same LLM reads the passive tool results and writes findings.
    Simple, debuggable, works on your hardware.
    """
    
    def __init__(self, profile: Dict[str, Any], llm: Optional[BaseLLMAdapter] = None):
        self.profile = profile.copy()
        self.llm = llm or get_default_adapter()

        self.system_prompt = build_system_prompt(profile)
        self.history: List[Dict[str, str]] = []

        self.attack_count = 0
        self.finding_count = 0
        self.last_action = "none"
        self.last_result = "none"
        self.findings: List[Dict[str, Any]] = []

        self.max_iterations = get_config("max_iterations", 20)

        # Load memory from previous sessions
        self.memory = load_memory()
        client_name = profile.get("client_name", "unknown")
        memory_context = memory_to_context(self.memory, client_name)
        if memory_context:
            self.profile["_memory_context"] = memory_context

        print(f"[AGENT] Initialized — LLM: {self.llm.get_model_info()['model']}")
        print(f"[AGENT] Tools: {list_tools()}")

    def _build_messages(self, iteration_prompt: str) -> List[Dict[str, str]]:
        """
        Build the full message list for the LLM:
        1. System prompt (permanent instructions + memory context)
        2. Conversation history (all previous iterations)
        3. Current iteration prompt (what to do now)
        """
        messages = [{"role": "system", "content": self.system_prompt}]

        memory_context = self.profile.get("_memory_context")
        if memory_context:
            messages.append({
                "role": "system",
                "content": f"MEMORY FROM PREVIOUS AUDITS:\n{memory_context}\n\n"
                           f"Use this to avoid re-testing confirmed findings."
            })

        messages.extend(self.history)
        messages.append({"role": "user", "content": iteration_prompt})
        return messages

    def step(self) -> bool:
        """
        One iteration of the ReAct loop.
        Returns True to continue, False when done.
        """
        if self.attack_count >= self.max_iterations:
            print(f"[AGENT] Max iterations ({self.max_iterations}) reached.")
            return False

        iteration_prompt = ITERATION_PROMPT_TEMPLATE.format(
            attack_count=self.attack_count,
            finding_count=self.finding_count,
            last_action=self.last_action,
            last_result=self.last_result[:400]
        )

        messages = self._build_messages(iteration_prompt)
        print(f"\n[ITERATION {self.attack_count + 1}/{self.max_iterations}]")

        # Call LLM
        try:
            response = self.llm.invoke(
                messages,
                temperature=get_config("temperature_plan", 0.4)
            )
        except Exception as e:
            print(f"[ERROR] LLM call failed: {e}")
            self.last_result = f"LLM error: {e}"
            self.attack_count += 1
            return True

        # Log reasoning
        thought = parse_thought(response)
        if thought:
            print(f"[THOUGHT] {thought[:300]}")

        # Add to history
        self.history.append({"role": "user", "content": iteration_prompt})
        self.history.append({"role": "assistant", "content": response})

        # Check for completion signal
        done_phrases = ["audit complete", "all checks done", "all tools tested", "session complete"]
        if any(p in response.lower() for p in done_phrases):
            print("[AGENT] Completion signal detected.")
            return False

        # Parse and execute tool call
        tool_name, args = parse_tool_call(response)

        if tool_name is None:
            self.last_result = "No tool call detected. Please call a tool."
            self.last_action = "none"
            return True

        if tool_name not in _TOOL_REGISTRY:
            self.last_result = f"Unknown tool: {tool_name}. Available: {list_tools()}"
            return True

        print(f"[TOOL] {tool_name}({json.dumps(args)[:150]})")

        try:
            result = _TOOL_REGISTRY[tool_name](**args)
        except Exception as e:
            result = {"error": f"{type(e).__name__}: {str(e)}"}

        result_str = json.dumps(result, indent=2)
        print(f"[RESULT] {result_str[:300]}")

        # Feed result back
        self.history.append({
            "role": "user",
            "content": f"Tool result for {tool_name}:\n{result_str}"
        })

        self.attack_count += 1
        self.last_action = f"{tool_name}({json.dumps(args)[:80]})"
        self.last_result = result_str[:400]

        if tool_name == "write_finding":
            self.finding_count += 1
            self.findings.append(result)

        return True

    def run(self) -> Dict[str, Any]:
        """Run the complete audit loop and return results."""
        client_name = self.profile.get("client_name", "unknown")
        print("=" * 60)
        print(f"OgunAI Passive Security Audit")
        print(f"Client: {client_name}")
        print(f"Target: {self.profile.get('api_url', 'unknown')}")
        print("=" * 60)

        start = time.time()
        try:
            while True:
                if not self.step():
                    break
                time.sleep(get_config("request_delay_seconds", 1.0))
        except KeyboardInterrupt:
            print("\n[AGENT] Interrupted.")
        except Exception as e:
            print(f"\n[ERROR] Agent crashed: {e}")
            import traceback
            traceback.print_exc()

        elapsed = time.time() - start

        # Generate report
        report_path = None
        if self.findings:
            report_text = generate_markdown_report(
                findings=self.findings,
                target_url=self.profile.get("api_url", ""),
                client_name=client_name,
                session_metadata={"duration_seconds": elapsed}
            )
            report_path = save_report(report_text, client_name)

        # Update memory
        record_session(self.memory, client_name, self.findings)

        print(f"\n{'=' * 60}")
        print(f"AUDIT COMPLETE")
        print(f"Duration:   {elapsed:.0f}s ({elapsed / 60:.1f} min)")
        print(f"Iterations: {self.attack_count}")
        print(f"Findings:   {self.finding_count}")
        print(f"Report:     {report_path or 'none (no findings)'}")
        print("=" * 60)

        return {
            "client_name": client_name,
            "status": "completed",
            "iterations": self.attack_count,
            "findings_count": self.finding_count,
            "findings": self.findings,
            "report_path": report_path,
            "duration_seconds": elapsed
        }


# ═══════════════════════════════════════════════════════════════════
# TOOL REGISTRATION — Register all tools so the agent can call them
# ═══════════════════════════════════════════════════════════════════

# ── Passive tools ─────────────────────────────────────────────────
register_tool("check_security_headers", check_security_headers)
register_tool("scan_sensitive_paths", scan_sensitive_paths)
register_tool("check_ssl_tls", check_ssl_tls)
register_tool("check_dns_email_security", check_dns_email_security)
register_tool("check_cors_policy", check_cors_policy)
register_tool("check_rate_limiting", check_rate_limiting)
register_tool("check_information_disclosure", check_information_disclosure)
register_tool("scan_dependencies", scan_dependencies)
register_tool("write_finding", write_finding)

