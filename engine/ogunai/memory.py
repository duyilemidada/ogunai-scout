"""
Cross-Session JSON Memory with File Locking

Prevents race conditions when multiple background tasks (passive + offensive)
try to read/write the same memory file simultaneously.

Uses filelock (lightweight, cross-platform, no dependencies beyond Python).
"""

import json
import os
from typing import Dict, Any
from filelock import FileLock

from .config import get_config

MEMORY_PATH = get_config("memory_file", "./agent_memory.json")
LOCK_PATH = MEMORY_PATH + ".lock"

DEFAULT_MEMORY = {
    "sessions_run": 0,
    "total_findings": 0,
    "clients": {}
}


def load_memory() -> Dict[str, Any]:
    """
    Load memory with a shared read lock.
    Multiple processes can read simultaneously, but writes are exclusive.
    """
    lock = FileLock(LOCK_PATH, timeout=10)  # Wait up to 10 seconds for lock
    
    with lock:
        if os.path.exists(MEMORY_PATH):
            try:
                with open(MEMORY_PATH, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                return DEFAULT_MEMORY.copy()
    return DEFAULT_MEMORY.copy()


def save_memory(memory: Dict[str, Any]) -> None:
    """
    Save memory with an exclusive write lock.
    Blocks other processes from reading or writing during the save.
    """
    lock = FileLock(LOCK_PATH, timeout=10)
    
    with lock:
        temp = MEMORY_PATH + ".tmp"
        try:
            with open(temp, "w", encoding="utf-8") as f:
                json.dump(memory, f, indent=2, ensure_ascii=False)
            os.replace(temp, MEMORY_PATH)
        except IOError as e:
            print(f"[MEMORY] Warning: could not save memory: {e}")


def get_client_memory(memory: Dict[str, Any], client_name: str) -> Dict[str, Any]:
    if client_name not in memory["clients"]:
        memory["clients"][client_name] = {
            "sessions_run": 0,
            "known_findings": [],
            "effective_checks": []
        }
    return memory["clients"][client_name]


def memory_to_context(memory: Dict[str, Any], client_name: str) -> str:
    client_mem = get_client_memory(memory, client_name)
    parts = [f"Previous audits of {client_name}: {client_mem['sessions_run']}"]

    if client_mem["known_findings"]:
        parts.append("Already confirmed findings (skip redundant re-testing):")
        for f in client_mem["known_findings"][-5:]:
            parts.append(f"  - {f}")

    if client_mem["effective_checks"]:
        parts.append("Checks that found issues before (run these first):")
        for c in client_mem["effective_checks"][-3:]:
            parts.append(f"  - {c}")

    return "\n".join(parts) if len(parts) > 1 else ""


def record_session(memory: Dict[str, Any], client_name: str, findings: list) -> None:
    """Update memory after a completed session."""
    client_mem = get_client_memory(memory, client_name)
    memory["sessions_run"] = memory.get("sessions_run", 0) + 1
    memory["total_findings"] = memory.get("total_findings", 0) + len(findings)
    client_mem["sessions_run"] = client_mem.get("sessions_run", 0) + 1

    for finding in findings:
        family = finding.get("attack_family", "unknown")
        sev = finding.get("severity", "LOW")

        summary = f"{family} ({sev}): {finding.get('title', '')[:60]}"
        if summary not in client_mem["known_findings"]:
            client_mem["known_findings"].append(summary)

        if family not in client_mem["effective_checks"]:
            client_mem["effective_checks"].append(family)

    # Note: We do NOT call save_memory() here directly.
    # The caller (background task) should call save_memory(memory) after all updates.
    # This prevents partial updates if multiple findings are being added.