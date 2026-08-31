# engine/ogunai/memory_rag.py
"""
Lightweight RAG using sentence-transformers + numpy.

No ChromaDB. No compilation. No servers.
Embeddings stored in a JSON file alongside the existing agent_memory.json.
Retrieval via cosine similarity with numpy.

Why this works better than ChromaDB for our scale:
- At 10-100 findings, a linear scan with numpy is instant (~1ms)
- ChromaDB's HNSW index only pays off at tens of thousands of vectors
- Zero compilation, zero infrastructure, works on Windows/Linux/Render
- The JSON store is human-readable and easy to inspect/debug
"""

import os
import json
import hashlib
from typing import List, Dict, Any, Optional
from pathlib import Path

from .config import get_config

# Store embeddings next to the memory file
MEMORY_FILE = get_config("memory_file", "./agent_memory.json")
VECTOR_STORE_PATH = str(Path(MEMORY_FILE).parent / "agent_vectors.json")

# Lazy-loaded globals — initialised on first use
_embedder = None
_rag_available = None  # None = not checked, True/False = result


def _init_rag() -> bool:
    """
    Lazy init of sentence-transformers.
    Returns True if available, False if not installed.
    Subsequent calls return the cached result immediately.
    """
    global _embedder, _rag_available

    if _rag_available is not None:
        return _rag_available

    try:
        from sentence_transformers import SentenceTransformer
        # all-MiniLM-L6-v2: 80MB, CPU-only, 384-dim, fast enough for our scale
        _embedder = SentenceTransformer("all-MiniLM-L6-v2")
        _rag_available = True

        store = _load_store()
        print(
            f"[RAG] Initialized — sentence-transformers (all-MiniLM-L6-v2), "
            f"{len(store.get('findings', []))} findings in vector store"
        )
        return True

    except ImportError:
        print("[RAG] Unavailable — sentence-transformers not installed. "
              "Run: pip install sentence-transformers")
        _rag_available = False
        return False
    except Exception as e:
        print(f"[RAG] Init failed: {e}")
        _rag_available = False
        return False


# ── Vector store (JSON on disk) ───────────────────────────────────────────────

def _load_store() -> Dict[str, Any]:
    """Load the vector store from disk. Returns empty store if not found."""
    if os.path.exists(VECTOR_STORE_PATH):
        try:
            with open(VECTOR_STORE_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            pass
    return {"findings": []}


def _save_store(store: Dict[str, Any]) -> None:
    """Atomically write the vector store to disk."""
    temp = VECTOR_STORE_PATH + ".tmp"
    try:
        with open(temp, "w", encoding="utf-8") as f:
            json.dump(store, f, ensure_ascii=False)
        os.replace(temp, VECTOR_STORE_PATH)
    except IOError as e:
        print(f"[RAG] Could not save vector store: {e}")


def _cosine_similarity(a: List[float], b: List[float]) -> float:
    """Cosine similarity between two vectors using only stdlib + basic math."""
    try:
        import numpy as np
        va, vb = np.array(a), np.array(b)
        denom = np.linalg.norm(va) * np.linalg.norm(vb)
        if denom == 0:
            return 0.0
        return float(np.dot(va, vb) / denom)
    except ImportError:
        # Pure Python fallback (slower but dependency-free)
        dot = sum(x * y for x, y in zip(a, b))
        norm_a = sum(x * x for x in a) ** 0.5
        norm_b = sum(x * x for x in b) ** 0.5
        denom = norm_a * norm_b
        return dot / denom if denom > 0 else 0.0


def _finding_id(finding: Dict[str, Any], client_name: str) -> str:
    """Stable ID for a finding — same finding in same client = same ID."""
    key = f"{client_name}|{finding.get('attack_family', '')}|{finding.get('title', '')}"
    return hashlib.md5(key.encode()).hexdigest()


def _finding_to_text(finding: Dict[str, Any]) -> str:
    """Convert finding to embeddable text. Title + description + recommendation."""
    parts = [
        finding.get("title", ""),
        finding.get("description", ""),
        finding.get("recommendation", ""),
    ]
    return " | ".join(p for p in parts if p)


# ── Public API ────────────────────────────────────────────────────────────────

def store_findings(findings: List[Dict[str, Any]], client_name: str) -> None:
    """
    Embed and store a list of findings after a completed session.
    Uses upsert: same finding_id → update, not duplicate.
    """
    if not findings or not _init_rag():
        return

    store = _load_store()
    existing_ids = {item["id"] for item in store["findings"]}
    added = 0

    for finding in findings:
        fid = _finding_id(finding, client_name)
        text = _finding_to_text(finding)
        if not text.strip():
            continue

        try:
            vector = _embedder.encode(text).tolist()
        except Exception as e:
            print(f"[RAG] Embedding failed for '{finding.get('title')}': {e}")
            continue

        entry = {
            "id": fid,
            "client_name": client_name,
            "attack_family": finding.get("attack_family", "UNKNOWN"),
            "severity": finding.get("severity", "LOW"),
            "title": finding.get("title", "")[:200],
            "endpoint": finding.get("endpoint", "")[:200],
            "recommendation": finding.get("recommendation", "")[:400],
            "text": text,
            "vector": vector,
        }

        if fid in existing_ids:
            # Update in place
            store["findings"] = [
                entry if item["id"] == fid else item
                for item in store["findings"]
            ]
        else:
            store["findings"].append(entry)
            existing_ids.add(fid)
            added += 1

    _save_store(store)
    print(
        f"[RAG] Stored {added} new findings for '{client_name}' "
        f"(total: {len(store['findings'])})"
    )


def query_similar_findings(
    query_text: str,
    n_results: int = 5,
    exclude_client: Optional[str] = None,
    min_similarity: float = 0.5,
) -> List[Dict[str, Any]]:
    """
    Find past findings semantically similar to query_text.

    Args:
        query_text: What to search for
        n_results: Max results to return
        exclude_client: Skip findings from this client (for cross-client only)
        min_similarity: Cosine similarity threshold (0–1). 0.5 is reasonable.

    Returns:
        List of finding dicts sorted by similarity (highest first).
    """
    if not _init_rag():
        return []

    store = _load_store()
    candidates = store.get("findings", [])

    if not candidates:
        return []

    if exclude_client:
        candidates = [c for c in candidates if c.get("client_name") != exclude_client]

    if not candidates:
        return []

    try:
        query_vector = _embedder.encode(query_text).tolist()
    except Exception as e:
        print(f"[RAG] Query embedding failed: {e}")
        return []

    # Score all candidates
    scored = []
    for item in candidates:
        vec = item.get("vector")
        if not vec:
            continue
        sim = _cosine_similarity(query_vector, vec)
        if sim >= min_similarity:
            scored.append({
                "title": item.get("title", ""),
                "attack_family": item.get("attack_family", ""),
                "severity": item.get("severity", ""),
                "client_name": item.get("client_name", ""),
                "recommendation": item.get("recommendation", ""),
                "similarity": round(sim, 3),
            })

    # Sort by similarity descending and cap
    scored.sort(key=lambda x: x["similarity"], reverse=True)
    return scored[:n_results]


def get_rag_context(client_name: str, target_type: str = "full_spectrum") -> str:
    """
    Build RAG context string for injection into the agent's system prompt.
    Runs multiple targeted queries for better recall across attack families.
    """
    if not _init_rag():
        return ""

    store = _load_store()
    if not store.get("findings"):
        return ""

    queries = [
        f"security header misconfiguration HTTP {target_type} API",
        f"email spoofing SPF DMARC DNS missing record {target_type}",
        f"rate limiting brute force protection endpoint {target_type}",
        f"sensitive path exposed credentials environment {target_type}",
        f"SSL TLS certificate CORS cross-origin policy {target_type}",
        f"information disclosure version error stack trace {target_type}",
        f"dependency vulnerability CVE outdated package {target_type}",
    ]

    seen_titles: set = set()
    all_findings: List[Dict[str, Any]] = []

    for query in queries:
        results = query_similar_findings(
            query_text=query,
            n_results=2,
            min_similarity=0.45,  # slightly lower per-query to improve recall
        )
        for f in results:
            if f["title"] not in seen_titles:
                seen_titles.add(f["title"])
                all_findings.append(f)

    if not all_findings:
        return ""

    unique_clients = len(set(f["client_name"] for f in all_findings))
    lines = [
        f"Past findings from {unique_clients} previously audited system(s). "
        f"Use these as starting hypotheses — check if they apply here:\n"
    ]

    by_severity: Dict[str, List] = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
    for f in all_findings:
        by_severity.get(f.get("severity", "LOW"), by_severity["LOW"]).append(f)

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        items = by_severity[sev]
        if not items:
            continue
        lines.append(f"\n{sev} findings seen in similar systems:")
        for f in items:
            lines.append(f"  - [{f['attack_family']}] {f['title']} "
                         f"(seen in: {f['client_name']}, similarity: {f['similarity']})")
            if f.get("recommendation"):
                rec = f["recommendation"][:150]
                lines.append(f"    Fix: {rec}{'...' if len(f['recommendation']) > 150 else ''}")

    context = "\n".join(lines)
    print(f"[RAG] Injected context: {len(all_findings)} findings "
          f"from {unique_clients} client(s)")
    return context


def rebuild_from_session_data(sessions_data: List[Dict[str, Any]]) -> int:
    """
    Rebuild the vector store from session findings loaded from SQLite.
    Call at startup after a Render redeploy wipes /tmp.
    """
    if not _init_rag():
        return 0

    # Clear existing store
    _save_store({"findings": []})

    count = 0
    for session in sessions_data:
        client = session.get("client_name", "unknown")
        findings = session.get("findings", [])
        if findings:
            store_findings(findings, client)
            count += len(findings)

    print(f"[RAG] Rebuilt vector store: {count} findings")
    return count