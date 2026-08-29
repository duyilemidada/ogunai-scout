# engine/ogunai/memory_rag.py
"""
Lightweight RAG Layer for OgunAI Scout

Stores past findings as embeddings in ChromaDB (embedded, no server).
On each new session, retrieves semantically similar findings from previous
audits — across all clients — and injects them into the agent's context.

This gives the agent cross-client learning:
"Past audits of similar APIs found X, Y, Z — check these first."

Architecture decisions:
- ChromaDB in embedded mode: zero infrastructure, single directory on disk
- all-MiniLM-L6-v2: 80MB, CPU-only, ~50ms inference, good semantic quality
- Graceful degradation: if either package is missing, everything silently skips
- ChromaDB dir: ./chroma_db in dev, /tmp/chroma_db on Render (ephemeral but
  still useful within a container's lifetime across multiple sessions)

Render free tier caveat: /tmp persists across requests but resets on redeploy.
This means cross-session RAG works within a deployment but not across deploys.
For the portfolio use case this is fine. For production: mount a persistent disk
and point CHROMA_DIR at it.
"""

import os
import hashlib
import json
from typing import List, Dict, Any, Optional

from .config import get_config

# ChromaDB persist directory — configurable via env
CHROMA_DIR = os.getenv(
    "CHROMA_DIR",
    "/tmp/chroma_db" if os.getenv("ENVIRONMENT") == "production" else "./chroma_db"
)

COLLECTION_NAME = "ogunai_findings"

# These are loaded lazily so import failures don't crash the whole engine
_chroma_client = None
_collection = None
_embedder = None
_rag_available = None  # None = not yet checked, True/False = checked


def _init_rag() -> bool:
    """
    Lazy initialisation of ChromaDB and sentence-transformers.
    Returns True if RAG is available, False if packages are missing.
    Subsequent calls return the cached result immediately.
    """
    global _chroma_client, _collection, _embedder, _rag_available

    if _rag_available is not None:
        return _rag_available

    try:
        import chromadb
        from chromadb.utils import embedding_functions

        # Embedded ChromaDB — no server, persists to local directory
        os.makedirs(CHROMA_DIR, exist_ok=True)
        _chroma_client = chromadb.PersistentClient(path=CHROMA_DIR)

        # sentence-transformers embedding function built into ChromaDB
        # all-MiniLM-L6-v2: 80MB, CPU-friendly, 384-dimensional embeddings
        ef = embedding_functions.SentenceTransformerEmbeddingFunction(
            model_name="all-MiniLM-L6-v2"
        )

        # Get or create the findings collection
        _collection = _chroma_client.get_or_create_collection(
            name=COLLECTION_NAME,
            embedding_function=ef,
            metadata={"hnsw:space": "cosine"}  # cosine similarity for text
        )

        _rag_available = True
        print(f"[RAG] Initialized — ChromaDB at {CHROMA_DIR}, "
              f"{_collection.count()} findings in store")
        return True

    except ImportError as e:
        print(f"[RAG] Unavailable — missing package: {e}. "
              f"Install: pip install chromadb sentence-transformers")
        _rag_available = False
        return False
    except Exception as e:
        print(f"[RAG] Init failed: {e}")
        _rag_available = False
        return False


def _finding_id(finding: Dict[str, Any], client_name: str) -> str:
    """
    Generate a stable unique ID for a finding.
    Same finding detected in the same client on different sessions gets the
    same ID — this prevents duplicate embeddings and allows upsert behaviour.
    """
    key = f"{client_name}|{finding.get('attack_family', '')}|{finding.get('title', '')}"
    return hashlib.md5(key.encode()).hexdigest()


def _finding_to_document(finding: Dict[str, Any]) -> str:
    """
    Convert a finding dict to a single text string for embedding.
    Concatenating title + description + recommendation gives the embedder
    the most semantic signal to work with.
    """
    parts = [
        finding.get("title", ""),
        finding.get("description", ""),
        finding.get("recommendation", ""),
    ]
    return " | ".join(p for p in parts if p)


def store_findings(findings: List[Dict[str, Any]], client_name: str) -> None:
    """
    Store a list of findings in the vector store after a completed session.

    Uses upsert semantics: if the same finding ID already exists (same client,
    same attack family, same title), it updates rather than duplicating.

    Args:
        findings: List of finding dicts from write_finding()
        client_name: Name of the audited client
    """
    if not findings:
        return

    if not _init_rag():
        return

    try:
        ids = []
        documents = []
        metadatas = []

        for finding in findings:
            fid = _finding_id(finding, client_name)
            doc = _finding_to_document(finding)

            if not doc.strip():
                continue

            ids.append(fid)
            documents.append(doc)
            metadatas.append({
                "client_name": client_name,
                "attack_family": finding.get("attack_family", "UNKNOWN"),
                "severity": finding.get("severity", "LOW"),
                "title": finding.get("title", "")[:200],  # ChromaDB metadata size limit
                "endpoint": finding.get("endpoint", "")[:200],
                "recommendation": finding.get("recommendation", "")[:400],
            })

        if ids:
            _collection.upsert(ids=ids, documents=documents, metadatas=metadatas)
            print(f"[RAG] Stored {len(ids)} findings for '{client_name}' "
                  f"(total in store: {_collection.count()})")

    except Exception as e:
        print(f"[RAG] Could not store findings: {e}")


def query_similar_findings(
    query_text: str,
    n_results: int = 5,
    exclude_client: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Find past findings semantically similar to the query text.

    Args:
        query_text: Description of what to search for
        n_results: Maximum number of results to return
        exclude_client: Optionally exclude findings from a specific client
                       (useful to avoid showing a client their own past findings
                        when you want cross-client learning only)

    Returns:
        List of dicts with keys: title, attack_family, severity, client_name,
        recommendation, distance (lower = more similar)
    """
    if not _init_rag():
        return []

    try:
        total = _collection.count()
        if total == 0:
            return []

        # Can't return more results than exist
        actual_n = min(n_results, total)

        where_filter = None
        if exclude_client:
            where_filter = {"client_name": {"$ne": exclude_client}}

        results = _collection.query(
            query_texts=[query_text],
            n_results=actual_n,
            where=where_filter,
            include=["documents", "metadatas", "distances"]
        )

        findings = []
        metadatas = results.get("metadatas", [[]])[0]
        distances = results.get("distances", [[]])[0]

        for meta, dist in zip(metadatas, distances):
            # Only include genuinely similar results (cosine distance < 0.5)
            # Distance 0 = identical, 1 = completely dissimilar, 2 = opposite
            if dist < 0.5:
                findings.append({
                    "title": meta.get("title", ""),
                    "attack_family": meta.get("attack_family", ""),
                    "severity": meta.get("severity", ""),
                    "client_name": meta.get("client_name", ""),
                    "recommendation": meta.get("recommendation", ""),
                    "similarity_distance": round(dist, 3),
                })

        return findings

    except Exception as e:
        print(f"[RAG] Query failed: {e}")
        return []


def get_rag_context(client_name: str, target_type: str = "full_spectrum") -> str:
    """
    Build the RAG context string to inject into the agent's system prompt.

    Runs multiple targeted queries to retrieve the most relevant past findings
    across different attack categories. Returns a formatted string ready for
    injection into the LLM context.

    Args:
        client_name: Current client being audited
        target_type: Type of target (full_spectrum, ml_only, etc.)

    Returns:
        Formatted string of past findings, or empty string if none found
    """
    if not _init_rag():
        return ""

    if _collection.count() == 0:
        return ""

    # Run targeted queries for each major attack family
    # This gives better recall than a single generic query
    queries = [
        f"security header misconfiguration HTTP {target_type} API",
        f"email spoofing SPF DMARC DNS configuration {target_type}",
        f"rate limiting brute force protection {target_type} API endpoint",
        f"sensitive path exposed credentials environment file {target_type}",
        f"SSL TLS certificate CORS cross-origin policy {target_type}",
        f"information disclosure version leakage error response {target_type}",
        f"dependency vulnerability CVE outdated package {target_type}",
    ]

    seen_titles = set()
    all_findings = []

    for query in queries:
        results = query_similar_findings(
            query_text=query,
            n_results=2,  # 2 per query × 7 queries = up to 14 candidates
            exclude_client=None  # Include all clients for cross-client learning
        )
        for f in results:
            # Deduplicate by title
            if f["title"] not in seen_titles:
                seen_titles.add(f["title"])
                all_findings.append(f)

    if not all_findings:
        return ""

    # Format for injection into system prompt
    lines = [
        f"Past findings from {len(set(f['client_name'] for f in all_findings))} "
        f"previously audited system(s) — use these to prioritise checks and "
        f"avoid re-detecting issues you have already seen:\n"
    ]

    # Group by severity for readability
    by_severity = {"HIGH": [], "MEDIUM": [], "LOW": [], "CRITICAL": []}
    for f in all_findings:
        sev = f.get("severity", "LOW")
        by_severity.get(sev, by_severity["LOW"]).append(f)

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        items = by_severity[sev]
        if not items:
            continue
        lines.append(f"\n{sev} severity findings seen before:")
        for f in items:
            lines.append(
                f"  - [{f['attack_family']}] {f['title']} "
                f"(seen in: {f['client_name']})"
            )
            if f.get("recommendation"):
                # Truncate recommendation for context brevity
                rec = f["recommendation"][:150]
                lines.append(f"    Fix: {rec}{'...' if len(f['recommendation']) > 150 else ''}")

    context = "\n".join(lines)
    print(f"[RAG] Injected context: {len(all_findings)} past findings across "
          f"{len(queries)} query domains")
    return context


def rebuild_from_session_data(sessions_data: List[Dict[str, Any]]) -> int:
    """
    Rebuild the vector store from session findings data.

    Call this at startup if the ChromaDB directory was wiped (e.g., Render
    redeploy). Pass in the findings you load from your SQLite database.

    Args:
        sessions_data: List of dicts: [{"client_name": str, "findings": [...]}]

    Returns:
        Number of findings stored
    """
    if not _init_rag():
        return 0

    count = 0
    for session in sessions_data:
        client = session.get("client_name", "unknown")
        findings = session.get("findings", [])
        if findings:
            store_findings(findings, client)
            count += len(findings)

    print(f"[RAG] Rebuilt vector store with {count} findings from database")
    return count