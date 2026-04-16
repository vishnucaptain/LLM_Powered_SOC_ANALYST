import os
import re
import sqlite3
from typing import Any, Optional


_embedding: Optional[Any] = None
_vector_db: Optional[Any] = None


def _project_root() -> str:
    # backend/rag/rag_engine.py -> backend/rag -> backend -> project root
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _resolve_persist_directory() -> str:
    """Resolve Chroma persist dir, defaulting to project-root vector_db."""
    raw_dir = (os.getenv("RAG_VECTOR_DB_DIR") or "vector_db").strip()
    base = _project_root()

    candidate = raw_dir if os.path.isabs(raw_dir) else os.path.join(base, raw_dir)

    # If caller passed a bad relative path, fall back to canonical project vector_db.
    if not os.path.exists(candidate):
        fallback = os.path.join(base, "vector_db")
        if os.path.exists(fallback):
            return fallback

    return candidate


def _sqlite_db_path() -> str:
    return os.path.join(_resolve_persist_directory(), "chroma.sqlite3")


def _retrieve_context_sqlite(query: str, k: int = 3) -> str:
    """
    Fallback retrieval directly from Chroma SQLite FTS index.
    This guarantees we can still read persisted context from vector_db.
    """
    db_path = _sqlite_db_path()
    if not os.path.exists(db_path):
        return ""

    # Build a simple FTS query: word1 OR word2 OR ...
    tokens = re.findall(r"[A-Za-z0-9_.-]+", query or "")
    tokens = [t for t in tokens if len(t) > 1][:10]
    if not tokens:
        return ""
    fts_query = " OR ".join(tokens)

    try:
        con = sqlite3.connect(db_path)
        cur = con.cursor()
        rows = cur.execute(
            """
            SELECT string_value
            FROM embedding_fulltext_search
            WHERE embedding_fulltext_search MATCH ?
            LIMIT ?
            """,
            (fts_query, max(1, int(k))),
        ).fetchall()
        con.close()
    except Exception:
        return ""

    snippets = [r[0] for r in rows if r and r[0]]
    return "\n\n".join(snippets)


def _get_vector_db() -> Any:
    """Lazily initialize Chroma so import-time failures don't break the API."""
    global _embedding, _vector_db
    if _vector_db is not None:
        return _vector_db

    embedding_model = os.getenv("RAG_EMBEDDING_MODEL", "sentence-transformers/all-MiniLM-L6-v2")
    persist_directory = _resolve_persist_directory()

    # Imported lazily so missing optional deps don't crash at module import time.
    from langchain_community.vectorstores import Chroma
    from langchain_huggingface import HuggingFaceEmbeddings

    _embedding = HuggingFaceEmbeddings(model_name=embedding_model)
    _vector_db = Chroma(
        persist_directory=persist_directory,
        embedding_function=_embedding,
    )
    return _vector_db


def retrieve_context(query: str, k: int = 3) -> str:
    """Retrieve top-k RAG passages. Returns empty context on retrieval failure."""
    cleaned_query = (query or "").strip()
    if not cleaned_query:
        return ""

    try:
        vector_db = _get_vector_db()
        results = vector_db.similarity_search(cleaned_query, k=max(1, int(k)))
        context = "\n\n".join(
            doc.page_content for doc in results if getattr(doc, "page_content", None)
        )
        if context.strip():
            return context
    except Exception:
        pass

    # Guaranteed persisted-db fallback path.
    return _retrieve_context_sqlite(cleaned_query, k=max(1, int(k)))