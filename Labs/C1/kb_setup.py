"""
ISDO - Knowledge Base indexer and retrieval test.

1. Reads every .md file in data/kb/
2. Splits each article at level-2 headings (## ...) into chunks
3. Stores all chunks in a persistent ChromaDB collection called 'isdo_kb'
4. Runs 4 sample queries and prints the best-matching article + confidence

Only dependency: chromadb  (pip install chromadb)
Embeddings use ChromaDB's built-in default model (all-MiniLM-L6-v2, ONNX).
It is downloaded once (~80 MB) to ~/.cache/chroma on the first run.

Run from anywhere:  python Labs/C1/kb_setup.py
(finds data/kb by walking up from this script's folder)
"""

import re
from pathlib import Path

import chromadb

# --- Paths & settings ---------------------------------------------------------
def find_project_root(start: Path) -> Path:
    """Walk up from the script's folder until we find data/kb."""
    for folder in [start, *start.parents]:
        if (folder / "data" / "kb").is_dir():
            return folder
    raise FileNotFoundError(f"Could not find a data/kb folder above {start}")


BASE_DIR = find_project_root(Path(__file__).resolve().parent)
KB_DIR = BASE_DIR / "data" / "kb"
CHROMA_DIR = BASE_DIR / "data" / "chroma_db"
COLLECTION_NAME = "isdo_kb"

# Matches level-2 headings only ("## Symptoms"), not "#" or "### Step 1"
H2_PATTERN = re.compile(r"^##\s+(.+?)\s*$", re.MULTILINE)
TITLE_PATTERN = re.compile(r"^#\s+(.+?)\s*$", re.MULTILINE)


# --- 1 & 2: Read files and chunk at ## headings ------------------------------
def chunk_markdown(file_path: Path) -> list[dict]:
    """Split one markdown article into chunks at each '## ' heading.

    The text before the first '##' (title, category, tags) becomes an
    'Overview' chunk. The article title is prefixed to every chunk so each
    chunk still carries context when it is retrieved on its own.
    """
    text = file_path.read_text(encoding="utf-8")
    article = file_path.stem  # e.g. "vpn_troubleshooting"

    title_match = TITLE_PATTERN.search(text)
    title = title_match.group(1) if title_match else article

    headings = list(H2_PATTERN.finditer(text))
    sections = []

    # Preamble (everything before the first ##)
    first_h2_start = headings[0].start() if headings else len(text)
    preamble = text[:first_h2_start].strip()
    if preamble:
        sections.append(("Overview", preamble))

    # One section per ## heading, running until the next ## heading
    for i, match in enumerate(headings):
        end = headings[i + 1].start() if i + 1 < len(headings) else len(text)
        body = text[match.start():end].strip()
        sections.append((match.group(1), body))

    chunks = []
    for idx, (section, body) in enumerate(sections):
        content = body if section == "Overview" else f"{title}\n\n{body}"
        chunks.append(
            {
                "id": f"{article}::{idx:02d}",
                "text": content,
                "metadata": {
                    "article": article,
                    "file": file_path.name,
                    "title": title,
                    "section": section,
                    "chunk_index": idx,
                },
            }
        )
    return chunks


def load_kb(kb_dir: Path) -> list[dict]:
    md_files = sorted(kb_dir.glob("*.md"))
    if not md_files:
        raise FileNotFoundError(f"No .md files found in {kb_dir}")

    all_chunks = []
    print(f"Reading {len(md_files)} articles from {kb_dir}")
    for f in md_files:
        chunks = chunk_markdown(f)
        all_chunks.extend(chunks)
        print(f"  {f.name:<28} -> {len(chunks)} chunks")
    print(f"Total chunks: {len(all_chunks)}\n")
    return all_chunks


# --- 3: Store in ChromaDB ------------------------------------------------------
def build_collection(chunks: list[dict]):
    client = chromadb.PersistentClient(path=str(CHROMA_DIR))

    # Start clean on every run so edited/removed articles don't leave stale chunks
    try:
        client.delete_collection(COLLECTION_NAME)
    except Exception:
        pass  # collection didn't exist yet

    collection = client.create_collection(
        name=COLLECTION_NAME,
        metadata={"hnsw:space": "cosine"},  # cosine distance -> similarity = 1 - d
    )
    collection.add(
        ids=[c["id"] for c in chunks],
        documents=[c["text"] for c in chunks],
        metadatas=[c["metadata"] for c in chunks],
    )
    print(f"Stored {collection.count()} chunks in collection '{COLLECTION_NAME}'")
    print(f"ChromaDB location: {CHROMA_DIR}\n")
    return collection


# --- 4: Query ------------------------------------------------------------------
def best_article(collection, query: str, n_results: int = 10) -> list[dict]:
    """Return articles ranked by their best-matching chunk.

    Confidence = cosine similarity (1 - cosine distance) of the article's
    top chunk. Typical values with this model: 0.5-0.7 is a strong match,
    below ~0.3 is weak.
    """
    n = min(n_results, collection.count())
    res = collection.query(query_texts=[query], n_results=n)

    best = {}
    for meta, dist in zip(res["metadatas"][0], res["distances"][0]):
        score = 1.0 - dist
        art = meta["article"]
        if art not in best or score > best[art]["confidence"]:
            best[art] = {"article": art, "section": meta["section"],
                         "title": meta["title"], "confidence": score}
    return sorted(best.values(), key=lambda r: r["confidence"], reverse=True)


SAMPLE_QUERIES = [
    ("My account got locked after too many wrong password attempts",
     "password_reset"),
    ("AnyConnect keeps saying authentication failed since I changed my password",
     "vpn_troubleshooting"),
    ("Whole finance team getting DBCON_FAIL when logging into SAP",
     "erp_connectivity"),
    ("Outlook on my iPhone stopped syncing new emails",
     "email_troubleshooting"),
]


def run_tests(collection):
    print("=" * 72)
    print("Retrieval test")
    print("=" * 72)
    passed = 0
    for i, (query, expected) in enumerate(SAMPLE_QUERIES, 1):
        ranked = best_article(collection, query)
        top = ranked[0]
        ok = top["article"] == expected
        passed += ok
        print(f"\nQ{i}: {query}")
        print(f"  Best match : {top['article']}.md  ({top['title']})")
        print(f"  Section    : {top['section']}")
        print(f"  Confidence : {top['confidence']:.3f}  ({top['confidence']:.1%})")
        if len(ranked) > 1:
            print(f"  Runner-up  : {ranked[1]['article']}.md  "
                  f"({ranked[1]['confidence']:.3f})")
        print(f"  Expected   : {expected}.md  -> {'PASS' if ok else 'CHECK'}")
    print(f"\n{passed}/{len(SAMPLE_QUERIES)} queries matched the expected article.")


if __name__ == "__main__":
    chunks = load_kb(KB_DIR)
    collection = build_collection(chunks)
    run_tests(collection)
