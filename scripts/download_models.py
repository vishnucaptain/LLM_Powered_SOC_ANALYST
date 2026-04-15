"""
download_models.py
------------------
Pre-download all models required by the LLM-Powered SOC Analyst pipeline.

Run this ONCE before starting the server so the first investigation call
doesn't trigger a slow download mid-request.

Models downloaded:
  1. microsoft/Phi-3.5-mini-instruct  (~7 GB) — local LLM for SOC reports
  2. sentence-transformers/all-MiniLM-L6-v2 (~90 MB) — RAG embedding model

Usage:
    python scripts/download_models.py

Hardware note:
  Phi-3.5 runs in float16 on GPU (CUDA/MPS) or float32 on CPU.
  Minimum 8 GB RAM recommended for CPU inference.
"""

import sys
import time

BOLD  = "\033[1m"
GREEN = "\033[92m"
YELLOW= "\033[93m"
RED   = "\033[91m"
RESET = "\033[0m"


def banner(msg: str):
    print(f"\n{BOLD}{'─' * 60}{RESET}")
    print(f"{BOLD}  {msg}{RESET}")
    print(f"{BOLD}{'─' * 60}{RESET}")


def ok(msg: str):
    print(f"{GREEN}  ✔  {msg}{RESET}")


def warn(msg: str):
    print(f"{YELLOW}  ⚠  {msg}{RESET}")


def fail(msg: str):
    print(f"{RED}  ✘  {msg}{RESET}")


# ─────────────────────────────────────────────────────────────
# 1. Check dependencies
# ─────────────────────────────────────────────────────────────
banner("Step 1 — Checking dependencies")

missing = []
for pkg in ("torch", "transformers", "accelerate", "sentence_transformers"):
    try:
        __import__(pkg)
        ok(f"{pkg} is installed")
    except ImportError:
        fail(f"{pkg} is NOT installed")
        missing.append(pkg)

if missing:
    print(f"\n{RED}Install missing packages first:{RESET}")
    print(f"  pip install transformers>=4.43.0 accelerate>=0.30.0 sentence-transformers torch")
    sys.exit(1)


# ─────────────────────────────────────────────────────────────
# 2. Download Phi-3.5-mini-instruct
# ─────────────────────────────────────────────────────────────
banner("Step 2 — Downloading Phi-3.5-mini-instruct (~7 GB)")
warn("This may take several minutes on first run.")
warn("Subsequent runs use the cached weights and are instant.")

PHI_MODEL = "microsoft/Phi-3.5-mini-instruct"

try:
    import torch
    from transformers import AutoTokenizer, AutoModelForCausalLM

    print(f"\n  Fetching tokenizer …")
    t0 = time.time()
    tokenizer = AutoTokenizer.from_pretrained(PHI_MODEL, trust_remote_code=True)
    ok(f"Tokenizer downloaded  ({time.time()-t0:.1f}s)")

    dtype = torch.float16 if (torch.cuda.is_available() or torch.backends.mps.is_available()) else torch.float32
    device = "cuda" if torch.cuda.is_available() else ("mps" if torch.backends.mps.is_available() else "cpu")
    print(f"\n  Device  : {device}  |  dtype : {dtype}")
    print(f"  Fetching model weights …")

    t0 = time.time()
    model = AutoModelForCausalLM.from_pretrained(
        PHI_MODEL,
        trust_remote_code=True,
        torch_dtype=dtype,
        device_map="auto",
    )
    model.eval()
    ok(f"Phi-3.5 model downloaded & loaded  ({time.time()-t0:.1f}s)")

    # Quick smoke test
    print(f"\n  Running smoke test (5 tokens) …")
    messages = [{"role": "user", "content": "Reply with only: OK"}]
    inputs = tokenizer.apply_chat_template(
        messages,
        add_generation_prompt=True,
        tokenize=True,
        return_dict=True,
        return_tensors="pt",
    ).to(model.device)

    with torch.no_grad():
        out = model.generate(**inputs, max_new_tokens=5, do_sample=False,
                             pad_token_id=tokenizer.eos_token_id)
    reply = tokenizer.decode(out[0][inputs["input_ids"].shape[-1]:], skip_special_tokens=True)
    ok(f"Smoke test passed — model replied: '{reply.strip()}'")

    # Free memory — server will reload lazily
    del model, tokenizer

except Exception as exc:
    fail(f"Phi-3.5 download failed: {exc}")
    print(f"\n  Possible causes:")
    print(f"    • No internet connection")
    print(f"    • Insufficient disk space (need ~7 GB free)")
    print(f"    • Hugging Face rate limit — set HF_TOKEN env var")
    sys.exit(1)


# ─────────────────────────────────────────────────────────────
# 3. Download RAG embedding model
# ─────────────────────────────────────────────────────────────
banner("Step 3 — Downloading RAG embedding model (~90 MB)")

EMBED_MODEL = "sentence-transformers/all-MiniLM-L6-v2"

try:
    from sentence_transformers import SentenceTransformer
    t0 = time.time()
    embed = SentenceTransformer(EMBED_MODEL)
    test_vec = embed.encode(["T1110 Brute Force"])
    ok(f"Embedding model downloaded  ({time.time()-t0:.1f}s)  |  dim={len(test_vec[0])}")
    del embed
except Exception as exc:
    fail(f"Embedding model download failed: {exc}")
    sys.exit(1)


# ─────────────────────────────────────────────────────────────
# 4. Done
# ─────────────────────────────────────────────────────────────
banner("✔  All models downloaded — you can now start the server!")
print(f"""
  Run the backend:
    {BOLD}uvicorn backend.main:app --reload --port 8000{RESET}

  Then open the frontend:
    {BOLD}open frontend/index.html{RESET}

  Or test with curl:
    {BOLD}curl -s http://localhost:8000/{RESET}
""")
