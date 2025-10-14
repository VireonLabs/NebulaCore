# ai/models/mistral-7b/download_weights.py
"""
Production-ready downloader for HuggingFace model snapshot.
- Validates HF token (optional).
- Uses huggingface_hub.snapshot_download (preferred).
- Retries with exponential backoff.
- Fallback to `huggingface-cli download` if needed.
- Verifies presence of essential files after download.
- Configurable via env vars or CLI args.
"""

import os
import sys
import time
import glob
import shutil
import logging
import subprocess
import argparse
from typing import List

try:
    from huggingface_hub import snapshot_download, HfApi
except Exception:
    snapshot_download = None
    HfApi = None  # fallback will use huggingface-cli via subprocess

# ------------ Configuration (defaults can be overridden by env or CLI) ------------
DEFAULT_MODEL_DIR = os.environ.get("MODEL_DIR", "./mistral-7b")
DEFAULT_MODEL_NAME = os.environ.get("MODEL_NAME", "mistralai/Mistral-7B-v0.2")
DEFAULT_HF_TOKEN = os.environ.get("HF_TOKEN", "")
DEFAULT_RETRIES = int(os.environ.get("DL_RETRIES", "3"))
DEFAULT_BACKOFF = float(os.environ.get("DL_BACKOFF", "5.0"))  # seconds base

# Patterns that indicate model files exist (at least one)
MODEL_FILE_PATTERNS = [
    "pytorch_model-*.bin",
    "*.bin",
    "*.safetensors",
    "config.json",
    "generation_config.json",
    "tokenizer.json",
    "tokenizer.model",
]

# Minimum acceptable filesize (bytes) for weight files to consider them valid (optional safeguard)
MIN_WEIGHT_BYTES = 1 * 1024 * 1024  # 1 MB (very small safeguard; real models >> this)

# Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("download-weights")

# ---------------- Helpers ----------------
def has_model_files(path: str) -> bool:
    """Return True if any expected model file patterns exist and pass a minimal size check."""
    if not os.path.isdir(path):
        return False
    for pattern in MODEL_FILE_PATTERNS:
        matches = glob.glob(os.path.join(path, pattern))
        if not matches:
            continue
        # if match is weight file, check minimal size
        for m in matches:
            try:
                if os.path.getsize(m) >= MIN_WEIGHT_BYTES:
                    return True
            except Exception:
                continue
    return False

def ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)

def validate_token(token: str) -> bool:
    """Optional simple validation of HF token via HfApi().whoami() when available."""
    if not token:
        log.warning("No HF_TOKEN provided (will fail if download from HF required).")
        return False
    if HfApi is None:
        log.info("huggingface_hub not available for token validation; skipping validation.")
        return True
    try:
        api = HfApi()
        who = api.whoami(token=token)
        log.info("HF token validated for user: %s", who.get("name") or who.get("user", {}).get("name", "<unknown>"))
        return True
    except Exception as e:
        log.error("HF token validation failed: %s", e)
        return False

def copy_snapshot_to_model_dir(snapshot_path: str, model_dir: str):
    """Copy files from HF snapshot cache (or repo clone) into model_dir."""
    ensure_dir(model_dir)
    log.info("Copying snapshot files from %s to %s ...", snapshot_path, model_dir)
    for item in os.listdir(snapshot_path):
        s = os.path.join(snapshot_path, item)
        d = os.path.join(model_dir, item)
        if os.path.isdir(s):
            shutil.copytree(s, d, dirs_exist_ok=True)
        else:
            shutil.copy2(s, d)
    log.info("Snapshot files copied.")

# ---------------- Core download logic ----------------
def download_with_snapshot(repo_id: str, token: str, retries: int, backoff: float, model_dir: str) -> bool:
    """Try to download using huggingface_hub.snapshot_download with retries."""
    if snapshot_download is None:
        log.info("snapshot_download not available in environment.")
        return False

    attempt = 0
    while attempt < retries:
        attempt += 1
        try:
            log.info("Attempt %d/%d: snapshot_download(%s) ...", attempt, retries, repo_id)
            # snapshot_download will cache in HF cache dir; returns path to snapshot
            path = snapshot_download(repo_id=repo_id, token=token, resume_download=True)
            if not path or not os.path.exists(path):
                raise RuntimeError(f"snapshot_download returned invalid path: {path}")
            copy_snapshot_to_model_dir(path, model_dir)
            return True
        except KeyboardInterrupt:
            raise
        except Exception as e:
            log.warning("snapshot_download attempt %d failed: %s", attempt, e)
            if attempt < retries:
                sleep_time = backoff * (2 ** (attempt - 1))
                log.info("Retrying in %.1f seconds...", sleep_time)
                time.sleep(sleep_time)
    return False

def download_with_cli(repo_id: str, token: str, model_dir: str) -> bool:
    """Fallback: use huggingface-cli download via subprocess (if installed)."""
    log.info("Falling back to huggingface-cli download (subprocess). Ensure 'huggingface-cli' is installed).")
    cmd = [
        "huggingface-cli", "download", repo_id,
        "--cache-dir", model_dir,
        "--token", token,
        "--resume"
    ]
    try:
        subprocess.run(cmd, check=True)
        return True
    except subprocess.CalledProcessError as e:
        log.error("huggingface-cli download failed: %s", e)
        return False
    except FileNotFoundError:
        log.error("huggingface-cli not found in PATH.")
        return False

def verify_model_dir(model_dir: str) -> bool:
    """Post-download verification: check expected files exist."""
    ok = has_model_files(model_dir)
    if ok:
        log.info("Model files verification: OK (found files in %s).", model_dir)
    else:
        log.error("Model files verification: FAILED (no valid model files found in %s).", model_dir)
    return ok

def download_model(repo_id: str, token: str, model_dir: str, retries: int = DEFAULT_RETRIES, backoff: float = DEFAULT_BACKOFF, force: bool = False) -> bool:
    """Main entry: download or skip if present."""
    if has_model_files(model_dir) and not force:
        log.info("Model files already present in %s — skipping download.", model_dir)
        return True

    ensure_dir(model_dir)

    # Validate token if possible
    if token:
        valid = validate_token(token)
        if not valid:
            log.warning("HF token validation failed or skipped. Proceeding to attempt download (may fail).")

    # Try snapshot_download first (preferred)
    ok = download_with_snapshot(repo_id, token, retries, backoff, model_dir)
    if not ok:
        # fallback to CLI method
        ok = download_with_cli(repo_id, token, model_dir)

    if not ok:
        log.error("All download methods failed.")
        return False

    # verify
    if not verify_model_dir(model_dir):
        log.error("Download finished but verification failed.")
        return False

    log.info("Model weights ready in %s.", model_dir)
    return True

# ---------------- CLI / Entrypoint ----------------
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Download model weights from Hugging Face (production-ready).")
    p.add_argument("--model-dir", default=DEFAULT_MODEL_DIR, help="Target local model directory.")
    p.add_argument("--model-name", default=DEFAULT_MODEL_NAME, help="HuggingFace repo id (e.g. org/model).")
    p.add_argument("--hf-token", default=DEFAULT_HF_TOKEN, help="HuggingFace token (or set HF_TOKEN env var).")
    p.add_argument("--retries", type=int, default=DEFAULT_RETRIES, help="Number of retries for snapshot_download.")
    p.add_argument("--backoff", type=float, default=DEFAULT_BACKOFF, help="Base backoff seconds for retries (exponential).")
    p.add_argument("--force", action="store_true", help="Force re-download even if files appear present.")
    return p.parse_args()

def main():
    args = parse_args()
    model_dir = args.model_dir
    model_name = args.model_name
    hf_token = args.hf_token

    log.info("Starting download weights: repo=%s target=%s", model_name, model_dir)
    try:
        ok = download_model(model_name, hf_token, model_dir, retries=args.retries, backoff=args.backoff, force=args.force)
        if not ok:
            log.error("Model download failed.")
            sys.exit(2)
    except Exception as e:
        log.exception("Fatal error during download: %s", e)
        sys.exit(3)
    log.info("Download script finished successfully.")
    sys.exit(0)

if __name__ == "__main__":
    main()