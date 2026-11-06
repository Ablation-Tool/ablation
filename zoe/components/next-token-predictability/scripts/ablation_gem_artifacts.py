import hashlib
import os
from pathlib import Path
import tempfile

import numpy as np
from huggingface_hub import hf_hub_download


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def prepare_model(root, model_id, model_sha256, tokenizer_sha256):
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    for filename in ("onnx/model.onnx", "tokenizer.json", "config.json"):
        hf_hub_download(model_id, filename, local_dir=root)
    if sha256(root / "onnx/model.onnx") != model_sha256:
        raise ValueError("model hash mismatch")
    if sha256(root / "tokenizer.json") != tokenizer_sha256:
        raise ValueError("tokenizer hash mismatch")


def atomic_write_bytes(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile("wb", dir=path.parent, prefix=f".{path.name}.", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def atomic_write_text(path, text):
    atomic_write_bytes(path, text.encode("utf-8"))


def atomic_savez(path, **arrays):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile("wb", dir=path.parent, prefix=f".{path.name}.", delete=False) as stream:
            temporary = Path(stream.name)
            np.savez_compressed(stream, **arrays)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
