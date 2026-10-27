import numpy as np
import pytest

from ablation.analyzers import finding_registry
from ablation.analyzers.finding_registry import FindingRegistry


def _empty_registry(tmp_path, monkeypatch):
    monkeypatch.setattr(
        finding_registry, "_SEED_PATH", tmp_path / "missing_seed_corpus.json"
    )
    registry = FindingRegistry(tmp_path / "findings.db")
    registry.register(
        vendor="test",
        product="test",
        title="example finding",
        description="example description",
        cwe_class="CWE-78",
        severity="HIGH",
    )
    return registry


def test_build_embeddings_supports_encode_only_models(tmp_path, monkeypatch):
    registry = _empty_registry(tmp_path, monkeypatch)

    class EncodeOnlyModel:
        def __init__(self):
            self.calls = []

        def encode(self, texts, **kwargs):
            self.calls.append((texts, kwargs))
            return np.array([[1.0, 0.0] for _ in texts])

    model = EncodeOnlyModel()
    try:
        assert registry.build_embeddings(model) == 1
        assert registry.stats()["with_embedding"] == 1
        assert model.calls == [
            (
                ["example finding | example description"],
                {"normalize_embeddings": True, "show_progress_bar": False},
            )
        ]
        hits = registry.find_similar(np.array([1.0, 0.0], dtype=np.float32))
        assert [hit["title"] for hit in hits] == ["example finding"]
    finally:
        registry.close()


def test_build_embeddings_prefers_existing_embed_api(tmp_path, monkeypatch):
    registry = _empty_registry(tmp_path, monkeypatch)

    class EmbedModel:
        def embed(self, texts):
            for _ in texts:
                yield np.array([0.0, 1.0])

        def encode(self, *args, **kwargs):
            raise AssertionError("encode should not be called when embed is available")

    try:
        assert registry.build_embeddings(EmbedModel()) == 1
        hits = registry.find_similar(np.array([0.0, 1.0], dtype=np.float32))
        assert [hit["title"] for hit in hits] == ["example finding"]
    finally:
        registry.close()


def test_build_embeddings_rejects_unsupported_models(tmp_path, monkeypatch):
    registry = _empty_registry(tmp_path, monkeypatch)
    try:
        with pytest.raises(TypeError, match="neither .embed nor .encode"):
            registry.build_embeddings(object())
    finally:
        registry.close()
