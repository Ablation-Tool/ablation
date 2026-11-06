#!/usr/bin/env python3
"""HOP: Harmonic Osculating Predictor — a tiny hidden-state extrapolation experiment."""
import html
import math
import re
from pathlib import Path

import torch
from transformers import AutoModelForCausalLM, AutoTokenizer

torch.set_grad_enabled(False)
MODEL = "distilbert/distilgpt2"
OUT = Path.home() / "Documents/folio_output"


def book_text(path, limit=9000):
    raw = path.read_text(errors="ignore")
    raw = re.sub(r"<(script|style)\b[^>]*>.*?</\1>", " ", raw, flags=re.S | re.I)
    text = html.unescape(re.sub(r"<[^>]+>", " ", raw))
    return re.sub(r"\s+", " ", text)[:limit]


code = """
def rotate(vector, angle):
    x, y = vector
    c = math.cos(angle)
    s = math.sin(angle)
    return (x * c - y * s, x * s + y * c)

def rotate(vector, angle):
    x, y = vector
    c = math.cos(angle)
    s = math.sin(angle)
    return (x * c - y * s, x * s + y * c)
"""

sources = {
    "music": book_text(OUT / "learn-music-theory/004_Chapter_1.html"),
    "geometry": book_text(OUT / "classical-geometry-euclidean/007_c01.htm.html"),
    "code": code * 3,
}

print(f"Loading {MODEL} ...")
tok = AutoTokenizer.from_pretrained(MODEL)
model = AutoModelForCausalLM.from_pretrained(MODEL).eval()
E = model.get_output_embeddings().weight  # tied vocabulary embeddings


def rank_tokens(h):
    return (h @ E.T).topk(5, dim=-1).indices


def hop(h, t, n):
    """Extrapolate n steps along the local arc through h[t-2:t+1]."""
    v0 = h[t - 1] - h[t - 2]
    v1 = h[t] - h[t - 1]
    n0, n1 = v0.norm(), v1.norm()
    if n0 < 1e-8 or n1 < 1e-8:
        return h[t] + n * v1
    u = v0 / n0
    perp = v1 - (v1 @ u) * u
    pn = perp.norm()
    if pn < 1e-8:
        return h[t] + n * v1 * (n1 / n0)
    w = perp / pn
    theta = math.atan2((v1 @ w).item(), (v1 @ u).item())
    # Previous turning angle gives angular acceleration for the second step.
    if t >= 3:
        vm1 = h[t - 2] - h[t - 3]
        nm1 = vm1.norm()
        if nm1 > 1e-8:
            um1 = vm1 / nm1
            pm = v0 - (v0 @ um1) * um1
            if pm.norm() > 1e-8:
                wm = pm / pm.norm()
                prev_theta = math.atan2((v0 @ wm).item(), (v0 @ um1).item())
                dtheta = theta - prev_theta
            else:
                dtheta = 0.0
        else:
            dtheta = 0.0
    else:
        dtheta = 0.0
    s = (n1 / n0).clamp(0.25, 4.0).item()
    result = h[t].clone()
    scale = 1.0
    for k in range(n):
        scale *= s
        # Rotate the previous step in its plane: a walk with turning angle.
        step = scale * n1 * (math.cos((k + 2) * theta + k * dtheta) * u
                             + math.sin((k + 2) * theta + k * dtheta) * w)
        result = result + step
    return result


rows = []
for source, text in sources.items():
    ids = tok(text[:3000], return_tensors="pt").input_ids[0][:700]
    if len(ids) < 20:
        continue
    out = model(ids.unsqueeze(0), output_hidden_states=True)
    h = out.hidden_states[-1][0]  # final normalized hidden state, [L, D]
    truth1 = ids[1:]
    logits = out.logits[0]
    entropy = -(logits.softmax(-1) * logits.log_softmax(-1)).sum(-1)
    for t in range(3, len(ids) - 2):
        actual1, actual2 = ids[t + 1].item(), ids[t + 2].item()
        model_top = rank_tokens(h[t])
        cv1 = h[t] + (h[t] - h[t - 1])
        cv2 = h[t] + 2 * (h[t] - h[t - 1])
        hop1, hop2 = hop(h, t, 1), hop(h, t, 2)
        repeat2 = model_top[0].repeat(5)
        rows.append({
            "source": source,
            "entropy": entropy[t].item(),
            "model1": (rank_tokens(h[t]) == actual1),
            "cv1": (rank_tokens(cv1) == actual1),
            "hop1": (rank_tokens(hop1) == actual1),
            "repeat2": (repeat2 == actual2),
            "cv2": (rank_tokens(cv2) == actual2),
            "hop2": (rank_tokens(hop2) == actual2),
            "err1": 1 - torch.nn.functional.cosine_similarity(hop1, h[t + 1], dim=0).item(),
            "err2": 1 - torch.nn.functional.cosine_similarity(hop2, h[t + 2], dim=0).item(),
        })


def report(subset, label):
    n = len(subset)
    print(f"\n{label}  (positions={n})")
    print("method                 top-1       top-5")
    for key, name in [("model1", "model, 1 ahead"), ("cv1", "velocity, 1 ahead"),
                      ("hop1", "HOP, 1 ahead"), ("repeat2", "repeat, 2 ahead"),
                      ("cv2", "velocity, 2 ahead"), ("hop2", "HOP, 2 ahead")]:
        hits = torch.stack([r[key] for r in subset]).float()
        print(f"{name:22s} {hits[:, 0].mean():7.1%}    {hits.any(1).float().mean():7.1%}")
    print(f"HOP cosine error: 1 ahead={sum(r['err1'] for r in subset)/n:.3f}  "
          f"2 ahead={sum(r['err2'] for r in subset)/n:.3f}")


for source in sources:
    subset = [r for r in rows if r["source"] == source]
    if subset:
        report(subset, source)
report(rows, "ALL")
ordered = sorted(rows, key=lambda r: r["entropy"])
for name, subset in [("low entropy / consonant", ordered[:len(rows)//3]),
                     ("high entropy / dissonant", ordered[-len(rows)//3:])]:
    report(subset, name)
