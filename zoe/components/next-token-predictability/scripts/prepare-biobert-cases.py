#!/usr/bin/env python3
import hashlib
import json
from html.parser import HTMLParser
from pathlib import Path
import random
import re
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from transformers import AutoTokenizer

from ablation_gem_artifacts import atomic_write_text

MODEL = "dmis-lab/biobert-base-cased-v1.2"
REVISION = "67c9c25b46986521ca33df05d8540da1210b3256"
SEED = 20261103
OUTPUT = Path("evidence/biobert-optimization")
STOPWORDS = set("about above after again against almost also among and any are because been before being below between both but can could did does down during each few for from further had has have her here hers herself him himself his how into its itself just more most other our ours ourselves out over own same she should some such than that the their theirs them themselves then there these they this those through too under until very was were what when where which while who whom why will with would you your yours".split())


class TextExtractor(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []

    def handle_data(self, data):
        self.parts.append(data)


def clean_abstract(value):
    parser = TextExtractor()
    parser.feed(value or "")
    return re.sub(r"\s+", " ", "".join(parser.parts)).strip()


def sha256(value):
    return hashlib.sha256(value).hexdigest()


def fetch_candidates():
    endpoint = "https://www.ebi.ac.uk/europepmc/webservices/rest/search"
    query = "OPEN_ACCESS:Y AND HAS_ABSTRACT:Y AND SRC:MED AND FIRST_PDATE:[2018-01-01 TO 2024-12-31] AND (BIOLOGY OR BIOMEDICINE)"
    cursor = "*"
    while cursor:
        parameters = urlencode({
            "query": query,
            "format": "json",
            "resultType": "core",
            "pageSize": 100,
            "cursorMark": cursor,
        })
        request = Request(endpoint + "?" + parameters, headers={"User-Agent": "accessible-volume-research/1.0"})
        with urlopen(request, timeout=60) as response:
            payload = json.load(response)
        yield from payload["resultList"]["result"]
        next_cursor = payload.get("nextCursorMark")
        if next_cursor == cursor:
            return
        cursor = next_cursor


def tokenized(tokenizer, text):
    encoded = tokenizer(text, return_offsets_mapping=True, add_special_tokens=True)
    ids = encoded["input_ids"]
    return ids, tokenizer.convert_ids_to_tokens(ids), encoded["offset_mapping"]


def eligible_candidates(tokenizer, text):
    ids, tokens, offsets = tokenized(tokenizer, text)
    offset_positions = {tuple(offset): index for index, offset in enumerate(offsets)}
    candidates = []
    counts = {"lexical": 0, "stopword": 0, "repeated": 0, "non_single_token": 0, "unknown_token": 0}
    for match in re.finditer(r"(?<![A-Za-z])[a-z]{4,14}(?![A-Za-z])", text):
        counts["lexical"] += 1
        word = match.group(0)
        if word in STOPWORDS:
            counts["stopword"] += 1
            continue
        occurrences = re.findall(rf"(?<![A-Za-z]){re.escape(word)}(?![A-Za-z])", text, flags=re.IGNORECASE)
        if len(occurrences) != 1:
            counts["repeated"] += 1
            continue
        span = (match.start(), match.end())
        position = offset_positions.get(span)
        if position is None or tokens[position].startswith("##"):
            counts["non_single_token"] += 1
            continue
        if ids[position] == tokenizer.unk_token_id:
            counts["unknown_token"] += 1
            continue
        candidates.append({
            "word": word,
            "start": match.start(),
            "end": match.end(),
            "position": position,
            "token_id": ids[position],
        })
    return ids, candidates, counts


def main():
    output = OUTPUT
    output.mkdir(parents=True, exist_ok=True)
    tokenizer = AutoTokenizer.from_pretrained(MODEL, revision=REVISION)
    sources = []
    cases = []
    excluded = []
    selection_counts = []
    for result in fetch_candidates():
        if len(sources) == 30:
            break
        pmid = str(result.get("pmid") or result.get("id") or "")
        title = clean_abstract(result.get("title"))
        abstract = clean_abstract(result.get("abstractText"))
        license_name = result.get("license") or "not supplied"
        source_id = f"pmid-{pmid}" if pmid else f"europepmc-{result.get('id')}"
        if not pmid or not title or not abstract:
            excluded.append({"source_id": source_id, "reason": "Missing PMID, title, or abstract"})
            continue
        if not license_name.lower().startswith("cc"):
            excluded.append({"source_id": source_id, "reason": "No explicit Creative Commons license", "license": license_name})
            continue
        if not 80 <= len(abstract.split()) <= 400:
            excluded.append({"source_id": source_id, "reason": "Abstract outside the 80–400 word range", "license": license_name})
            continue
        ids, candidates, counts = eligible_candidates(tokenizer, abstract)
        if len(ids) > 480:
            excluded.append({"source_id": source_id, "reason": "Abstract exceeds 480 BioBERT tokens", "license": license_name})
            continue
        if len(candidates) < 4:
            excluded.append({"source_id": source_id, "reason": "Fewer than four eligible single-token targets", "license": license_name})
            continue
        chosen = []
        remaining = list(range(len(candidates)))
        for ordinal in range(1, 5):
            desired = (ordinal * len(candidates)) // 5
            index = min(remaining, key=lambda value: (abs(value - desired), value))
            remaining.remove(index)
            candidate = candidates[index]
            case_id = f"bio-{source_id}-{ordinal:02d}"
            chosen.append({
                "case_id": case_id,
                "source_document_id": source_id,
                "domain": "biology",
                "context": abstract,
                "target": candidate["word"],
                "target_start": candidate["start"],
                "target_end": candidate["end"],
                "target_position": candidate["position"],
                "target_token_id": candidate["token_id"],
                "difficulty_label": "length_le_7" if len(candidate["word"]) <= 7 else "length_gt_7",
            })
        cases.extend(chosen)
        sources.append({
            "source_document_id": source_id,
            "pmid": pmid,
            "pmcid": result.get("pmcid"),
            "doi": result.get("doi"),
            "title": title,
            "authors": result.get("authorString"),
            "journal": result.get("journalTitle"),
            "publication_year": result.get("pubYear"),
            "license": license_name,
            "url": f"https://europepmc.org/article/MED/{pmid}",
            "abstract_sha256": sha256(abstract.encode("utf-8")),
            "abstract_tokens": len(ids),
            "eligible_target_count": len(candidates),
        })
        selection_counts.append({"source_document_id": source_id, **counts})
        print("ACCEPTED", source_id, len(candidates), "targets", len(ids), "tokens", flush=True)
    if len(sources) != 30 or len(cases) != 120:
        raise RuntimeError(f"Expected 30 documents and 120 cases, got {len(sources)} and {len(cases)}")
    document_ids = sorted(source["source_document_id"] for source in sources)
    random.Random(SEED).shuffle(document_ids)
    assignments = {}
    for index, document_id in enumerate(document_ids):
        assignments[document_id] = "development" if index < 15 else "validation" if index < 20 else "test"
    for case in cases:
        case["split"] = assignments[case["source_document_id"]]
    created = __import__("datetime").datetime.now(__import__("datetime").timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    case_manifest = {
        "schema_version": 1,
        "created_utc": created,
        "model": MODEL,
        "model_revision": REVISION,
        "domain": "biology",
        "source_dataset": "Europe PMC open-access abstracts",
        "selection": "Four deterministic, single-token, non-repeated targets per document; eligibility frozen before inference",
        "case_count": len(cases),
        "cases": cases,
    }
    case_bytes = (json.dumps(case_manifest, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    atomic_write_text(output / "cases.json", case_bytes.decode("utf-8"))
    split_manifest = {
        "schema_version": 1,
        "seed": SEED,
        "split_unit": "source_document",
        "cases_sha256": sha256(case_bytes),
        "documents": [{"source_document_id": key, "split": value} for key, value in sorted(assignments.items())],
        "case_counts": {name: sum(case["split"] == name for case in cases) for name in ("development", "validation", "test")},
    }
    atomic_write_text(output / "splits.json", json.dumps(split_manifest, indent=2) + "\n")
    atomic_write_text(output / "sources.json", json.dumps({
        "schema_version": 1,
        "created_utc": created,
        "accepted_documents": sources,
        "excluded_documents": excluded,
        "target_eligibility": selection_counts,
    }, indent=2, ensure_ascii=False) + "\n")
    print("FROZEN", len(cases), "cases", split_manifest["case_counts"])
    print("CASE MANIFEST SHA-256", split_manifest["cases_sha256"])


if __name__ == "__main__":
    main()
