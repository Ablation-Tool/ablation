# Erste Schritte

Von der Installation zum ersten Schwachstellenkandidaten in 15 Minuten. Jedes stripped ELF-Binary funktioniert.

---

## Installation

**Voraussetzungen:** Python 3.10+, pip

```bash
pip install git+https://github.com/Ablation-Tool/ablation
```

Mit LLM-Funktionen:

```bash
pip install "git+https://github.com/Ablation-Tool/ablation#egg=ablation[llm]"
```

Aus dem Quellcode:

```bash
git clone https://github.com/Ablation-Tool/ablation
cd ablation
pip install -e .
```

Installation prüfen:

```bash
python -c "from ablation.analyzers.binary_context import BinaryContext; print('ok')"
```

---

## Schritt 1: Binary laden

`BinaryContext` ist der Einstiegspunkt für alle Analysen. Übergeben Sie ein beliebiges stripped ELF-Binary:

```python
from ablation.analyzers.binary_context import BinaryContext

ctx = BinaryContext.load_or_build('/path/to/binary.so')
print(ctx.summary())
```

**Erster Durchlauf:** 0,5 bis 5 Sekunden je nach Binary-Größe. Ablation baut auf und speichert im Cache unter `~/.ablation/cache/<sha256>_<name>.json`.

**Jeder nachfolgende Durchlauf:** 110 ms. Der Cache ist per SHA256 indiziert, daher baut ein anderer Build desselben Binary-Namens automatisch neu auf.

Beispielausgabe:

```
BinaryContext: libservice.so
  sha256     : fdfaceccdc740d82...
  base_va    : 0x0
  func_starts: 19024
  exports    : 14
  plt entries: 187
  strings    : 44821
  call_edges : 58903
  str_xrefs  : 218440 pairs indexed
  named funcs: 0 (overlay)
```

---

## Schritt 2: Semantischen Sweep durchführen

Der Sweep ist der zentrale Workflow. Er kodiert alle Funktionen als BERT-Verhaltenssignaturen und fragt nach Schwachstellenbeschreibungen in einfachem Englisch ab. Verwenden Sie `sweeps/base_sweep.py` als Vorlage oder erstellen Sie Ihren eigenen:

```python
from ablation.analyzers.corpus_builder import CorpusBuilder
from ablation.analyzers.semantic_search import SemanticSearcher
from ablation.analyzers.pattern_library import PatternLibrary

# Verhaltensbeschreibungs-Corpus in func_id.db aufbauen
cb = CorpusBuilder()
cb.build('/path/to/binary.so', product='my-target', version='1.0')

# BERT-Embeddings aufbauen (~35s für 19k Funktionen auf CPU)
searcher = SemanticSearcher('~/.ablation/func_id.db')
searcher.build_corpus()

# Nach Schwachstellenbeschreibung abfragen
results = searcher.query(
    "TLV parser that advances pointer without minimum length check",
    top_k=10
)

for r in results:
    print(f"  0x{r.va:x}  {r.name or hex(r.va):<50s}  score={r.score:.3f}")
```

**Erwartete Laufzeit:** 35 bis 60 Sekunden für 19.000 Funktionen auf CPU. Nachfolgende Abfragen gegen denselben Corpus laufen in unter einer Sekunde, da Embeddings gecacht sind.

---

## Schritt 3: Kandidaten prüfen

Holen Sie für jeden Kandidaten mit hohem Score seinen Kontext:

```python
va = 0x1000  # Kandidaten-VA aus den Sweep-Ergebnissen

# Was ruft diese Funktion auf?
print("callees:", ctx.callees_of(va))

# Welche Strings referenziert sie?
print("strings:", ctx.strings_in_func(va))

# Was ruft sie auf?
print("callers:", ctx.callers_of(va))
```

Die meisten Kandidaten brauchen zwei bis drei Minuten, um so zu prüfen. Wenn die Callee-Liste Speicherfunktionen enthält (`memcpy`, `malloc`, `free`) und die Caller-Kette einen Netzwerk-Einstiegspunkt erreicht, fahren Sie mit der manuellen Rückverfolgung fort.

---

## Schritt 4: Bestätigte Funktionen benennen

Wenn Sie den Zweck einer Funktion identifiziert haben, registrieren Sie ihren Namen. Namen bleiben über Sitzungen hinweg erhalten und erscheinen in allen nachfolgenden Analyseausgaben:

```python
ctx.set_name(0x1000, 'proto_parse_message', source='confirmed')

# Namen erscheinen überall:
print(ctx.callees_of(0x1000))   # Labels statt Hexadressen
print(ctx.names_table())           # alle benannten Funktionen in diesem Binary
```

Namen werden in `~/.ablation/function_names.json` gespeichert, indexiert nach Binary-SHA256. Sie überleben Sitzungsneustarts, Binary-Verschiebungen und Systemneustarts.

---

## Schritt 5: Bestätigte Muster registrieren

Wenn Sie eine echte Schwachstelle bestätigen, registrieren Sie die Abfrage, die sie gefunden hat. Sie wird auf zukünftige Binaries automatisch angewendet:

```python
from ablation.analyzers.pattern_library import PatternLibrary

pl = PatternLibrary()
pl.record_hit(
    query="TLV pointer advance loop with no minimum length check",
    binary_sha="fdfaceccdc740d82",
    va=0x1000,
    confirmed=True,
    vuln_class="infinite_loop",
    cvss=7.5,
)
```

Bei jedem zukünftigen Sweep, ob einer anderen Firmware-Version oder einem anderen Hersteller, führt `pl.sweep(searcher)` alle bestätigten Muster automatisch aus.

---

## Sitzung fortsetzen

Ablation ist für mehrsitzige Forschung ausgelegt. Am Anfang jeder Sitzung:

```python
# Kontext laden (110ms -- nutzt Cache)
ctx = BinaryContext.load_or_build('/path/to/binary.so')

# Alle zuvor benannten Funktionen anzeigen
print(ctx.names_table())

# Bestätigte Erkenntnisse überprüfen
from ablation.analyzers.finding_registry import FindingRegistry
fr = FindingRegistry()
fr.list_findings(binary_sha=ctx.sha256[:16])
```

---

## Nächste Schritte

- [Workflow zur Schwachstellensuche](../../workflows/vuln-hunting.md) -- vollständige Schleife vom Sweep bis zur offenlegungsbereiten Erkenntnis
- [Modulreferenz](../../module-reference/) -- über 50 Analysatoren mit Parametern und Beispielen
- [CONTRIBUTING.md](../../../CONTRIBUTING.md) -- wie man Muster, Sweeps und Analysatormodule hinzufügt
