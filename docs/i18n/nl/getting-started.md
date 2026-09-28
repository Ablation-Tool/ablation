# Aan de slag

Van installatie naar de eerste kwetsbaarheidskandidaat in 15 minuten. Werkt met elk stripped ELF-binair bestand.

---

## Installatie

**Vereisten:** Python 3.10+, pip

```bash
pip install git+https://github.com/Ablation-Tool/ablation
```

Met LLM-functies:

```bash
pip install "git+https://github.com/Ablation-Tool/ablation#egg=ablation[llm]"
```

Vanuit bron:

```bash
git clone https://github.com/Ablation-Tool/ablation
cd ablation
pip install -e .
```

Installatie verifiëren:

```bash
python -c "from ablation.analyzers.binary_context import BinaryContext; print('ok')"
```

---

## Stap 1: Laad uw binair bestand

`BinaryContext` is het toegangspunt voor alle analyses. Geef een stripped ELF-binair bestand door:

```python
from ablation.analyzers.binary_context import BinaryContext

ctx = BinaryContext.load_or_build('/path/to/binary.so')
print(ctx.summary())
```

**Eerste keer:** 0,5 tot 5 seconden afhankelijk van de grootte van het binaire bestand. Ablation bouwt en slaat op in cache naar `~/.ablation/cache/<sha256>_<name>.json`.

**Elke volgende keer:** 110 ms. De cache is SHA256-gesleuteld — een andere build met dezelfde binaire bestandsnaam wordt automatisch opnieuw gebouwd.

Voorbeelduitvoer:

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

## Stap 2: Voer een semantische scan uit

De scan is de kernworkflow. Codeert alle functies als BERT-gedragsvingerafdrukken en voert queries uit op kwetsbaarheidsbeschrijving in gewoon Engels. Gebruik `sweeps/base_sweep.py` als sjabloon, of bouw uw eigen:

```python
from ablation.analyzers.corpus_builder import CorpusBuilder
from ablation.analyzers.semantic_search import SemanticSearcher
from ablation.analyzers.pattern_library import PatternLibrary

# Bouw corpus van gedragsbeschrijvingen naar func_id.db
cb = CorpusBuilder()
cb.build('/path/to/binary.so', product='my-target', version='1.0')

# Bouw BERT-embeddings (~35s for 19k functions on CPU)
searcher = SemanticSearcher('~/.ablation/func_id.db')
searcher.build_corpus()

# Query op kwetsbaarheidsbeschrijving
results = searcher.query(
    "TLV parser that advances pointer without minimum length check",
    top_k=10
)

for r in results:
    print(f"  0x{r.va:x}  {r.name or hex(r.va):<50s}  score={r.score:.3f}")
```

**Verwachte uitvoeringstijd:** 35 tot 60 seconden voor 19.000 functies op CPU. Volgende queries op hetzelfde corpus draaien in minder dan een seconde — embeddings zijn gecached.

---

## Stap 3: Kandidaten triageren

Voor elke kandidaat met een hoge score, haal de context op:

```python
va = 0x1000  # kandidaat-VA uit scanresultaten

# Wat roept deze functie aan?
print("callees:", ctx.callees_of(va))

# Welke strings refereert het?
print("strings:", ctx.strings_in_func(va))

# Wat roept het aan?
print("callers:", ctx.callers_of(va))
```

De meeste kandidaten worden op deze manier in twee tot drie minuten getriageerd. Als de callee-lijst geheugenfuncties bevat (`memcpy`, `malloc`, `free`) en de caller-keten een netwerkinvoerpunt bereikt, ga dan verder met handmatig traceren.

---

## Stap 4: Bevestigde functies benoemen

Wanneer u het doel van een functie identificeert, registreer dan de naam. Namen blijven bestaan tussen sessies en verschijnen in alle volgende analyseuitvoer:

```python
ctx.set_name(0x1000, 'proto_parse_message', source='confirmed')

# Namen verschijnen overal:
print(ctx.callees_of(0x1000))   # labels in plaats van hex-adressen
print(ctx.names_table())           # alle benoemde functies in dit binaire bestand
```

Namen worden opgeslagen in `~/.ablation/function_names.json`, gesleuteld op binaire SHA256. Overleven sessie-herstarts, binaire verplaatsingen en systeemherstarts.

---

## Stap 5: Bevestigde patronen registreren

Wanneer u een echte kwetsbaarheid bevestigt, registreer dan de query die het vond. Het wordt automatisch opnieuw afgespeeld op toekomstige binaire bestanden:

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

Op elke toekomstige scan — andere firmwareversie, andere leverancier — voert `pl.sweep(searcher)` automatisch alle bevestigde patronen uit.

---

## Een sessie hervatten

Ablation is ontworpen voor onderzoek met meerdere sessies. Aan het begin van elke sessie:

```python
# Laad context (110ms -- gebruikt cache)
ctx = BinaryContext.load_or_build('/path/to/binary.so')

# Toon alle eerder benoemde functies
print(ctx.names_table())

# Bekijk bevestigde bevindingen
from ablation.analyzers.finding_registry import FindingRegistry
fr = FindingRegistry()
fr.list_findings(binary_sha=ctx.sha256[:16])
```

---

## Volgende stappen

- [Workflow voor het opsporen van kwetsbaarheden](../../workflows/vuln-hunting.md) -- volledige lus van scan naar openbaarmakingsklare bevinding
- [Modulereferentie](../../module-reference/) -- meer dan 50 analysatoren met parameters en voorbeelden
- [CONTRIBUTING.md](../../../CONTRIBUTING.md) -- patronen, scans en analysatormodules toevoegen
