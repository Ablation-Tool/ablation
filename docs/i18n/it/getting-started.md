# Guida introduttiva

Dall'installazione al primo candidato vulnerabile in 15 minuti. Funziona con qualsiasi binario ELF stripped.

---

## Installazione

**Requisiti:** Python 3.10+, pip

```bash
pip install git+https://github.com/Ablation-Tool/ablation
```

Con funzionalità LLM:

```bash
pip install "git+https://github.com/Ablation-Tool/ablation#egg=ablation[llm]"
```

Dal sorgente:

```bash
git clone https://github.com/Ablation-Tool/ablation
cd ablation
pip install -e .
```

Verifica l'installazione:

```bash
python -c "from ablation.analyzers.binary_context import BinaryContext; print('ok')"
```

---

## Passo 1: Carica il binario

`BinaryContext` è il punto di ingresso per tutta l'analisi. Passa qualsiasi binario ELF stripped:

```python
from ablation.analyzers.binary_context import BinaryContext

ctx = BinaryContext.load_or_build('/path/to/binary.so')
print(ctx.summary())
```

**Prima esecuzione:** da 0,5 a 5 secondi a seconda della dimensione del binario. Ablation costruisce e mette in cache in `~/.ablation/cache/<sha256>_<name>.json`.

**Ogni esecuzione successiva:** 110 ms. La cache è indicizzata per SHA256 — una build diversa dello stesso nome binario si ricostruisce automaticamente.

Output di esempio:

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

## Passo 2: Esegui una scansione semantica

La scansione è il flusso di lavoro principale. Codifica tutte le funzioni come impronte comportamentali BERT e interroga per descrizione di vulnerabilità in inglese semplice. Usa `sweeps/base_sweep.py` come modello, o costruisci il tuo:

```python
from ablation.analyzers.corpus_builder import CorpusBuilder
from ablation.analyzers.semantic_search import SemanticSearcher
from ablation.analyzers.pattern_library import PatternLibrary

# Costruisci corpus di descrizioni comportamentali in func_id.db
cb = CorpusBuilder()
cb.build('/path/to/binary.so', product='my-target', version='1.0')

# Costruisci embedding BERT (~35s per 19k funzioni su CPU)
searcher = SemanticSearcher('~/.ablation/func_id.db')
searcher.build_corpus()

# Interroga per descrizione di vulnerabilità
results = searcher.query(
    "TLV parser that advances pointer without minimum length check",
    top_k=10
)

for r in results:
    print(f"  0x{r.va:x}  {r.name or hex(r.va):<50s}  score={r.score:.3f}")
```

**Tempo di esecuzione previsto:** da 35 a 60 secondi per 19.000 funzioni su CPU. Le query successive sullo stesso corpus vengono eseguite in meno di un secondo — gli embedding sono in cache.

---

## Passo 3: Analizza i candidati

Per ogni candidato con punteggio alto, ottieni il suo contesto:

```python
va = 0x1000  # VA candidato dai risultati della scansione

# Cosa chiama questa funzione?
print("callees:", ctx.callees_of(va))

# Quali stringhe referenzia?
print("strings:", ctx.strings_in_func(va))

# Cosa la chiama?
print("callers:", ctx.callers_of(va))
```

La maggior parte dei candidati richiede due o tre minuti per essere analizzata in questo modo. Se la lista dei callee contiene funzioni di memoria (`memcpy`, `malloc`, `free`) e la catena dei caller raggiunge un punto di ingresso di rete, procedi alla traccia manuale.

---

## Passo 4: Nomina le funzioni confermate

Quando identifichi lo scopo di una funzione, registra il suo nome. I nomi persistono tra le sessioni e appaiono in tutti gli output di analisi successivi:

```python
ctx.set_name(0x1000, 'proto_parse_message', source='confirmed')

# I nomi appaiono ovunque:
print(ctx.callees_of(0x1000))   # etichette invece di indirizzi esadecimali
print(ctx.names_table())           # tutte le funzioni nominate in questo binario
```

I nomi vengono memorizzati in `~/.ablation/function_names.json`, indicizzati per SHA256 binario. Sopravvivono ai riavvii di sessione, agli spostamenti di binari e ai riavvii del sistema.

---

## Passo 5: Registra i pattern confermati

Quando confermi una vulnerabilità reale, registra la query che l'ha trovata. Si riproduce automaticamente sui binari futuri:

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

Su qualsiasi scansione futura — versione firmware diversa, vendor diverso — `pl.sweep(searcher)` esegue automaticamente tutti i pattern confermati.

---

## Riprendere una sessione

Ablation è progettato per la ricerca in più sessioni. All'inizio di qualsiasi sessione:

```python
# Carica il contesto (110ms -- usa la cache)
ctx = BinaryContext.load_or_build('/path/to/binary.so')

# Mostra tutte le funzioni precedentemente nominate
print(ctx.names_table())

# Rivedi i risultati confermati
from ablation.analyzers.finding_registry import FindingRegistry
fr = FindingRegistry()
fr.list_findings(binary_sha=ctx.sha256[:16])
```

---

## Passi successivi

- [Flusso di lavoro di caccia alle vulnerabilità](../../workflows/vuln-hunting.md) -- ciclo completo dalla scansione al risultato pronto per la divulgazione
- [Riferimento moduli](../../module-reference/) -- oltre 50 analizzatori con parametri ed esempi
- [CONTRIBUTING.md](../../../CONTRIBUTING.md) -- come aggiungere pattern, scansioni e moduli analizzatori
