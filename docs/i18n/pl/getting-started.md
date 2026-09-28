# Pierwsze kroki

Od instalacji do pierwszego kandydata na podatność w 15 minut. Działa z dowolnym stripped binarnym ELF.

---

## Instalacja

**Wymagania:** Python 3.10+, pip

```bash
pip install git+https://github.com/Ablation-Tool/ablation
```

Z funkcjami LLM:

```bash
pip install "git+https://github.com/Ablation-Tool/ablation#egg=ablation[llm]"
```

Ze źródła:

```bash
git clone https://github.com/Ablation-Tool/ablation
cd ablation
pip install -e .
```

Zweryfikuj instalację:

```bash
python -c "from ablation.analyzers.binary_context import BinaryContext; print('ok')"
```

---

## Krok 1: Wczytaj plik binarny

`BinaryContext` jest punktem wejścia dla wszystkich analiz. Przekaż dowolny stripped binarny ELF:

```python
from ablation.analyzers.binary_context import BinaryContext

ctx = BinaryContext.load_or_build('/path/to/binary.so')
print(ctx.summary())
```

**Pierwsze uruchomienie:** od 0,5 do 5 sekund w zależności od rozmiaru pliku binarnego. Ablation buduje i zapisuje w pamięci podręcznej w `~/.ablation/cache/<sha256>_<name>.json`.

**Każde kolejne uruchomienie:** 110 ms. Pamięć podręczna jest kluczowana SHA256 — inna kompilacja o tej samej nazwie pliku binarnego jest automatycznie przebudowywana.

Przykładowe wyjście:

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

## Krok 2: Uruchom skanowanie semantyczne

Skanowanie jest głównym przepływem pracy. Koduje wszystkie funkcje jako odciski behawioralne BERT i wykonuje zapytania na podstawie opisu podatności w prostym angielskim. Użyj `sweeps/base_sweep.py` jako szablonu lub zbuduj własny:

```python
from ablation.analyzers.corpus_builder import CorpusBuilder
from ablation.analyzers.semantic_search import SemanticSearcher
from ablation.analyzers.pattern_library import PatternLibrary

# Zbuduj korpus opisów behawioralnych do func_id.db
cb = CorpusBuilder()
cb.build('/path/to/binary.so', product='my-target', version='1.0')

# Zbuduj embeddingi BERT (~35s for 19k functions on CPU)
searcher = SemanticSearcher('~/.ablation/func_id.db')
searcher.build_corpus()

# Wykonaj zapytanie na podstawie opisu podatności
results = searcher.query(
    "TLV parser that advances pointer without minimum length check",
    top_k=10
)

for r in results:
    print(f"  0x{r.va:x}  {r.name or hex(r.va):<50s}  score={r.score:.3f}")
```

**Oczekiwany czas wykonania:** od 35 do 60 sekund dla 19 000 funkcji na CPU. Kolejne zapytania dotyczące tego samego korpusu działają w czasie poniżej jednej sekundy — embeddingi są w pamięci podręcznej.

---

## Krok 3: Triage kandydatów

Dla każdego kandydata z wysokim wynikiem pobierz jego kontekst:

```python
va = 0x1000  # VA kandydata z wyników skanowania

# Co wywołuje ta funkcja?
print("callees:", ctx.callees_of(va))

# Do jakich ciągów się odwołuje?
print("strings:", ctx.strings_in_func(va))

# Co ją wywołuje?
print("callers:", ctx.callers_of(va))
```

Większość kandydatów jest klasyfikowana w ciągu dwóch do trzech minut w ten sposób. Jeśli lista callees zawiera funkcje pamięci (`memcpy`, `malloc`, `free`) i łańcuch callerów osiąga punkt wejścia sieci, przejdź do ręcznego śledzenia.

---

## Krok 4: Nazwij potwierdzone funkcje

Gdy zidentyfikujesz cel funkcji, zarejestruj jej nazwę. Nazwy są zachowywane między sesjami i pojawiają się we wszystkich kolejnych wynikach analiz:

```python
ctx.set_name(0x1000, 'proto_parse_message', source='confirmed')

# Nazwy pojawiają się wszędzie:
print(ctx.callees_of(0x1000))   # etykiety zamiast adresów szesnastkowych
print(ctx.names_table())           # wszystkie nazwane funkcje w tym pliku binarnym
```

Nazwy są przechowywane w `~/.ablation/function_names.json`, kluczowane SHA256 binarnym. Przeżywają ponowne uruchomienia sesji, przeniesienia plików binarnych i ponowne uruchomienia systemu.

---

## Krok 5: Zarejestruj potwierdzone wzorce

Gdy potwierdzisz rzeczywistą podatność, zarejestruj zapytanie, które ją znalazło. Zostanie ono automatycznie odtworzone na przyszłych plikach binarnych:

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

Przy każdym przyszłym skanowaniu — innej wersji oprogramowania sprzętowego, innego dostawcy — `pl.sweep(searcher)` automatycznie uruchamia wszystkie potwierdzone wzorce.

---

## Wznów sesję

Ablation jest zaprojektowany do wielosesyjnych badań. Na początku każdej sesji:

```python
# Wczytaj kontekst (110ms -- używa pamięci podręcznej)
ctx = BinaryContext.load_or_build('/path/to/binary.so')

# Pokaż wszystkie wcześniej nazwane funkcje
print(ctx.names_table())

# Przejrzyj potwierdzone wyniki
from ablation.analyzers.finding_registry import FindingRegistry
fr = FindingRegistry()
fr.list_findings(binary_sha=ctx.sha256[:16])
```

---

## Następne kroki

- [Przepływ pracy polowania na podatności](../../workflows/vuln-hunting.md) -- pełna pętla od skanowania do wyniku gotowego do ujawnienia
- [Dokumentacja modułów](../../module-reference/) -- ponad 50 analizatorów z parametrami i przykładami
- [CONTRIBUTING.md](../../../CONTRIBUTING.md) -- jak dodawać wzorce, skanowania i moduły analizatorów
