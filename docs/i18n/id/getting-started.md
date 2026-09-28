# Memulai

Dari instalasi ke kandidat kerentanan pertama dalam 15 menit. Bekerja dengan binary ELF stripped apa pun.

---

## Instalasi

**Persyaratan:** Python 3.10+, pip

```bash
pip install git+https://github.com/Ablation-Tool/ablation
```

Dengan fitur LLM:

```bash
pip install "git+https://github.com/Ablation-Tool/ablation#egg=ablation[llm]"
```

Dari sumber:

```bash
git clone https://github.com/Ablation-Tool/ablation
cd ablation
pip install -e .
```

Verifikasi instalasi:

```bash
python -c "from ablation.analyzers.binary_context import BinaryContext; print('ok')"
```

---

## Langkah 1: Muat binary Anda

`BinaryContext` adalah titik masuk untuk semua analisis. Berikan binary ELF stripped apa pun:

```python
from ablation.analyzers.binary_context import BinaryContext

ctx = BinaryContext.load_or_build('/path/to/binary.so')
print(ctx.summary())
```

**Pertama kali:** 0,5 hingga 5 detik tergantung ukuran binary. Ablation membangun dan menyimpan cache ke `~/.ablation/cache/<sha256>_<name>.json`.

**Setiap kali setelahnya:** 110 ms. Cache diberi kunci SHA256 — build berbeda dengan nama binary yang sama dibangun ulang secara otomatis.

Contoh output:

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

## Langkah 2: Jalankan pemindaian semantik

Pemindaian adalah alur kerja inti. Mengkodekan semua fungsi sebagai sidik jari perilaku BERT dan melakukan kueri berdasarkan deskripsi kerentanan dalam bahasa Inggris sederhana. Gunakan `sweeps/base_sweep.py` sebagai templat, atau buat sendiri:

```python
from ablation.analyzers.corpus_builder import CorpusBuilder
from ablation.analyzers.semantic_search import SemanticSearcher
from ablation.analyzers.pattern_library import PatternLibrary

# Bangun korpus deskripsi perilaku ke func_id.db
cb = CorpusBuilder()
cb.build('/path/to/binary.so', product='my-target', version='1.0')

# Bangun embedding BERT (~35s for 19k functions on CPU)
searcher = SemanticSearcher('~/.ablation/func_id.db')
searcher.build_corpus()

# Kueri berdasarkan deskripsi kerentanan
results = searcher.query(
    "TLV parser that advances pointer without minimum length check",
    top_k=10
)

for r in results:
    print(f"  0x{r.va:x}  {r.name or hex(r.va):<50s}  score={r.score:.3f}")
```

**Waktu berjalan yang diharapkan:** 35 hingga 60 detik untuk 19.000 fungsi di CPU. Kueri berikutnya terhadap korpus yang sama berjalan dalam waktu kurang dari satu detik — embedding disimpan dalam cache.

---

## Langkah 3: Triase kandidat

Untuk setiap kandidat dengan skor tinggi, dapatkan konteksnya:

```python
va = 0x1000  # VA kandidat dari hasil pemindaian

# Apa yang dipanggil fungsi ini?
print("callees:", ctx.callees_of(va))

# String apa yang direferensikannya?
print("strings:", ctx.strings_in_func(va))

# Apa yang memanggilnya?
print("callers:", ctx.callers_of(va))
```

Sebagian besar kandidat ditriase dalam dua hingga tiga menit dengan cara ini. Jika daftar callee berisi fungsi memori (`memcpy`, `malloc`, `free`) dan rantai caller mencapai titik masuk jaringan, lanjutkan ke pelacakan manual.

---

## Langkah 4: Namai fungsi yang dikonfirmasi

Ketika Anda mengidentifikasi tujuan suatu fungsi, daftarkan namanya. Nama bertahan antar sesi dan muncul di semua output analisis berikutnya:

```python
ctx.set_name(0x1000, 'proto_parse_message', source='confirmed')

# Nama muncul di mana-mana:
print(ctx.callees_of(0x1000))   # label alih-alih alamat hex
print(ctx.names_table())           # semua fungsi bernama dalam binary ini
```

Nama disimpan di `~/.ablation/function_names.json`, diberi kunci SHA256 binary. Bertahan melalui restart sesi, pemindahan binary, dan reboot sistem.

---

## Langkah 5: Daftarkan pola yang dikonfirmasi

Ketika Anda mengkonfirmasi kerentanan nyata, daftarkan kueri yang menemukannya. Ini akan diputar ulang secara otomatis pada binary di masa depan:

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

Pada pemindaian di masa depan mana pun — versi firmware berbeda, vendor berbeda — `pl.sweep(searcher)` secara otomatis menjalankan semua pola yang dikonfirmasi.

---

## Melanjutkan sesi

Ablation dirancang untuk penelitian multi-sesi. Di awal sesi apa pun:

```python
# Muat konteks (110ms -- menggunakan cache)
ctx = BinaryContext.load_or_build('/path/to/binary.so')

# Tampilkan semua fungsi yang sebelumnya diberi nama
print(ctx.names_table())

# Tinjau temuan yang dikonfirmasi
from ablation.analyzers.finding_registry import FindingRegistry
fr = FindingRegistry()
fr.list_findings(binary_sha=ctx.sha256[:16])
```

---

## Langkah berikutnya

- [Alur kerja perburuan kerentanan](../../workflows/vuln-hunting.md) -- loop lengkap dari pemindaian ke temuan siap pengungkapan
- [Referensi modul](../../module-reference/) -- lebih dari 50 analyzer dengan parameter dan contoh
- [CONTRIBUTING.md](../../../CONTRIBUTING.md) -- cara menambahkan pola, pemindaian, dan modul analyzer
