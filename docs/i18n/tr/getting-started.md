# Başlarken

Kurulumdan ilk güvenlik açığı adayına 15 dakika. Sembolsüz herhangi bir ELF ikili dosyası çalışır.

---

## Kurulum

**Gereksinimler:** Python 3.10+, pip

```bash
pip install git+https://github.com/Ablation-Tool/ablation
```

LLM özellikleriyle:

```bash
pip install "git+https://github.com/Ablation-Tool/ablation#egg=ablation[llm]"
```

Kaynaktan:

```bash
git clone https://github.com/Ablation-Tool/ablation
cd ablation
pip install -e .
```

Kurulumu doğrulayın:

```bash
python -c "from ablation.analyzers.binary_context import BinaryContext; print('ok')"
```

---

## Adım 1: İkili dosyanızı yükleyin

`BinaryContext` tüm analizlerin giriş noktasıdır. Sembolsüz herhangi bir ELF ikili dosyası geçirin:

```python
from ablation.analyzers.binary_context import BinaryContext

ctx = BinaryContext.load_or_build('/path/to/binary.so')
print(ctx.summary())
```

**İlk çalıştırma:** İkili dosya boyutuna bağlı olarak 0,5 ila 5 saniye. Ablation `~/.ablation/cache/<sha256>_<name>.json` adresine önbelleğe alır.

**Sonraki çalıştırmalar:** 110 ms. Önbellek SHA256 ile anahtarlanır — aynı ikili dosya adının farklı bir derlemesi otomatik olarak yeniden oluşturulur.

Örnek çıktı:

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

## Adım 2: Semantik tarama çalıştırın

Tarama temel iş akışıdır. Tüm işlevleri BERT davranışsal parmak izleri olarak kodlar ve sade İngilizce güvenlik açığı açıklamasıyla sorgular. `sweeps/base_sweep.py`'yi şablon olarak kullanın veya kendinizinkini oluşturun:

```python
from ablation.analyzers.corpus_builder import CorpusBuilder
from ablation.analyzers.semantic_search import SemanticSearcher
from ablation.analyzers.pattern_library import PatternLibrary

# func_id.db'ye davranış açıklaması korpusu oluştur
cb = CorpusBuilder()
cb.build('/path/to/binary.so', product='my-target', version='1.0')

# BERT gömmeleri oluştur (~35s for 19k functions on CPU)
searcher = SemanticSearcher('~/.ablation/func_id.db')
searcher.build_corpus()

# Güvenlik açığı açıklamasıyla sorgula
results = searcher.query(
    "TLV parser that advances pointer without minimum length check",
    top_k=10
)

for r in results:
    print(f"  0x{r.va:x}  {r.name or hex(r.va):<50s}  score={r.score:.3f}")
```

**Beklenen çalışma süresi:** CPU'da 19.000 işlev için 35 ila 60 saniye. Aynı korpusa karşı sonraki sorgular bir saniyenin altında çalışır — gömmeler önbelleğe alınmıştır.

---

## Adım 3: Adayları sınıflandırın

Yüksek puanlı her aday için bağlamını alın:

```python
va = 0x1000  # tarama sonuçlarından aday VA

# Bu işlev neyi çağırıyor?
print("callees:", ctx.callees_of(va))

# Hangi dizelere başvuruyor?
print("strings:", ctx.strings_in_func(va))

# Onu ne çağırıyor?
print("callers:", ctx.callers_of(va))
```

Çoğu aday bu şekilde iki ila üç dakikada sınıflandırılır. Callee listesi bellek işlevleri (`memcpy`, `malloc`, `free`) içeriyorsa ve çağıran zinciri bir ağ giriş noktasına ulaşıyorsa manuel izlemeye geçin.

---

## Adım 4: Onaylanan işlevleri adlandırın

Bir işlevin amacını belirlediğinizde adını kaydedin. Adlar oturumlar arasında kalıcıdır ve sonraki tüm analiz çıktılarında görünür:

```python
ctx.set_name(0x1000, 'proto_parse_message', source='confirmed')

# Adlar her yerde görünür:
print(ctx.callees_of(0x1000))   # hex adresleri yerine etiketler
print(ctx.names_table())           # bu ikili dosyadaki tüm adlandırılmış işlevler
```

Adlar, ikili SHA256 ile anahtarlanmış olarak `~/.ablation/function_names.json` adresinde saklanır. Oturum yeniden başlatmalardan, ikili taşımalardan ve sistem yeniden başlatmalarından kurtulurlar.

---

## Adım 5: Onaylanan kalıpları kaydedin

Gerçek bir güvenlik açığını doğruladığınızda, onu bulan sorguyu kaydedin. Gelecekteki ikili dosyalarda otomatik olarak yeniden oynatılır:

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

Farklı firmware sürümü, farklı satıcı gibi gelecekteki herhangi bir taramada `pl.sweep(searcher)` tüm onaylanan kalıpları otomatik olarak çalıştırır.

---

## Oturumu sürdürün

Ablation çok oturumlu araştırma için tasarlanmıştır. Herhangi bir oturumun başında:

```python
# Bağlamı yükle (110ms -- önbellek kullanır)
ctx = BinaryContext.load_or_build('/path/to/binary.so')

# Daha önce adlandırılmış tüm işlevleri göster
print(ctx.names_table())

# Onaylanan bulguları gözden geçir
from ablation.analyzers.finding_registry import FindingRegistry
fr = FindingRegistry()
fr.list_findings(binary_sha=ctx.sha256[:16])
```

---

## Sonraki adımlar

- [Güvenlik açığı avlama iş akışı](../../workflows/vuln-hunting.md) -- taramadan açıklamaya hazır bulguya tam döngü
- [Modül referansı](../../module-reference/) -- parametreler ve örneklerle 50'den fazla analizör
- [CONTRIBUTING.md](../../../CONTRIBUTING.md) -- kalıplar, taramalar ve analizör modülleri nasıl eklenir
