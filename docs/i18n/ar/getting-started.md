# البدء

انتقل من التثبيت إلى أول مرشح للثغرات في 15 دقيقة. أي ملف ثنائي ELF مجرد من الرموز يعمل.

---

## التثبيت

**المتطلبات:** Python 3.10+، pip

```bash
pip install git+https://github.com/Ablation-Tool/ablation
```

مع ميزات LLM:

```bash
pip install "git+https://github.com/Ablation-Tool/ablation#egg=ablation[llm]"
```

من الكود المصدري:

```bash
git clone https://github.com/Ablation-Tool/ablation
cd ablation
pip install -e .
```

التحقق من التثبيت:

```bash
python -c "from ablation.analyzers.binary_context import BinaryContext; print('ok')"
```

---

## الخطوة الأولى: تحميل الملف الثنائي

`BinaryContext` هو نقطة الدخول لجميع التحليلات. مرّر أي ملف ثنائي ELF مجرد من الرموز:

```python
from ablation.analyzers.binary_context import BinaryContext

ctx = BinaryContext.load_or_build('/path/to/binary.so')
print(ctx.summary())
```

**التشغيل الأول:** من 0.5 إلى 5 ثوانٍ حسب حجم الملف الثنائي. يقوم Ablation بالبناء والتخزين المؤقت في `~/.ablation/cache/<sha256>_<name>.json`.

**كل تشغيل لاحق:** 110 ميلي ثانية. يُفهرَس التخزين المؤقت بواسطة SHA256، لذا فإن بناءً مختلفاً بنفس اسم الملف الثنائي يُعيد البناء تلقائياً.

مثال على المخرجات:

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

## الخطوة الثانية: تشغيل المسح الدلالي

المسح هو سير العمل الأساسي. يُشفّر جميع الدوال كبصمات سلوكية BERT ويستعلم بوصف الثغرة بالإنجليزية البسيطة. استخدم `sweeps/base_sweep.py` كقالب، أو ابنِ نموذجك الخاص:

```python
from ablation.analyzers.corpus_builder import CorpusBuilder
from ablation.analyzers.semantic_search import SemanticSearcher
from ablation.analyzers.pattern_library import PatternLibrary

# بناء مجموعة وصف السلوك في func_id.db
cb = CorpusBuilder()
cb.build('/path/to/binary.so', product='my-target', version='1.0')

# بناء تضمينات BERT (حوالي 35 ثانية لـ 19 ألف دالة على وحدة المعالجة المركزية)
searcher = SemanticSearcher('~/.ablation/func_id.db')
searcher.build_corpus()

# الاستعلام بوصف الثغرة
results = searcher.query(
    "TLV parser that advances pointer without minimum length check",
    top_k=10
)

for r in results:
    print(f"  0x{r.va:x}  {r.name or hex(r.va):<50s}  score={r.score:.3f}")
```

**وقت التشغيل المتوقع:** من 35 إلى 60 ثانية لـ 19,000 دالة على وحدة المعالجة المركزية. الاستعلامات اللاحقة على نفس المجموعة تُنفَّذ في أقل من ثانية لأن التضمينات مخزنة مؤقتاً.

---

## الخطوة الثالثة: فرز المرشحين

لكل مرشح ذي درجة عالية، احصل على سياقه:

```python
va = 0x1000  # عنوان المرشح من نتائج المسح

# ماذا تستدعي هذه الدالة؟
print("callees:", ctx.callees_of(va))

# ما السلاسل التي تشير إليها؟
print("strings:", ctx.strings_in_func(va))

# ما الذي يستدعيها؟
print("callers:", ctx.callers_of(va))
```

تستغرق معظم المرشحات دقيقتين إلى ثلاث دقائق للفرز بهذه الطريقة. إذا كانت قائمة الاستدعاءات تحتوي على دوال ذاكرة (`memcpy`, `malloc`, `free`) ووصلت سلسلة المستدعيين إلى نقطة دخول شبكية، فتابع إلى التتبع اليدوي.

---

## الخطوة الرابعة: تسمية الدوال المؤكدة

عند تحديد غرض دالة، سجّل اسمها. تستمر الأسماء عبر الجلسات وتظهر في جميع مخرجات التحليل اللاحقة:

```python
ctx.set_name(0x1000, 'proto_parse_message', source='confirmed')

# تظهر الأسماء في كل مكان:
print(ctx.callees_of(0x1000))   # تسميات بدلاً من عناوين سداسية عشرية
print(ctx.names_table())           # جميع الدوال المسماة في هذا الملف الثنائي
```

تُخزَّن الأسماء في `~/.ablation/function_names.json`، مُفهرَسة بـ SHA256 الملف الثنائي. تبقى صالحة عبر إعادة تشغيل الجلسات ونقل الملفات الثنائية وإعادة تشغيل النظام.

---

## الخطوة الخامسة: تسجيل الأنماط المؤكدة

عند تأكيد ثغرة حقيقية، سجّل الاستعلام الذي وجدها. سيُعاد تشغيله تلقائياً على الملفات الثنائية المستقبلية:

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

في أي مسح مستقبلي، سواء كان إصداراً مختلفاً من البرامج الثابتة أو مورداً مختلفاً، يُشغّل `pl.sweep(searcher)` جميع الأنماط المؤكدة تلقائياً.

---

## استئناف جلسة

صُمِّم Ablation للبحث متعدد الجلسات. في بداية أي جلسة:

```python
# تحميل السياق (110 ميلي ثانية -- يستخدم التخزين المؤقت)
ctx = BinaryContext.load_or_build('/path/to/binary.so')

# عرض جميع الدوال المسماة مسبقاً
print(ctx.names_table())

# مراجعة الاكتشافات المؤكدة
from ablation.analyzers.finding_registry import FindingRegistry
fr = FindingRegistry()
fr.list_findings(binary_sha=ctx.sha256[:16])
```

---

## الخطوات التالية

- [سير عمل صيد الثغرات](../../workflows/vuln-hunting.md) -- الحلقة الكاملة من المسح إلى الاكتشاف الجاهز للإفصاح
- [مرجع الوحدات](../../module-reference/) -- أكثر من 50 محللاً مع المعاملات والأمثلة
- [CONTRIBUTING.md](../../../CONTRIBUTING.md) -- كيفية إضافة الأنماط والمسوحات ووحدات المحللين
