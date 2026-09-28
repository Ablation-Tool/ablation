# शुरुआत करें

इंस्टॉल से लेकर पहले कमजोरी उम्मीदवार तक 15 मिनट। कोई भी stripped ELF बाइनरी काम करती है।

---

## स्थापना

**आवश्यकताएं:** Python 3.10+, pip

```bash
pip install git+https://github.com/Ablation-Tool/ablation
```

LLM सुविधाओं के साथ:

```bash
pip install "git+https://github.com/Ablation-Tool/ablation#egg=ablation[llm]"
```

सोर्स से:

```bash
git clone https://github.com/Ablation-Tool/ablation
cd ablation
pip install -e .
```

इंस्टॉल की पुष्टि करें:

```bash
python -c "from ablation.analyzers.binary_context import BinaryContext; print('ok')"
```

---

## चरण 1: बाइनरी लोड करें

`BinaryContext` सभी विश्लेषण का प्रवेश बिंदु है। कोई भी stripped ELF बाइनरी पास करें:

```python
from ablation.analyzers.binary_context import BinaryContext

ctx = BinaryContext.load_or_build('/path/to/binary.so')
print(ctx.summary())
```

**पहली बार:** बाइनरी आकार के अनुसार 0.5 से 5 सेकंड। Ablation बनाता है और `~/.ablation/cache/<sha256>_<name>.json` में कैश करता है।

**बाद में:** 110 ms। कैश SHA256 से कीड है — एक ही नाम की अलग बिल्ड अपने आप रीबिल्ड होती है।

आउटपुट उदाहरण:

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

## चरण 2: सिमेंटिक स्वीप चलाएं

स्वीप मुख्य वर्कफ्लो है। सभी फंक्शन को BERT व्यवहार फिंगरप्रिंट के रूप में एनकोड करता है और सरल अंग्रेजी में कमजोरी विवरण से क्वेरी करता है। `sweeps/base_sweep.py` को टेम्प्लेट के रूप में उपयोग करें, या अपना बनाएं:

```python
from ablation.analyzers.corpus_builder import CorpusBuilder
from ablation.analyzers.semantic_search import SemanticSearcher
from ablation.analyzers.pattern_library import PatternLibrary

# func_id.db में व्यवहार विवरण कॉर्पस बनाएं
cb = CorpusBuilder()
cb.build('/path/to/binary.so', product='my-target', version='1.0')

# BERT एम्बेडिंग बनाएं (~35s for 19k functions on CPU)
searcher = SemanticSearcher('~/.ablation/func_id.db')
searcher.build_corpus()

# कमजोरी विवरण से क्वेरी करें
results = searcher.query(
    "TLV parser that advances pointer without minimum length check",
    top_k=10
)

for r in results:
    print(f"  0x{r.va:x}  {r.name or hex(r.va):<50s}  score={r.score:.3f}")
```

**अनुमानित समय:** CPU पर 19,000 फंक्शन के लिए 35 से 60 सेकंड। उसी कॉर्पस पर बाद की क्वेरी एक सेकंड से कम में — एम्बेडिंग कैश हैं।

---

## चरण 3: उम्मीदवारों को वर्गीकृत करें

उच्च स्कोर वाले प्रत्येक उम्मीदवार के लिए, उसका संदर्भ प्राप्त करें:

```python
va = 0x1000  # स्वीप परिणामों से उम्मीदवार VA

# यह फंक्शन क्या कॉल करता है?
print("callees:", ctx.callees_of(va))

# यह किन strings को रेफर करता है?
print("strings:", ctx.strings_in_func(va))

# इसे क्या कॉल करता है?
print("callers:", ctx.callers_of(va))
```

अधिकांश उम्मीदवार इस तरह दो से तीन मिनट में वर्गीकृत होते हैं। अगर callee सूची में मेमोरी फंक्शन (`memcpy`, `malloc`, `free`) हैं और caller chain नेटवर्क एंट्री पॉइंट तक पहुंचती है, तो मैन्युअल ट्रेस पर आगे बढ़ें।

---

## चरण 4: पुष्टि किए गए फंक्शन का नाम दें

जब आप किसी फंक्शन का उद्देश्य पहचानें, तो उसका नाम दर्ज करें। नाम सत्रों के बीच बने रहते हैं और सभी बाद के विश्लेषण आउटपुट में दिखते हैं:

```python
ctx.set_name(0x1000, 'proto_parse_message', source='confirmed')

# नाम हर जगह दिखते हैं:
print(ctx.callees_of(0x1000))   # hex addresses की जगह labels
print(ctx.names_table())           # इस बाइनरी में सभी नामित फंक्शन
```

नाम `~/.ablation/function_names.json` में, बाइनरी SHA256 से कीड होकर संग्रहित होते हैं। सत्र पुनरारंभ, बाइनरी मूव और सिस्टम रीबूट के बाद भी बने रहते हैं।

---

## चरण 5: पुष्टि किए गए पैटर्न दर्ज करें

जब आप एक वास्तविक कमजोरी की पुष्टि करें, तो उसे खोजने वाली क्वेरी दर्ज करें। यह भविष्य की बाइनरी पर स्वचालित रूप से दोहराई जाएगी:

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

किसी भी भविष्य के स्वीप पर — अलग फर्मवेयर संस्करण, अलग विक्रेता — `pl.sweep(searcher)` स्वचालित रूप से सभी पुष्टि किए गए पैटर्न चलाता है।

---

## सत्र फिर से शुरू करें

Ablation बहु-सत्र अनुसंधान के लिए डिज़ाइन किया गया है। किसी भी सत्र की शुरुआत में:

```python
# संदर्भ लोड करें (110ms -- cache का उपयोग)
ctx = BinaryContext.load_or_build('/path/to/binary.so')

# पहले नामित सभी फंक्शन दिखाएं
print(ctx.names_table())

# पुष्टि किए गए findings की समीक्षा करें
from ablation.analyzers.finding_registry import FindingRegistry
fr = FindingRegistry()
fr.list_findings(binary_sha=ctx.sha256[:16])
```

---

## अगले कदम

- [कमजोरी खोज वर्कफ्लो](../../workflows/vuln-hunting.md) -- स्वीप से disclosure-ready finding तक पूरा लूप
- [मॉड्यूल रेफरेंस](../../module-reference/) -- parameters और examples के साथ 50+ analyzers
- [CONTRIBUTING.md](../../../CONTRIBUTING.md) -- patterns, sweeps और analyzer modules जोड़ने का तरीका
