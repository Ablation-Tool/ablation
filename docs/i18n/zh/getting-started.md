# 快速开始

从安装到第一个漏洞候选，只需 15 分钟。任何无符号 ELF 二进制文件均可使用。

---

## 安装

**要求：** Python 3.10+，pip

```bash
pip install git+https://github.com/Ablation-Tool/ablation
```

包含 LLM 功能：

```bash
pip install "git+https://github.com/Ablation-Tool/ablation#egg=ablation[llm]"
```

从源代码安装：

```bash
git clone https://github.com/Ablation-Tool/ablation
cd ablation
pip install -e .
```

验证安装：

```bash
python -c "from ablation.analyzers.binary_context import BinaryContext; print('ok')"
```

---

## 第一步：加载二进制文件

`BinaryContext` 是所有分析的入口点。传入任意无符号 ELF 二进制文件：

```python
from ablation.analyzers.binary_context import BinaryContext

ctx = BinaryContext.load_or_build('/path/to/binary.so')
print(ctx.summary())
```

**首次运行：** 0.5 到 5 秒，具体取决于二进制文件大小。Ablation 会构建并缓存到 `~/.ablation/cache/<sha256>_<name>.json`。

**后续每次运行：** 110 毫秒。缓存按 SHA256 索引，因此同名二进制文件的不同构建版本会自动重新构建。

输出示例：

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

## 第二步：运行语义扫描

扫描是核心工作流程。它将所有函数编码为 BERT 行为特征，并通过简单英文的漏洞描述进行查询。使用 `sweeps/base_sweep.py` 作为模板，或构建自己的：

```python
from ablation.analyzers.corpus_builder import CorpusBuilder
from ablation.analyzers.semantic_search import SemanticSearcher
from ablation.analyzers.pattern_library import PatternLibrary

# 将行为描述语料库构建到 func_id.db
cb = CorpusBuilder()
cb.build('/path/to/binary.so', product='my-target', version='1.0')

# 构建 BERT 嵌入（CPU 上 19k 个函数约需 35 秒）
searcher = SemanticSearcher('~/.ablation/func_id.db')
searcher.build_corpus()

# 按漏洞描述查询
results = searcher.query(
    "TLV parser that advances pointer without minimum length check",
    top_k=10
)

for r in results:
    print(f"  0x{r.va:x}  {r.name or hex(r.va):<50s}  score={r.score:.3f}")
```

**预期运行时间：** CPU 上处理 19,000 个函数需 35 到 60 秒。后续对同一语料库的查询不到一秒，因为嵌入已缓存。

---

## 第三步：筛选候选函数

对每个高分候选函数获取其上下文：

```python
va = 0x1000  # 扫描结果中的候选 VA

# 这个函数调用了什么？
print("callees:", ctx.callees_of(va))

# 它引用了哪些字符串？
print("strings:", ctx.strings_in_func(va))

# 什么调用了它？
print("callers:", ctx.callers_of(va))
```

大多数候选函数通过这种方式筛选需要两到三分钟。如果被调用列表包含内存函数（`memcpy`、`malloc`、`free`），且调用链到达网络入口点，则继续进行手动追踪。

---

## 第四步：命名已确认的函数

当你确定一个函数的用途后，注册其名称。名称跨会话持久保存，并出现在所有后续分析输出中：

```python
ctx.set_name(0x1000, 'proto_parse_message', source='confirmed')

# 名称随处显示：
print(ctx.callees_of(0x1000))   # 显示标签而非十六进制地址
print(ctx.names_table())           # 此二进制文件中所有已命名的函数
```

名称存储在 `~/.ablation/function_names.json` 中，按二进制文件 SHA256 索引。在会话重启、二进制文件移动和系统重启后仍然有效。

---

## 第五步：注册已确认的模式

当你确认一个真实漏洞后，注册找到它的查询。它会在未来的二进制文件上自动重放：

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

在任何未来的扫描中，无论是不同的固件版本还是不同的厂商，`pl.sweep(searcher)` 都会自动运行所有已确认的模式。

---

## 恢复会话

Ablation 专为多会话研究设计。在任何会话开始时：

```python
# 加载上下文（110 毫秒，使用缓存）
ctx = BinaryContext.load_or_build('/path/to/binary.so')

# 显示所有之前命名的函数
print(ctx.names_table())

# 查看已确认的发现
from ablation.analyzers.finding_registry import FindingRegistry
fr = FindingRegistry()
fr.list_findings(binary_sha=ctx.sha256[:16])
```

---

## 后续步骤

- [漏洞挖掘工作流程](../../workflows/vuln-hunting.md) -- 从扫描到可披露发现的完整循环
- [模块参考](../../module-reference/) -- 50 多个分析器的参数和示例
- [CONTRIBUTING.md](../../../CONTRIBUTING.md) -- 如何添加模式、扫描和分析器模块
