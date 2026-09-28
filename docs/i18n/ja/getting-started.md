# はじめに

インストールから最初の脆弱性候補まで15分で完了します。シンボルなしのELFバイナリであれば何でも使えます。

---

## インストール

**要件:** Python 3.10+、pip

```bash
pip install git+https://github.com/Ablation-Tool/ablation
```

LLM機能あり:

```bash
pip install "git+https://github.com/Ablation-Tool/ablation#egg=ablation[llm]"
```

ソースから:

```bash
git clone https://github.com/Ablation-Tool/ablation
cd ablation
pip install -e .
```

インストールの確認:

```bash
python -c "from ablation.analyzers.binary_context import BinaryContext; print('ok')"
```

---

## ステップ1: バイナリをロードする

`BinaryContext`はすべての解析のエントリポイントです。シンボルなしのELFバイナリを渡します:

```python
from ablation.analyzers.binary_context import BinaryContext

ctx = BinaryContext.load_or_build('/path/to/binary.so')
print(ctx.summary())
```

**初回実行:** バイナリのサイズによって0.5〜5秒。Ablationは`~/.ablation/cache/<sha256>_<name>.json`にビルドしてキャッシュします。

**以降の各実行:** 110 ms。キャッシュはSHA256でインデックスされるため、同じバイナリ名の別のビルドは自動的に再ビルドされます。

出力例:

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

## ステップ2: セマンティックスイープを実行する

スイープはコアワークフローです。すべての関数をBERT行動フィンガープリントとしてエンコードし、平易な英語で脆弱性の説明をクエリします。`sweeps/base_sweep.py`をテンプレートとして使うか、独自に作成します:

```python
from ablation.analyzers.corpus_builder import CorpusBuilder
from ablation.analyzers.semantic_search import SemanticSearcher
from ablation.analyzers.pattern_library import PatternLibrary

# 行動説明コーパスをfunc_id.dbに構築
cb = CorpusBuilder()
cb.build('/path/to/binary.so', product='my-target', version='1.0')

# BERTエンベディングを構築（CPUで19k関数に約35秒）
searcher = SemanticSearcher('~/.ablation/func_id.db')
searcher.build_corpus()

# 脆弱性の説明でクエリ
results = searcher.query(
    "TLV parser that advances pointer without minimum length check",
    top_k=10
)

for r in results:
    print(f"  0x{r.va:x}  {r.name or hex(r.va):<50s}  score={r.score:.3f}")
```

**予想実行時間:** CPUで19,000関数に35〜60秒。同じコーパスへの以降のクエリはエンベディングがキャッシュされているため1秒未満で実行されます。

---

## ステップ3: 候補をトリアージする

スコアの高い各候補のコンテキストを取得します:

```python
va = 0x1000  # スイープ結果からの候補VA

# この関数は何を呼び出しますか？
print("callees:", ctx.callees_of(va))

# どの文字列を参照しますか？
print("strings:", ctx.strings_in_func(va))

# 何がこれを呼び出しますか？
print("callers:", ctx.callers_of(va))
```

ほとんどの候補は2〜3分でこの方法でトリアージできます。calleeリストにメモリ関数（`memcpy`、`malloc`、`free`）が含まれ、callerチェーンがネットワークエントリポイントに到達する場合、手動トレースに進みます。

---

## ステップ4: 確認済み関数を命名する

関数の目的を特定したら、その名前を登録します。名前はセッションをまたいで持続し、以降のすべての解析出力に表示されます:

```python
ctx.set_name(0x1000, 'proto_parse_message', source='confirmed')

# 名前はどこにでも表示されます:
print(ctx.callees_of(0x1000))   # 16進数アドレスの代わりにラベル
print(ctx.names_table())           # このバイナリのすべての命名済み関数
```

名前は`~/.ablation/function_names.json`に保存され、バイナリのSHA256でインデックスされます。セッションの再起動、バイナリの移動、システムの再起動を経ても保持されます。

---

## ステップ5: 確認済みパターンを登録する

本物の脆弱性を確認したら、それを見つけたクエリを登録します。将来のバイナリで自動的に再生されます:

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

今後のスイープでは、異なるファームウェアバージョンや異なるベンダーに関わらず、`pl.sweep(searcher)`がすべての確認済みパターンを自動的に実行します。

---

## セッションを再開する

Ablationはマルチセッション研究向けに設計されています。セッション開始時に:

```python
# コンテキストをロード（110ms -- キャッシュを使用）
ctx = BinaryContext.load_or_build('/path/to/binary.so')

# 以前に命名したすべての関数を表示
print(ctx.names_table())

# 確認済みの発見を確認
from ablation.analyzers.finding_registry import FindingRegistry
fr = FindingRegistry()
fr.list_findings(binary_sha=ctx.sha256[:16])
```

---

## 次のステップ

- [脆弱性ハンティングワークフロー](../../workflows/vuln-hunting.md) -- スイープから開示準備完了の発見までの完全なループ
- [モジュールリファレンス](../../module-reference/) -- 50以上のアナライザーとパラメータおよび例
- [CONTRIBUTING.md](../../../CONTRIBUTING.md) -- パターン、スイープ、アナライザーモジュールの追加方法
