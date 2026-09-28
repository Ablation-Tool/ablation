# 시작하기

설치부터 첫 번째 취약점 후보까지 15분. 심볼이 없는 ELF 바이너리라면 모두 사용 가능합니다.

---

## 설치

**요구 사항:** Python 3.10+, pip

```bash
pip install git+https://github.com/Ablation-Tool/ablation
```

LLM 기능 포함:

```bash
pip install "git+https://github.com/Ablation-Tool/ablation#egg=ablation[llm]"
```

소스에서 설치:

```bash
git clone https://github.com/Ablation-Tool/ablation
cd ablation
pip install -e .
```

설치 확인:

```bash
python -c "from ablation.analyzers.binary_context import BinaryContext; print('ok')"
```

---

## 1단계: 바이너리 로드

`BinaryContext`는 모든 분석의 진입점입니다. 심볼이 없는 ELF 바이너리를 전달하세요:

```python
from ablation.analyzers.binary_context import BinaryContext

ctx = BinaryContext.load_or_build('/path/to/binary.so')
print(ctx.summary())
```

**첫 실행:** 바이너리 크기에 따라 0.5~5초. Ablation이 빌드하고 `~/.ablation/cache/<sha256>_<name>.json`에 캐시합니다.

**이후 실행:** 110ms. 캐시는 SHA256으로 키가 지정되어 있어 동일한 바이너리 이름의 다른 빌드는 자동으로 재빌드됩니다.

출력 예시:

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

## 2단계: 시맨틱 스윕 실행

스윕은 핵심 워크플로입니다. 모든 함수를 BERT 행동 지문으로 인코딩하고 일반 영어로 된 취약점 설명으로 쿼리합니다. `sweeps/base_sweep.py`를 템플릿으로 사용하거나 직접 빌드하세요:

```python
from ablation.analyzers.corpus_builder import CorpusBuilder
from ablation.analyzers.semantic_search import SemanticSearcher
from ablation.analyzers.pattern_library import PatternLibrary

# func_id.db에 행동 설명 코퍼스 빌드
cb = CorpusBuilder()
cb.build('/path/to/binary.so', product='my-target', version='1.0')

# BERT 임베딩 빌드 (~35s for 19k functions on CPU)
searcher = SemanticSearcher('~/.ablation/func_id.db')
searcher.build_corpus()

# 취약점 설명으로 쿼리
results = searcher.query(
    "TLV parser that advances pointer without minimum length check",
    top_k=10
)

for r in results:
    print(f"  0x{r.va:x}  {r.name or hex(r.va):<50s}  score={r.score:.3f}")
```

**예상 실행 시간:** CPU에서 19,000개 함수 기준 35~60초. 같은 코퍼스에 대한 이후 쿼리는 임베딩이 캐시되어 1초 이내에 실행됩니다.

---

## 3단계: 후보 분류

점수가 높은 각 후보에 대해 컨텍스트를 가져오세요:

```python
va = 0x1000  # 스윕 결과의 후보 VA

# 이 함수가 무엇을 호출하나요?
print("callees:", ctx.callees_of(va))

# 어떤 문자열을 참조하나요?
print("strings:", ctx.strings_in_func(va))

# 무엇이 이 함수를 호출하나요?
print("callers:", ctx.callers_of(va))
```

대부분의 후보는 이 방식으로 2~3분 안에 분류됩니다. callees 목록에 메모리 함수(`memcpy`, `malloc`, `free`)가 포함되어 있고 호출자 체인이 네트워크 진입점에 도달하면 수동 추적으로 진행하세요.

---

## 4단계: 확인된 함수 이름 지정

함수의 목적을 파악했을 때 이름을 등록하세요. 이름은 세션 간에 유지되며 이후 모든 분석 출력에 나타납니다:

```python
ctx.set_name(0x1000, 'proto_parse_message', source='confirmed')

# 이름이 모든 곳에 나타납니다:
print(ctx.callees_of(0x1000))   # 16진수 주소 대신 레이블
print(ctx.names_table())           # 이 바이너리의 모든 명명된 함수
```

이름은 바이너리 SHA256으로 키가 지정되어 `~/.ablation/function_names.json`에 저장됩니다. 세션 재시작, 바이너리 이동, 시스템 재부팅 후에도 유지됩니다.

---

## 5단계: 확인된 패턴 등록

실제 취약점을 확인했을 때 해당 쿼리를 등록하세요. 이후 바이너리에서 자동으로 재실행됩니다:

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

다른 펌웨어 버전, 다른 벤더 등 이후의 모든 스윕에서 `pl.sweep(searcher)`가 확인된 패턴을 자동으로 실행합니다.

---

## 세션 재개

Ablation은 멀티 세션 연구를 위해 설계되었습니다. 세션 시작 시:

```python
# 컨텍스트 로드 (110ms -- 캐시 사용)
ctx = BinaryContext.load_or_build('/path/to/binary.so')

# 이전에 명명된 모든 함수 표시
print(ctx.names_table())

# 확인된 결과 검토
from ablation.analyzers.finding_registry import FindingRegistry
fr = FindingRegistry()
fr.list_findings(binary_sha=ctx.sha256[:16])
```

---

## 다음 단계

- [취약점 탐색 워크플로](../../workflows/vuln-hunting.md) -- 스윕부터 공개 준비 결과까지의 전체 루프
- [모듈 레퍼런스](../../module-reference/) -- 매개변수와 예시가 포함된 50개 이상의 분석기
- [CONTRIBUTING.md](../../../CONTRIBUTING.md) -- 패턴, 스윕, 분석기 모듈 추가 방법
