# Начало работы

От установки до первого кандидата на уязвимость за 15 минут. Подойдёт любой stripped ELF-бинарный файл.

---

## Установка

**Требования:** Python 3.10+, pip

```bash
pip install git+https://github.com/Ablation-Tool/ablation
```

С функциями LLM:

```bash
pip install "git+https://github.com/Ablation-Tool/ablation#egg=ablation[llm]"
```

Из исходного кода:

```bash
git clone https://github.com/Ablation-Tool/ablation
cd ablation
pip install -e .
```

Проверка установки:

```bash
python -c "from ablation.analyzers.binary_context import BinaryContext; print('ok')"
```

---

## Шаг 1: Загрузка бинарного файла

`BinaryContext` является точкой входа для всего анализа. Передайте любой stripped ELF-бинарный файл:

```python
from ablation.analyzers.binary_context import BinaryContext

ctx = BinaryContext.load_or_build('/path/to/binary.so')
print(ctx.summary())
```

**Первый запуск:** от 0,5 до 5 секунд в зависимости от размера бинарного файла. Ablation строит и кэширует в `~/.ablation/cache/<sha256>_<name>.json`.

**Каждый последующий запуск:** 110 мс. Кэш индексируется по SHA256, поэтому другая сборка с тем же именем бинарного файла перестраивается автоматически.

Пример вывода:

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

## Шаг 2: Запуск семантического сканирования

Сканирование является основным рабочим процессом. Оно кодирует все функции как поведенческие отпечатки BERT и выполняет запросы по описанию уязвимости на простом английском языке. Используйте `sweeps/base_sweep.py` в качестве шаблона или создайте собственный:

```python
from ablation.analyzers.corpus_builder import CorpusBuilder
from ablation.analyzers.semantic_search import SemanticSearcher
from ablation.analyzers.pattern_library import PatternLibrary

# Построение корпуса поведенческих описаний в func_id.db
cb = CorpusBuilder()
cb.build('/path/to/binary.so', product='my-target', version='1.0')

# Построение BERT-эмбеддингов (~35 сек для 19k функций на CPU)
searcher = SemanticSearcher('~/.ablation/func_id.db')
searcher.build_corpus()

# Запрос по описанию уязвимости
results = searcher.query(
    "TLV parser that advances pointer without minimum length check",
    top_k=10
)

for r in results:
    print(f"  0x{r.va:x}  {r.name or hex(r.va):<50s}  score={r.score:.3f}")
```

**Ожидаемое время выполнения:** от 35 до 60 секунд для 19 000 функций на CPU. Последующие запросы к тому же корпусу выполняются менее чем за секунду, так как эмбеддинги кэшируются.

---

## Шаг 3: Сортировка кандидатов

Для каждого кандидата с высоким баллом получите его контекст:

```python
va = 0x1000  # VA кандидата из результатов сканирования

# Что вызывает эта функция?
print("callees:", ctx.callees_of(va))

# На какие строки она ссылается?
print("strings:", ctx.strings_in_func(va))

# Что её вызывает?
print("callers:", ctx.callers_of(va))
```

Сортировка большинства кандидатов таким способом занимает две-три минуты. Если список вызовов содержит функции памяти (`memcpy`, `malloc`, `free`) и цепочка вызывающих достигает сетевой точки входа, переходите к ручной трассировке.

---

## Шаг 4: Именование подтверждённых функций

Когда вы определяете назначение функции, зарегистрируйте её имя. Имена сохраняются между сессиями и отображаются во всех последующих выводах анализа:

```python
ctx.set_name(0x1000, 'proto_parse_message', source='confirmed')

# Имена отображаются везде:
print(ctx.callees_of(0x1000))   # метки вместо шестнадцатеричных адресов
print(ctx.names_table())           # все именованные функции в этом бинарном файле
```

Имена хранятся в `~/.ablation/function_names.json` с индексацией по SHA256 бинарного файла. Они сохраняются после перезапуска сессий, перемещения бинарных файлов и перезагрузки системы.

---

## Шаг 5: Регистрация подтверждённых паттернов

Когда вы подтверждаете реальную уязвимость, зарегистрируйте запрос, который её нашёл. Он будет автоматически воспроизводиться на будущих бинарных файлах:

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

При любом будущем сканировании, будь то другая версия прошивки или другой производитель, `pl.sweep(searcher)` автоматически запускает все подтверждённые паттерны.

---

## Возобновление сессии

Ablation разработан для многосессийных исследований. В начале каждой сессии:

```python
# Загрузка контекста (110 мс -- использует кэш)
ctx = BinaryContext.load_or_build('/path/to/binary.so')

# Отображение всех ранее именованных функций
print(ctx.names_table())

# Просмотр подтверждённых находок
from ablation.analyzers.finding_registry import FindingRegistry
fr = FindingRegistry()
fr.list_findings(binary_sha=ctx.sha256[:16])
```

---

## Следующие шаги

- [Рабочий процесс поиска уязвимостей](../../workflows/vuln-hunting.md) -- полный цикл от сканирования до готовой к раскрытию находки
- [Справочник модулей](../../module-reference/) -- более 50 анализаторов с параметрами и примерами
- [CONTRIBUTING.md](../../../CONTRIBUTING.md) -- как добавлять паттерны, сканирования и модули анализаторов
